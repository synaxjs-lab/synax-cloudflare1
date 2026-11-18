/**
 * Small PostgREST-shaped adapter backed entirely by Cloudflare D1.
 * It deliberately supports only the table/filter operations used by SYNAX.
 * It is not an external REST service and never calls Supabase.
 */

export interface D1StatementLike {
  bind(...values: unknown[]): D1StatementLike;
  first<T = Record<string, unknown>>(columnName?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[]; success?: boolean; meta?: unknown }>;
  run<T = Record<string, unknown>>(): Promise<{ success?: boolean; meta?: { changes?: number; last_row_id?: number }; results?: T[] }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1StatementLike;
  batch<T = unknown>(statements: D1StatementLike[]): Promise<T[]>;
}

type TableName = 'synax_state' | 'synax_sessions' | 'synax_messages' | 'synax_user_usage' | 'synax_chat_settings' | 'synax_call_signals';

type TableInfo = {
  key: string;
  columns: string[];
  jsonColumns?: string[];
  boolColumns?: string[];
};

const TABLES: Record<TableName, TableInfo> = {
  synax_state: { key: 'id', columns: ['id', 'state', 'updated_at'], jsonColumns: ['state'] },
  synax_sessions: {
    key: 'token',
    columns: ['token', 'user_id', 'session_start', 'last_active', 'allowed_seconds', 'is_expired', 'active', 'ended_at'],
    boolColumns: ['is_expired', 'active'],
  },
  synax_messages: {
    key: 'id',
    columns: ['id', 'client_message_id', 'sender_id', 'type', 'text', 'file_url', 'file_name', 'file_size', 'audio_duration', 'timestamp', 'status', 'reactions', 'reply_to', 'is_pinned', 'is_edited', 'deleted'],
    jsonColumns: ['reactions', 'reply_to'],
    boolColumns: ['is_pinned', 'is_edited', 'deleted'],
  },
  synax_user_usage: {
    key: 'user_id',
    columns: ['user_id', 'continuous_used_seconds', 'daily_used_seconds', 'daily_usage_date', 'active', 'active_started_at', 'last_heartbeat', 'last_seen', 'updated_at', 'usage_version'],
    boolColumns: ['active'],
  },
  synax_chat_settings: { key: 'chat_id', columns: ['chat_id', 'background_type', 'background_value', 'background_updated_at', 'updated_by', 'updated_at'] },
  synax_call_signals: {
    key: 'id',
    columns: ['id', 'from_user_id', 'target_user_id', 'type', 'call_type', 'payload', 'created_at'],
    jsonColumns: ['payload'],
  },
};

function responseJson(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function parseJsonBody(body: BodyInit | null | undefined): any {
  if (body == null) return {};
  if (typeof body === 'string') return JSON.parse(body || '{}');
  if (body instanceof ArrayBuffer) return JSON.parse(new TextDecoder().decode(body));
  if (ArrayBuffer.isView(body)) return JSON.parse(new TextDecoder().decode(body));
  throw new Error('Unsupported database request body.');
}

function toSqlValue(column: string, value: unknown, info: TableInfo): unknown {
  if (value === undefined) return null;
  if (info.jsonColumns?.includes(column)) return value == null ? null : JSON.stringify(value);
  if (info.boolColumns?.includes(column)) return value ? 1 : 0;
  return value;
}

function decodeRow(table: TableName, source: Record<string, any>): Record<string, any> {
  const info = TABLES[table];
  const row: Record<string, any> = { ...source };
  for (const column of info.jsonColumns || []) {
    if (typeof row[column] === 'string') {
      try { row[column] = JSON.parse(row[column]); } catch { /* leave malformed legacy values visible */ }
    }
  }
  for (const column of info.boolColumns || []) {
    if (column in row) row[column] = Boolean(row[column]);
  }
  return row;
}

function whereClause(table: TableName, params: URLSearchParams): { sql: string; values: unknown[] } {
  const info = TABLES[table];
  const clauses: string[] = [];
  const values: unknown[] = [];
  for (const [rawField, expression] of params.entries()) {
    if (['select', 'order', 'limit', 'offset', 'on_conflict'].includes(rawField)) continue;

    let field = rawField;
    let sqlField: string;
    if (rawField === 'payload->>callId' && table === 'synax_call_signals') {
      sqlField = "json_extract(payload, '$.callId')";
    } else {
      if (!info.columns.includes(field)) continue;
      sqlField = `\"${field}\"`;
    }

    const match = /^(eq|neq|gt|gte|lt|lte|is|not|in)\.(.*)$/s.exec(expression);
    if (!match) continue;
    const operator = match[1];
    const rawValue = match[2];

    if (operator === 'is' && rawValue === 'null') {
      clauses.push(`${sqlField} IS NULL`);
    } else if (operator === 'not' && rawValue === 'is.null') {
      clauses.push(`${sqlField} IS NOT NULL`);
    } else if (operator === 'in') {
      const list = rawValue.startsWith('(') && rawValue.endsWith(')')
        ? rawValue.slice(1, -1).split(',').map((v) => v.replace(/^\"|\"$/g, ''))
        : [];
      if (list.length) {
        clauses.push(`${sqlField} IN (${list.map(() => '?').join(',')})`);
        values.push(...list);
      }
    } else {
      const sqlOperator = ({ eq: '=', neq: '!=', gt: '>', gte: '>=', lt: '<', lte: '<=' } as Record<string, string>)[operator];
      if (sqlOperator) {
        clauses.push(`${sqlField} ${sqlOperator} ?`);
        values.push(rawValue);
      }
    }
  }
  return { sql: clauses.length ? ` WHERE ${clauses.join(' AND ')}` : '', values };
}

async function selectRows(db: D1DatabaseLike, table: TableName, params: URLSearchParams): Promise<Record<string, any>[]> {
  const info = TABLES[table];
  const where = whereClause(table, params);
  const orderParts = (params.get('order') || '').split(',').filter(Boolean).map((part) => {
    const [column, direction = 'asc'] = part.split('.');
    if (!info.columns.includes(column) || !['asc', 'desc'].includes(direction.toLowerCase())) return '';
    return `\"${column}\" ${direction.toUpperCase()}`;
  }).filter(Boolean);
  const order = orderParts.length ? ` ORDER BY ${orderParts.join(', ')}` : '';
  const rawLimit = params.get('limit');
  const rawOffset = params.get('offset');
  const limitValue = rawLimit === null ? Number.NaN : Number(rawLimit);
  const offsetValue = rawOffset === null ? Number.NaN : Number(rawOffset);
  const limit = Number.isFinite(limitValue) && limitValue >= 0 ? Math.min(5000, Math.floor(limitValue)) : 5000;
  const offset = Number.isFinite(offsetValue) && offsetValue >= 0 ? Math.floor(offsetValue) : 0;
  const sql = `SELECT ${info.columns.map((column) => `\"${column}\"`).join(', ')} FROM \"${table}\"${where.sql}${order} LIMIT ? OFFSET ?`;
  const result = await db.prepare(sql).bind(...where.values, limit, offset).all<Record<string, any>>();
  return (result.results || []).map((row) => decodeRow(table, row));
}

async function insertRows(db: D1DatabaseLike, table: TableName, rowsInput: any[], params: URLSearchParams, prefer: string): Promise<Record<string, any>[]> {
  const info = TABLES[table];
  const ignoreDuplicates = /resolution=ignore-duplicates/i.test(prefer);
  const returnRepresentation = /return=representation/i.test(prefer);
  const conflictTarget = params.get('on_conflict') || info.key;
  if (!info.columns.includes(conflictTarget)) throw new Error(`Unsupported conflict target: ${conflictTarget}`);
  const insertedRows: Record<string, any>[] = [];

  for (const input of rowsInput) {
    const row = { ...input };
    if (table === 'synax_call_signals' && row.id == null) delete row.id;
    const columns = info.columns.filter((column) => column in row);
    if (!columns.length) continue;
    const values = columns.map((column) => toSqlValue(column, row[column], info));
    const placeholders = columns.map(() => '?').join(', ');
    const quotedColumns = columns.map((column) => `\"${column}\"`).join(', ');
    const prefix = ignoreDuplicates ? 'INSERT OR IGNORE' : 'INSERT';
    let conflict = '';
    if (!ignoreDuplicates && conflictTarget !== 'id' && table === 'synax_call_signals') {
      conflict = '';
    } else if (!ignoreDuplicates) {
      const updates = columns.filter((column) => column !== conflictTarget);
      conflict = updates.length
        ? ` ON CONFLICT(\"${conflictTarget}\") DO UPDATE SET ${updates.map((column) => `\"${column}\" = excluded.\"${column}\"`).join(', ')}`
        : ` ON CONFLICT(\"${conflictTarget}\") DO NOTHING`;
    }
    const sql = `${prefix} INTO \"${table}\" (${quotedColumns}) VALUES (${placeholders})${conflict}`;
    const result = await db.prepare(sql).bind(...values).run();

    if (returnRepresentation) {
      let keyValue = row[conflictTarget] ?? row[info.key];
      if (table === 'synax_call_signals' && keyValue == null) keyValue = result.meta?.last_row_id;
      if (keyValue != null) {
        const existing = await db.prepare(`SELECT ${info.columns.map((column) => `\"${column}\"`).join(', ')} FROM \"${table}\" WHERE \"${conflictTarget}\" = ? LIMIT 1`).bind(keyValue).first<Record<string, any>>();
        if (existing) insertedRows.push(decodeRow(table, existing));
      }
    }
  }
  return insertedRows;
}

async function patchRows(db: D1DatabaseLike, table: TableName, params: URLSearchParams, patch: Record<string, any>, prefer: string): Promise<Record<string, any>[]> {
  const info = TABLES[table];
  const columns = info.columns.filter((column) => column in patch && column !== info.key);
  if (!columns.length) return [];
  const where = whereClause(table, params);
  const before = /return=representation/i.test(prefer)
    ? await selectRows(db, table, new URLSearchParams(Array.from(params.entries()).filter(([k]) => !['select', 'order', 'limit', 'offset'].includes(k))))
    : [];
  if (!where.sql) throw new Error(`Refusing an unfiltered update on ${table}.`);
  const setSql = columns.map((column) => `\"${column}\" = ?`).join(', ');
  const values = columns.map((column) => toSqlValue(column, patch[column], info));
  await db.prepare(`UPDATE \"${table}\" SET ${setSql}${where.sql}`).bind(...values, ...where.values).run();
  if (!before.length) return [];
  const keys = before.map((row) => row[info.key]).filter((value) => value != null);
  const placeholders = keys.map(() => '?').join(',');
  const result = await db.prepare(`SELECT ${info.columns.map((column) => `\"${column}\"`).join(', ')} FROM \"${table}\" WHERE \"${info.key}\" IN (${placeholders})`).bind(...keys).all<Record<string, any>>();
  return (result.results || []).map((row) => decodeRow(table, row));
}

async function checkpointUsage(db: D1DatabaseLike, args: any): Promise<Record<string, any>> {
  const userId = args.p_user_id === 'person_2' ? 'person_2' : 'person_1';
  const now = Number(args.p_now_ms || Date.now());
  const grace = Math.max(0, Number(args.p_grace_ms || 15000));
  const today = String(args.p_today || new Date(now).toISOString().slice(0, 10));
  const existing = await db.prepare('SELECT * FROM synax_user_usage WHERE user_id = ? LIMIT 1').bind(userId).first<Record<string, any>>();
  const row: Record<string, any> = existing || {
    user_id: userId, continuous_used_seconds: 0, daily_used_seconds: 0,
    daily_usage_date: today, active: 0, active_started_at: null,
    last_heartbeat: 0, last_seen: 0, updated_at: null, usage_version: 0,
  };
  const wasActive = Boolean(row.active);
  if (Boolean(args.p_active)) {
    if (!wasActive || !row.active_started_at) row.active_started_at = now;
    row.active = 1;
    row.last_heartbeat = now;
  } else {
    if (wasActive && row.active_started_at) {
      const heartbeat = Number(row.last_heartbeat || row.active_started_at);
      const effectiveEnd = Math.min(now, heartbeat + grace);
      const elapsed = Math.max(0, Math.floor((effectiveEnd - Number(row.active_started_at)) / 1000));
      row.continuous_used_seconds = Number(row.continuous_used_seconds || 0) + elapsed;
      row.daily_used_seconds = Number(row.daily_used_seconds || 0) + elapsed;
    }
    row.active = 0;
    row.active_started_at = null;
    row.last_heartbeat = now;
    if (wasActive) row.last_seen = now;
  }
  row.daily_usage_date = row.daily_usage_date || today;
  row.usage_version = Number(row.usage_version || 0) + 1;
  row.updated_at = new Date(now).toISOString();
  await insertRows(db, 'synax_user_usage', [row], new URLSearchParams('on_conflict=user_id'), 'resolution=merge-duplicates');
  return decodeRow('synax_user_usage', row);
}

async function resetDailyUsage(db: D1DatabaseLike, args: any): Promise<Record<string, any>[]> {
  const resetAt = Number(args.p_reset_at_ms || Date.now());
  const resetDate = String(args.p_reset_date || new Date(resetAt).toISOString().slice(0, 10));
  const rows: Record<string, any>[] = [];
  for (const userId of ['person_1', 'person_2']) {
    const existing = await db.prepare('SELECT * FROM synax_user_usage WHERE user_id = ? LIMIT 1').bind(userId).first<Record<string, any>>();
    const row: Record<string, any> = existing || {
      user_id: userId, continuous_used_seconds: 0, daily_used_seconds: 0,
      daily_usage_date: resetDate, active: 0, active_started_at: null,
      last_heartbeat: 0, last_seen: 0, updated_at: null, usage_version: 0,
    };
    const heartbeat = Number(row.last_heartbeat || 0);
    const activeAtReset = Boolean(row.active && heartbeat > 0 && heartbeat <= Date.now() + 15000 && heartbeat >= resetAt - 15000);
    row.daily_usage_date = resetDate;
    row.daily_used_seconds = 0;
    row.continuous_used_seconds = 0;
    if (activeAtReset) {
      row.active = 1;
      row.active_started_at = resetAt;
    } else if (row.active) {
      row.active = 0;
      row.active_started_at = null;
      row.last_seen = heartbeat || row.last_seen || resetAt;
    }
    row.updated_at = new Date(resetAt).toISOString();
    row.usage_version = Number(row.usage_version || 0) + 1;
    await insertRows(db, 'synax_user_usage', [row], new URLSearchParams('on_conflict=user_id'), 'resolution=merge-duplicates');
    rows.push(decodeRow('synax_user_usage', row));
  }
  return rows;
}

export async function d1RestFetch(database: D1DatabaseLike, pathname: string, init: RequestInit = {}): Promise<Response> {
  if (!database) throw new Error('Cloudflare D1 binding SYNAX_DB is not configured.');
  const url = new URL(pathname, 'https://synax-d1.internal');
  const path = url.pathname.replace(/^\/rest\/v1\//, '');
  const method = String(init.method || 'GET').toUpperCase();
  const prefer = String((init.headers as Record<string, string> | undefined)?.Prefer || (init.headers as Headers | undefined)?.get?.('Prefer') || '');

  if (path.startsWith('rpc/')) {
    const body = parseJsonBody(init.body);
    if (path === 'rpc/synax_checkpoint_usage' && method === 'POST') {
      return responseJson([await checkpointUsage(database, body)]);
    }
    if (path === 'rpc/synax_reset_daily_usage' && method === 'POST') {
      return responseJson(await resetDailyUsage(database, body));
    }
    return responseJson({ error: `Unsupported D1 RPC: ${path}` }, 404);
  }

  const table = path.split('/')[0] as TableName;
  if (!(table in TABLES)) return responseJson({ error: `Unknown SYNAX D1 table: ${table}` }, 404);
  const params = url.searchParams;

  if (method === 'GET') return responseJson(await selectRows(database, table, params));
  if (method === 'POST') {
    const body = parseJsonBody(init.body);
    const rows = Array.isArray(body) ? body : [body];
    const inserted = await insertRows(database, table, rows, params, prefer);
    return responseJson(inserted, 200);
  }
  if (method === 'PATCH') {
    const patch = parseJsonBody(init.body);
    return responseJson(await patchRows(database, table, params, patch, prefer));
  }
  if (method === 'DELETE') {
    const info = TABLES[table];
    const where = whereClause(table, params);
    if (!where.sql) return responseJson({ error: `Refusing an unfiltered delete on ${table}.` }, 400);
    await database.prepare(`DELETE FROM \"${table}\"${where.sql}`).bind(...where.values).run();
    return responseJson([]);
  }
  return responseJson({ error: `Unsupported method ${method}` }, 405);
}

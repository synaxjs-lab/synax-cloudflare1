import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { d1RestFetch } from '../worker/d1-rest.ts';

class SqliteStatementAdapter {
  constructor(db, sql) { this.db = db; this.sql = sql; this.values = []; }
  bind(...values) { this.values = values; return this; }
  first(columnName) {
    const row = this.db.prepare(this.sql).get(...this.values);
    if (columnName && row) return row[columnName] ?? null;
    return row ?? null;
  }
  all() { return { results: this.db.prepare(this.sql).all(...this.values), success: true }; }
  run() {
    const result = this.db.prepare(this.sql).run(...this.values);
    return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  }
}

class SqliteD1Adapter {
  constructor(db) { this.db = db; }
  prepare(sql) { return new SqliteStatementAdapter(this.db, sql); }
  async batch(statements) {
    return this.db.transaction(() => statements.map((statement) => statement.run()))();
  }
}

async function createTestDb() {
  const db = new DatabaseSync(':memory:');
  const migration = await readFile(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8');
  db.exec(migration);
  return { raw: db, d1: new SqliteD1Adapter(db) };
}

async function request(d1, path, method = 'GET', body, prefer = '') {
  return d1RestFetch(d1, path, {
    method,
    headers: { Prefer: prefer },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test('D1 adapter supports fresh state, messages, sessions, call signaling and usage RPCs', async () => {
  const { raw, d1 } = await createTestDb();

  // State JSON round-trip and conflict update.
  let response = await request(d1, '/rest/v1/synax_state?on_conflict=id', 'POST', {
    id: 'main', state: { settings: { theme: 'celestial' }, users: { person_1: { name: 'A' } } }, updated_at: '2026-11-18T00:00:00.000Z',
  }, 'resolution=merge-duplicates,return=minimal');
  assert.equal(response.status, 200);
  response = await request(d1, '/rest/v1/synax_state?id=eq.main&select=state&limit=1');
  let rows = await response.json();
  assert.equal(rows[0].state.settings.theme, 'celestial');

  // Idempotent message insert, chronological paging, JSON columns and update.
  const message = {
    id: 'msg_1', client_message_id: 'client_1', sender_id: 'person_1', type: 'text', text: 'hello',
    timestamp: 100, status: 'sent', reactions: { '👍': 'person_2' }, reply_to: { id: 'm0' },
    is_pinned: false, is_edited: false, deleted: false,
  };
  response = await request(d1, '/rest/v1/synax_messages?on_conflict=client_message_id', 'POST', message, 'resolution=ignore-duplicates,return=representation');
  rows = await response.json();
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].reactions, { '👍': 'person_2' });
  await request(d1, '/rest/v1/synax_messages?on_conflict=client_message_id', 'POST', { ...message, id: 'different_id', text: 'duplicate retry' }, 'resolution=ignore-duplicates,return=representation');
  response = await request(d1, '/rest/v1/synax_messages?client_message_id=eq.client_1&limit=1');
  rows = await response.json();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].text, 'hello');
  response = await request(d1, '/rest/v1/synax_messages?id=eq.msg_1', 'PATCH', { status: 'read', is_pinned: true }, 'return=representation');
  rows = await response.json();
  assert.equal(rows[0].status, 'read');
  assert.equal(rows[0].is_pinned, true);

  // Pagination, order and IN filter used by message-history and read receipts.
  for (let n = 2; n <= 5; n += 1) {
    await request(d1, '/rest/v1/synax_messages?on_conflict=id', 'POST', {
      ...message, id: `msg_${n}`, client_message_id: `client_${n}`, timestamp: n * 100, text: `message ${n}`,
    }, 'resolution=ignore-duplicates,return=minimal');
  }
  response = await request(d1, '/rest/v1/synax_messages?order=timestamp.desc&limit=2&offset=1');
  rows = await response.json();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].timestamp, 400);
  response = await request(d1, '/rest/v1/synax_messages?id=in.(msg_2,msg_4)');
  rows = await response.json();
  assert.equal(rows.length, 2);

  // Session boolean conversion and deletion.
  await request(d1, '/rest/v1/synax_sessions?on_conflict=token', 'POST', {
    token: 'session_1', user_id: 'person_1', session_start: 10, last_active: 11,
    allowed_seconds: 3600, is_expired: false, active: true, ended_at: null,
  }, 'resolution=merge-duplicates,return=minimal');
  response = await request(d1, '/rest/v1/synax_sessions?token=eq.session_1&limit=1');
  rows = await response.json();
  assert.equal(rows[0].active, true);
  await request(d1, '/rest/v1/synax_sessions?token=eq.session_1', 'DELETE');
  response = await request(d1, '/rest/v1/synax_sessions?token=eq.session_1');
  assert.deepEqual(await response.json(), []);

  // Call signal auto-increment and JSON payload->>callId filter.
  response = await request(d1, '/rest/v1/synax_call_signals', 'POST', {
    from_user_id: 'person_1', target_user_id: 'person_2', type: 'offer', call_type: 'voice',
    payload: { callId: 'call_abc', sdp: 'test' }, created_at: '2026-11-18T00:00:00.000Z',
  }, 'return=representation');
  rows = await response.json();
  assert.equal(rows.length, 1);
  assert.ok(rows[0].id > 0);
  response = await request(d1, '/rest/v1/synax_call_signals?payload-%3E%3EcallId=eq.call_abc');
  rows = await response.json();
  assert.equal(rows.length, 1);

  // Usage checkpoint and scheduled reset RPCs.
  response = await request(d1, '/rest/v1/rpc/synax_checkpoint_usage', 'POST', {
    p_user_id: 'person_1', p_active: true, p_now_ms: 100000, p_today: '2026-11-18', p_grace_ms: 15000,
  });
  rows = await response.json();
  assert.equal(rows[0].active, true);
  response = await request(d1, '/rest/v1/rpc/synax_checkpoint_usage', 'POST', {
    p_user_id: 'person_1', p_active: false, p_now_ms: 160000, p_today: '2026-11-18', p_grace_ms: 15000,
  });
  rows = await response.json();
  assert.equal(rows[0].daily_used_seconds, 15);
  response = await request(d1, '/rest/v1/rpc/synax_reset_daily_usage', 'POST', {
    p_reset_at_ms: 200000, p_reset_date: '2026-11-19',
  });
  rows = await response.json();
  assert.equal(rows.length, 2);
  assert.equal(rows.find((row) => row.user_id === 'person_1').daily_used_seconds, 0);

  // Upload manifest and part bookkeeping are created by direct D1 statements in the API.
  raw.prepare(`INSERT INTO synax_uploads (upload_id, object_key, r2_upload_id, user_id, file_name, content_type, file_size, uploaded_size, created_at, completed)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run('up_1', 'media/person_1/a.bin', 'r2_1', 'person_1', 'a.bin', 'application/octet-stream', 12, 12, 1000, 0);
  raw.prepare('INSERT INTO synax_upload_parts (upload_id, part_number, etag, part_size) VALUES (?, ?, ?, ?)').run('up_1', 1, 'etag', 12);
  raw.prepare('DELETE FROM synax_uploads WHERE upload_id = ?').run('up_1');
  assert.equal(raw.prepare('SELECT COUNT(*) AS c FROM synax_upload_parts WHERE upload_id = ?').get('up_1').c, 0);

  raw.close();
});

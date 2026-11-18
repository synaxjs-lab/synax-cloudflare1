import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import { d1RestFetch } from './worker/d1-rest';

// Type definitions for internal server database
interface DbSchema {
  users: {
    person_1: {
      id: 'person_1';
      slot: 1;
      name: string;
      username: string;
      passwordHash: string;
      logo: any;
      pfpUrl: string;
      nickname: string;
      bio: string;
      isLocked: boolean;
      lockReason?: string;
      allowedMinutes: number;
      dailyUsageSeconds: number;
      dailyUsageDate?: string;
      sessionStartTimestamp?: number;
      activeUsageSeconds?: number;
      activeSessionCount?: number;
      activeSessionStartedAt?: number;
      lastActiveTimestamp?: number;
    };
    person_2: {
      id: 'person_2';
      slot: 2;
      name: string;
      username: string;
      passwordHash: string;
      logo: any;
      pfpUrl: string;
      nickname: string;
      bio: string;
      isLocked: boolean;
      lockReason?: string;
      allowedMinutes: number;
      dailyUsageSeconds: number;
      dailyUsageDate?: string;
      sessionStartTimestamp?: number;
      activeUsageSeconds?: number;
      activeSessionCount?: number;
      activeSessionStartedAt?: number;
      lastActiveTimestamp?: number;
    };
  };
  admin: {
    username: string;
    passwordHash: string;
  };
  settings: {
    worldTitle: string;
    worldSubtitle: string;
    welcomeMessage: string;
    theme: 'celestial' | 'cyberpunk' | 'twilight' | 'aurora';
    chatWallpaper: string;
    accentColor: string;
    introDurationSeconds: number;
    timeOverMessage: string;
    timeStrategy: 'continuous' | 'daily';
    dailyResetAtMidnight?: boolean;
    warningMinutes: number[];
    showTimerToUsers?: boolean;
    restrictionsOnExpire: {
      disableMessaging: boolean;
      disableVoiceCalls: boolean;
      disableVideoCalls: boolean;
      disableImages: boolean;
      disableFiles: boolean;
      disableVoiceMessages: boolean;
      lockSession: boolean;
    };
    featuresEnabled: {
      messages: boolean;
      reactions: boolean;
      imageSharing: boolean;
      fileSharing: boolean;
      voiceMessages: boolean;
      voiceCalls: boolean;
      videoCalls: boolean;
      editing: boolean;
      deleting: boolean;
    };
  };
  messages: any[];
  sessions: Record<string, {
    token: string;
    userId: 'person_1' | 'person_2' | 'admin';
    sessionStart: number;
    lastActive: number;
    allowedSeconds: number;
    isExpired: boolean;
    active?: boolean;
    endedAt?: number;
  }>;
  logs: any[];
}

// Passwords use async PBKDF2 through Web Crypto. This avoids expensive
// synchronous JavaScript hashing inside the 10 ms CPU budget of Workers Free.
const PASSWORD_HASH_ITERATIONS = 310_000;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hashPassword(password: string): Promise<string> {
  const normalized = String(password || '');
  if (normalized.length < 12 || normalized.length > 1024) {
    throw new Error('Passwords must be between 12 and 1024 characters.');
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(normalized), 'PBKDF2', false, ['deriveBits']);
  const derived = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PASSWORD_HASH_ITERATIONS, hash: 'SHA-256' },
    material,
    256,
  ));
  return `pbkdf2-sha256$${PASSWORD_HASH_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(derived)}`;
}

async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  try {
    const [algorithm, iterationText, saltText, hashText] = String(storedHash || '').split('$');
    const iterations = Number(iterationText);
    if (algorithm !== 'pbkdf2-sha256' || !Number.isInteger(iterations) || iterations < 100_000 || iterations > 1_000_000) return false;
    const expected = base64ToBytes(hashText);
    const salt = base64ToBytes(saltText);
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password || '')), 'PBKDF2', false, ['deriveBits']);
    const actual = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, expected.length * 8,
    ));
    if (actual.length !== expected.length) return false;
    let difference = 0;
    for (let index = 0; index < actual.length; index += 1) difference |= actual[index] ^ expected[index];
    return difference === 0;
  } catch {
    return false;
  }
}

// Initial seed. It runs only when the new D1 database has no SYNAX state row.
async function getInitialDb(env: any = cloudflareEnv): Promise<DbSchema> {
  const person1Password = String(env?.SYNAX_PERSON_1_PASSWORD || '');
  const person2Password = String(env?.SYNAX_PERSON_2_PASSWORD || '');
  const adminPassword = String(env?.SYNAX_ADMIN_PASSWORD || '');
  const configuredPasswords = [person1Password, person2Password, adminPassword];
  if (configuredPasswords.some((password) => password.length < 12)) {
    throw new Error('Set SYNAX_PERSON_1_PASSWORD, SYNAX_PERSON_2_PASSWORD and SYNAX_ADMIN_PASSWORD as Worker secrets (at least 12 characters each) before first deployment.');
  }
  const [person1Hash, person2Hash, adminHash] = await Promise.all([
    hashPassword(person1Password), hashPassword(person2Password), hashPassword(adminPassword),
  ]);
  return {
    users: {
      person_1: {
        id: 'person_1',
        slot: 1,
        name: 'Kaelen Thorne',
        username: 'kaelen',
        passwordHash: person1Hash,
        logo: {
          id: 'astral_crest',
          name: 'Astral Crest',
          accentColor: '#6366f1',
          glowColor: 'rgba(99, 102, 241, 0.5)',
          svgPath: 'M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z'
        },
        pfpUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=400&auto=format&fit=crop&q=80',
        nickname: 'Kael',
        bio: 'Guardian of the Northern Star',
        isLocked: false,
        allowedMinutes: 60,
        dailyUsageSeconds: 0,
        activeUsageSeconds: 0,
        activeSessionCount: 0,
      },
      person_2: {
        id: 'person_2',
        slot: 2,
        name: 'Seraphina Vance',
        username: 'seraphina',
        passwordHash: person2Hash,
        logo: {
          id: 'lunar_chrono',
          name: 'Lunar Chrono',
          accentColor: '#ec4899',
          glowColor: 'rgba(236, 72, 153, 0.5)',
          svgPath: 'M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z'
        },
        pfpUrl: 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=400&auto=format&fit=crop&q=80',
        nickname: 'Sera',
        bio: 'Keeper of the Celestial Loom',
        isLocked: false,
        allowedMinutes: 60,
        dailyUsageSeconds: 0,
      }
    },
    admin: {
      username: 'admin',
      passwordHash: adminHash,
    },
    settings: {
      worldTitle: 'SYNAX',
      worldSubtitle: 'Where Two Worlds Meet.',
      welcomeMessage: 'Welcome to your private sanctuary. Every conversation, voice note, and shared moment here belongs solely to you both.',
      theme: 'celestial',
      chatWallpaper: 'stars',
      accentColor: '#6366f1',
      introDurationSeconds: 7,
      timeOverMessage: 'Your private-world time has ended for now. See you again soon ✨',
      timeStrategy: 'daily',
      dailyResetAtMidnight: true,
      warningMinutes: [10, 5, 1],
      showTimerToUsers: true,
      restrictionsOnExpire: {
        disableMessaging: true,
        disableVoiceCalls: true,
        disableVideoCalls: true,
        disableImages: true,
        disableFiles: true,
        disableVoiceMessages: true,
        lockSession: true
      },
      featuresEnabled: {
        messages: true,
        reactions: true,
        imageSharing: true,
        fileSharing: true,
        voiceMessages: true,
        voiceCalls: true,
        videoCalls: true,
        editing: true,
        deleting: true
      }
    },
    messages: [],
    sessions: {},
    logs: [
      {
        id: 'log_init',
        timestamp: Date.now(),
        actor: 'System',
        action: 'Synax Core Initialized',
        details: 'Initial configuration and user marks loaded',
        level: 'info'
      }
    ]
  };
}

// Persistent state is stored in Cloudflare D1. Media is stored in R2.
// The D1 and R2 bindings are server-only and must never be exposed to the browser.
let cloudflareEnv: any = null;
let cloudflareExecutionContext: any = null;

export function configureCloudflareRuntime(env: any, ctx: any) {
  cloudflareEnv = env;
  cloudflareExecutionContext = ctx;
}
const D1_STATE_TABLE = 'synax_state';
const D1_STATE_ID = 'main';
const D1_SESSIONS_TABLE = 'synax_sessions';
const D1_CALL_SIGNALS_TABLE = 'synax_call_signals';
const D1_MESSAGES_TABLE = 'synax_messages';
const D1_USER_USAGE_TABLE = 'synax_user_usage';
const D1_CHAT_SETTINGS_TABLE = 'synax_chat_settings';
const SYNAX_CHAT_ID = 'private';
const ALLOWED_CHAT_BACKGROUND_PRESETS = new Set(['stars','nebula','aurora','twilight','midnight','crimson']);
const isProduction = true;
const useD1 = true;

const FALLBACK_ICE_SERVERS = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.l.google.com:19302' },
];

function getConfiguredTurnKeyId(): string {
  return String(cloudflareEnv?.CLOUDFLARE_TURN_KEY_ID || '').trim();
}

function getConfiguredTurnApiToken(): string {
  return String(cloudflareEnv?.CLOUDFLARE_TURN_API_TOKEN || '').trim();
}

let db: DbSchema;
let persistenceQueue: Promise<void> = Promise.resolve();
let lastPersistenceError: unknown = null;
let lastRemoteSync = 0;
let stateRefreshInFlight: Promise<void> | null = null;
const STATE_REFRESH_TTL_MS = 10000;
// Session revocation and timer expiry must take effect on the next request.
const SESSION_CACHE_TTL_MS = 0;
const sessionCache = new Map<string, { session: DbSchema['sessions'][string]; expiresAt: number }>();

// D1 is the authoritative database in the Cloudflare deployment.
let sessionsTableAvailable: boolean | null = true;
let usageTableAvailable: boolean | null = true;
let usageCheckpointRpcAvailable: boolean | null = true;

function isMissingDataApiTableError(error: unknown): boolean {
  const message = String(error instanceof Error ? error.message : error || '');
  return /no such table|unknown SYNAX D1 table|D1 binding .* not configured/i.test(message);
}


type ChatBackgroundRecord = {
  chat_id: string;
  background_type: 'preset' | 'image';
  background_value: string;
  background_updated_at: number;
  updated_by: 'person_1' | 'person_2' | null;
};

const DEFAULT_CHAT_BACKGROUND: ChatBackgroundRecord = {
  chat_id: SYNAX_CHAT_ID,
  background_type: 'preset',
  background_value: 'stars',
  background_updated_at: 0,
  updated_by: null,
};

function normalizeChatBackground(row: any): ChatBackgroundRecord {
  const type = row?.background_type === 'image' ? 'image' : 'preset';
  const value = String(row?.background_value || (type === 'preset' ? 'stars' : '')).trim();
  return {
    chat_id: SYNAX_CHAT_ID,
    background_type: type,
    background_value: type === 'preset' && !ALLOWED_CHAT_BACKGROUND_PRESETS.has(value) ? 'stars' : value,
    background_updated_at: Number(row?.background_updated_at || 0),
    updated_by: row?.updated_by === 'person_1' || row?.updated_by === 'person_2' ? row.updated_by : null,
  };
}

async function loadChatBackground(): Promise<ChatBackgroundRecord> {
  try {
    const res = await databaseFetch(
      `/rest/v1/${D1_CHAT_SETTINGS_TABLE}?chat_id=eq.${encodeURIComponent(SYNAX_CHAT_ID)}` +
      `&select=chat_id,background_type,background_value,background_updated_at,updated_by&limit=1`,
    );
    const rows = await res.json() as any[];
    return rows[0] ? normalizeChatBackground(rows[0]) : DEFAULT_CHAT_BACKGROUND;
  } catch (error) {
    if (isMissingDataApiTableError(error)) return DEFAULT_CHAT_BACKGROUND;
    throw error;
  }
}

async function saveChatBackground(background: ChatBackgroundRecord) {
  await databaseFetch(`/rest/v1/${D1_CHAT_SETTINGS_TABLE}?on_conflict=chat_id`, {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({
      chat_id: SYNAX_CHAT_ID,
      background_type: background.background_type,
      background_value: background.background_value,
      background_updated_at: background.background_updated_at,
      updated_by: background.updated_by,
      updated_at: new Date().toISOString(),
    }),
  });
}

function cloneDb(value: DbSchema): DbSchema {
  return JSON.parse(JSON.stringify(value));
}

async function databaseFetch(pathname: string, init: RequestInit = {}) {
  const database = cloudflareEnv?.SYNAX_DB;
  if (!database) throw new Error('Cloudflare D1 binding SYNAX_DB is missing. Configure it in wrangler.jsonc.');
  return d1RestFetch(database, pathname, init);
}

async function signMediaKey(objectKey: string): Promise<string> {
  const secret = String(cloudflareEnv?.SYNAX_MEDIA_SIGNING_SECRET || '');
  if (secret.length < 32) throw new Error('SYNAX_MEDIA_SIGNING_SECRET is not configured.');
  const cryptoKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(objectKey));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function createSignedMediaUrl(objectKey: string): Promise<string> {
  const signature = await signMediaKey(objectKey);
  return `/api/media?key=${encodeURIComponent(objectKey)}&sig=${signature}`;
}

/** Extract only SYNAX's own signed R2 media URL. External avatar/image URLs are ignored. */
function getPrivateR2ObjectKey(mediaUrl: unknown): string | null {
  if (typeof mediaUrl !== 'string' || !mediaUrl.trim()) return null;
  try {
    const parsed = new URL(mediaUrl, 'https://synax.invalid');
    if (parsed.pathname !== '/api/media') return null;
    const key = parsed.searchParams.get('key') || '';
    if (!/^(media|chat-backgrounds)\/[A-Za-z0-9_./-]+$/.test(key) || key.includes('..')) return null;
    return key;
  } catch {
    return null;
  }
}

async function deletePrivateR2Media(mediaUrl: unknown): Promise<void> {
  const key = getPrivateR2ObjectKey(mediaUrl);
  if (!key || !cloudflareEnv?.SYNAX_MEDIA) return;
  try {
    await cloudflareEnv.SYNAX_MEDIA.delete(key);
  } catch (error) {
    // The database change remains authoritative; an orphaned R2 object is
    // logged for cleanup rather than making a successful message delete fail.
    console.error('SYNAX R2 object cleanup failed:', key, error);
  }
}

async function deletePrivateR2MediaBatch(mediaUrls: unknown[], retainedKeys = new Set<string>()): Promise<number> {
  const keys = Array.from(new Set(mediaUrls.map(getPrivateR2ObjectKey).filter((key): key is string => Boolean(key))))
    .filter((key) => !retainedKeys.has(key));
  let deleted = 0;
  for (let offset = 0; offset < keys.length; offset += 10) {
    const batch = keys.slice(offset, offset + 10);
    const results = await Promise.allSettled(batch.map((key) => cloudflareEnv.SYNAX_MEDIA.delete(key)));
    deleted += results.filter((result) => result.status === 'fulfilled').length;
    results.forEach((result, index) => {
      if (result.status === 'rejected') console.error('SYNAX R2 batch cleanup failed:', batch[index], result.reason);
    });
  }
  return deleted;
}

const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_LIMIT_MAX_FAILURES = 5;

async function getLoginAttemptKey(req: Request, userId: 'person_1' | 'person_2' | 'admin'): Promise<string> {
  // Cloudflare supplies this header at the edge. For local development, use a
  // shared local key rather than trusting a client-controlled X-Forwarded-For.
  const ipAddress = String(req.headers['cf-connecting-ip'] || 'local-development').slice(0, 80);
  return signMediaKey(`login:${userId}:${ipAddress}`);
}

async function getLoginLockout(req: Request, userId: 'person_1' | 'person_2' | 'admin') {
  const key = await getLoginAttemptKey(req, userId);
  const row = await cloudflareEnv.SYNAX_DB.prepare(
    'SELECT failure_count, window_started_at, locked_until FROM synax_login_attempts WHERE attempt_key = ? LIMIT 1',
  ).bind(key).first();
  const now = Date.now();
  return {
    key,
    lockedUntil: Number(row?.locked_until || 0) > now ? Number(row.locked_until) : 0,
  };
}

async function recordFailedLogin(key: string) {
  const now = Date.now();
  await cloudflareEnv.SYNAX_DB.prepare(`
    INSERT INTO synax_login_attempts (attempt_key, window_started_at, failure_count, locked_until, updated_at)
    VALUES (?, ?, 1, NULL, ?)
    ON CONFLICT(attempt_key) DO UPDATE SET
      failure_count = CASE
        WHEN ? - window_started_at >= ? THEN 1
        ELSE failure_count + 1
      END,
      window_started_at = CASE
        WHEN ? - window_started_at >= ? THEN ?
        ELSE window_started_at
      END,
      locked_until = CASE
        WHEN (CASE WHEN ? - window_started_at >= ? THEN 1 ELSE failure_count + 1 END) >= ?
          THEN ? + ?
        ELSE NULL
      END,
      updated_at = excluded.updated_at
  `).bind(
    key, now, now,
    now, LOGIN_RATE_LIMIT_WINDOW_MS,
    now, LOGIN_RATE_LIMIT_WINDOW_MS, now,
    now, LOGIN_RATE_LIMIT_WINDOW_MS, LOGIN_RATE_LIMIT_MAX_FAILURES,
    now, LOGIN_RATE_LIMIT_WINDOW_MS,
  ).run();
}

async function clearFailedLogins(key: string) {
  await cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_login_attempts WHERE attempt_key = ?').bind(key).run();
}

function safeObjectExtension(fileName: string): string {
  const ext = (String(fileName || '').match(/(\.[^.]+)$/)?.[1] || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
  return ext && ext.length <= 15 ? ext : '';
}

function safeInlineFileName(fileName: string): string {
  return String(fileName || 'download').replace(/[\r\n"\\]/g, '_').slice(0, 160) || 'download';
}

function safeMediaContentDisposition(mimeType: string, fileName: string): string {
  const safeName = safeInlineFileName(fileName);
  // Only browser-native media types are shown inline. Other uploaded formats
  // are downloads to avoid rendering user-supplied HTML or active documents on
  // the SYNAX origin.
  const inline = /^(image\/(jpeg|png|webp|gif|avif)|video\/(mp4|webm|quicktime)|audio\/(mpeg|mp4|wav|ogg|webm))$/i.test(mimeType);
  return `${inline ? 'inline' : 'attachment'}; filename="${safeName}"`;
}

async function persistToD1(snapshot: DbSchema) {
  const body = JSON.stringify({ id: D1_STATE_ID, state: snapshot, updated_at: new Date().toISOString() });
  const res = await databaseFetch(`/rest/v1/${D1_STATE_TABLE}?on_conflict=id`, {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body,
  });
  await res.arrayBuffer().catch(() => undefined);
}

async function loadDbFromD1(): Promise<DbSchema | null> {
  const res = await databaseFetch(`/rest/v1/${D1_STATE_TABLE}?id=eq.${encodeURIComponent(D1_STATE_ID)}&select=state&limit=1`);
  const rows = await res.json() as Array<{ state: DbSchema }>;
  return rows[0]?.state || null;
}

type D1MessageRow = {
  id: string;
  client_message_id?: string | null;
  sender_id: 'person_1' | 'person_2' | 'system';
  type: 'text' | 'image' | 'video' | 'file' | 'voice' | 'system';
  text?: string | null;
  file_url?: string | null;
  file_name?: string | null;
  file_size?: number | null;
  audio_duration?: number | null;
  timestamp: number;
  status: 'sent' | 'delivered' | 'read';
  reactions?: Record<string, string> | null;
  reply_to?: { id: string; text: string; senderName: string } | null;
  is_pinned?: boolean | null;
  is_edited?: boolean | null;
  deleted?: boolean | null;
};

function rowToChatMessage(row: D1MessageRow): any {
  return {
    id: row.id,
    clientMessageId: row.client_message_id || undefined,
    senderId: row.sender_id,
    type: row.type,
    text: row.text || '',
    fileUrl: row.file_url || undefined,
    fileName: row.file_name || undefined,
    fileSize: row.file_size == null ? undefined : Number(row.file_size),
    audioDuration: row.audio_duration == null ? undefined : Number(row.audio_duration),
    timestamp: Number(row.timestamp),
    status: row.status,
    reactions: row.reactions || {},
    replyTo: (() => {
      const value = row.reply_to;
      if (!value) return undefined;
      if (typeof value === 'string') {
        try { return JSON.parse(value); } catch { return undefined; }
      }
      return value;
    })(),
    isPinned: Boolean(row.is_pinned),
    isEdited: Boolean(row.is_edited),
    deleted: Boolean(row.deleted),
  };
}

function chatMessageToRow(message: any, clientMessageId?: string | null): D1MessageRow {
  return {
    id: String(message.id),
    client_message_id: clientMessageId || null,
    sender_id: message.senderId,
    type: message.type,
    text: message.text || '',
    file_url: message.fileUrl || null,
    file_name: message.fileName || null,
    file_size: message.fileSize == null ? null : Number(message.fileSize),
    audio_duration: message.audioDuration == null ? null : Number(message.audioDuration),
    timestamp: Number(message.timestamp),
    status: message.status || 'sent',
    reactions: message.reactions || {},
    reply_to: message.replyTo || null,
    is_pinned: Boolean(message.isPinned),
    is_edited: Boolean(message.isEdited),
    deleted: Boolean(message.deleted),
  };
}

async function loadMessagesFromD1(): Promise<any[]> {
  // Cloudflare D1 is the canonical long-term message history. The Durable Object
  // queue only supplements rows which have not reached D1 yet.
  // IMPORTANT: a failed Durable Object queue read must NOT block canonical
  // history. Previously that read ran before the try/catch, so one unhealthy
  // realtime request caused GET /api/messages to fail even while D1 had
  // the messages. That made messages appear to vanish after refresh.
  let pending: any[] = [];
  try {
    pending = await loadPendingMessagesFromRealtime();
  } catch (error) {
    console.warn(
      'SYNAX realtime pending queue unavailable; continuing with D1 message history:',
      error,
    );
  }

  const pageSize = 1000;
  const rows: D1MessageRow[] = [];
  try {
    // Read every page rather than silently truncating history at 5,000 rows.
    // PostgREST commonly caps a response at 1,000 rows. Request newest-first,
    // then restore chronological order before returning to the chat UI.
    for (let offset = 0; ; offset += pageSize) {
      const path =
        `/rest/v1/${D1_MESSAGES_TABLE}?select=id,client_message_id,sender_id,type,text,file_url,file_name,file_size,audio_duration,timestamp,status,reactions,reply_to,is_pinned,is_edited,deleted` +
        `&order=timestamp.desc,id.desc&limit=${pageSize}&offset=${offset}`;
      const response = await databaseFetch(path, {
        headers: { 'Cache-Control': 'no-cache' },
      });
      const page = await response.json() as D1MessageRow[];
      if (!Array.isArray(page)) {
        throw new Error('D1 returned an invalid message history response.');
      }
      rows.push(...page);
      if (page.length < pageSize) break;
    }
  } catch (error) {
    if (isMissingDataApiTableError(error)) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Canonical chat history ${D1_MESSAGES_TABLE} is not accessible in D1. ` +
        `Check that the D1 migrations have been applied and the SYNAX_DB binding is configured. Details: ${detail}`
      );
    }
    console.error('SYNAX canonical message history fetch failed:', error);
    throw error;
  }

  // Client retries and Durable Object pending entries may overlap with rows
  // already committed to D1. Deduplicate by client ID first, then row ID.
  const unique = new Map<string, D1MessageRow>();
  for (const row of rows) {
    const key = String(row.client_message_id || row.id || '');
    if (key && !unique.has(key)) unique.set(key, row);
  }
  const messages = Array.from(unique.values())
    .map(rowToChatMessage)
    .sort((a: any, b: any) =>
      Number(a.timestamp) - Number(b.timestamp) || String(a.id).localeCompare(String(b.id))
    );

  return mergePendingMessages(messages, pending);
}

async function findMessageById(id: string): Promise<any | null> {
  const res = await databaseFetch(
    `/rest/v1/${D1_MESSAGES_TABLE}?id=eq.${encodeURIComponent(id)}&select=id,client_message_id,sender_id,type,text,file_url,file_name,file_size,audio_duration,timestamp,status,reactions,reply_to,is_pinned,is_edited,deleted&limit=1`,
    { headers: { 'Cache-Control': 'no-cache' } },
  );
  const rows = await res.json() as D1MessageRow[];
  return rows[0] ? rowToChatMessage(rows[0]) : null;
}

async function findMessageByClientId(clientMessageId: string): Promise<any | null> {
  const res = await databaseFetch(
    `/rest/v1/${D1_MESSAGES_TABLE}?client_message_id=eq.${encodeURIComponent(clientMessageId)}&select=id,client_message_id,sender_id,type,text,file_url,file_name,file_size,audio_duration,timestamp,status,reactions,reply_to,is_pinned,is_edited,deleted&limit=1`,
    { headers: { 'Cache-Control': 'no-cache' } },
  );
  const rows = await res.json() as D1MessageRow[];
  return rows[0] ? rowToChatMessage(rows[0]) : null;
}

async function insertMessageToD1(message: any, clientMessageId?: string | null): Promise<any> {
  const row = chatMessageToRow(message, clientMessageId);
  const useIdempotency = Boolean(clientMessageId);
  const path = useIdempotency
    ? `/rest/v1/${D1_MESSAGES_TABLE}?on_conflict=client_message_id`
    : `/rest/v1/${D1_MESSAGES_TABLE}?on_conflict=id`;

  const res = await databaseFetch(path, {
    method: 'POST',
    headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
    body: JSON.stringify(row),
  });
  const rows = await res.json().catch(() => []);
  if (Array.isArray(rows) && rows[0]) return rowToChatMessage(rows[0]);

  // A safe idempotent retry can be ignored by Postgres because the row already
  // exists. Confirm that canonical row before reporting the message as saved.
  const existing = useIdempotency
    ? await findMessageByClientId(String(clientMessageId))
    : await findMessageById(String(message.id));
  if (existing) return existing;
  throw new Error('D1 did not return or confirm the saved chat message.');
}

async function updateMessageInD1(id: string, patch: Record<string, unknown>): Promise<any | null> {
  const res = await databaseFetch(`/rest/v1/${D1_MESSAGES_TABLE}?id=eq.${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify(patch),
  });
  const rows = await res.json().catch(() => []);
  return Array.isArray(rows) && rows[0] ? rowToChatMessage(rows[0]) : null;
}

async function markMessagesReadInD1(senderId: 'person_1' | 'person_2', messageIds?: string[]) {
  const safeIds = Array.isArray(messageIds)
    ? messageIds.filter((id) => /^[A-Za-z0-9._:-]{1,160}$/.test(String(id))).slice(0, 200)
    : [];
  const idFilter = safeIds.length
    ? `&id=in.(${safeIds.map((id) => encodeURIComponent(String(id))).join(',')})`
    : '';
  const res = await databaseFetch(
    `/rest/v1/${D1_MESSAGES_TABLE}?sender_id=eq.${senderId}&status=neq.read${idFilter}`,
    {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({ status: 'read' }),
    },
  );
  const rows = await res.json().catch(() => []);
  return Array.isArray(rows) ? rows.length : 0;
}

async function clearMessagesInD1(seedMessages: any[]) {
  // Admin clear/seed operations target the canonical table only. Capture old
  // media references before deleting rows so R2 does not accumulate orphaned files.
  const previousMessages = await loadMessagesFromD1();
  await clearPendingMessagesFromRealtime();
  await databaseFetch(`/rest/v1/${D1_MESSAGES_TABLE}?id=not.is.null`, {
    method: 'DELETE',
    headers: { Prefer: 'return=minimal' },
  });
  if (seedMessages.length) {
    await databaseFetch(`/rest/v1/${D1_MESSAGES_TABLE}?on_conflict=id`, {
      method: 'POST',
      headers: { Prefer: 'resolution=ignore-duplicates,return=minimal' },
      body: JSON.stringify(seedMessages.map((message) => chatMessageToRow(message))),
    });
  }
  const retainedKeys = new Set(seedMessages.map((message) => getPrivateR2ObjectKey(message.fileUrl || message.file_url)).filter(Boolean) as string[]);
  await deletePrivateR2MediaBatch(previousMessages.map((message) => message.fileUrl), retainedKeys);
}

type UserUsageRow = {
  user_id: 'person_1' | 'person_2';
  continuous_used_seconds: number;
  daily_used_seconds: number;
  daily_usage_date?: string | null;
  active: boolean;
  active_started_at?: number | null;
  last_heartbeat: number;
  last_seen: number;
  updated_at?: string | null;
  usage_version: number;

};

function normalizePresenceTimestamp(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value <= 0) return 0;
    return value < 100_000_000_000 ? Math.round(value * 1000) : Math.round(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return 0;
    if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
      const numeric = Number(trimmed);
      if (!Number.isFinite(numeric) || numeric <= 0) return 0;
      return numeric < 100_000_000_000 ? Math.round(numeric * 1000) : Math.round(numeric);
    }
    const parsed = Date.parse(trimmed);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  }
  return 0;
}

function isRecentlyHeartbeating(lastHeartbeat: unknown, now = Date.now()): boolean {
  const timestamp = normalizePresenceTimestamp(lastHeartbeat);
  return timestamp > 0 && now - timestamp <= 15_000;
}

function makeDefaultUsageRow(userId: 'person_1' | 'person_2'): UserUsageRow {
  return {
    user_id: userId,
    continuous_used_seconds: 0,
    daily_used_seconds: 0,
    daily_usage_date: getIndiaDateKey(),
    active: false,
    active_started_at: null,
    last_heartbeat: 0,
    last_seen: 0,
    updated_at: null,
    usage_version: 0,
  };
}

function usageFromLegacyUser(userId: 'person_1' | 'person_2'): UserUsageRow {
  const user = db.users[userId] as any;
  return {
    user_id: userId,
    continuous_used_seconds: Number(user.activeUsageSeconds || user.dailyUsageSeconds || 0),
    daily_used_seconds: Number(user.dailyUsageSeconds || 0),
    daily_usage_date: user.dailyUsageDate || getIndiaDateKey(),
    active: false,
    active_started_at: null,
    last_heartbeat: normalizePresenceTimestamp(user.lastActiveTimestamp),
    last_seen: normalizePresenceTimestamp(user.lastActiveTimestamp),
    updated_at: null,
    usage_version: 0,
  };
}

function mirrorUsageToLegacyUser(row: UserUsageRow) {
  const user = db.users[row.user_id] as any;
  user.activeUsageSeconds = Number(row.continuous_used_seconds || 0);
  user.dailyUsageSeconds = Number(row.daily_used_seconds || 0);
  user.dailyUsageDate = row.daily_usage_date || getIndiaDateKey();
  user.lastActiveTimestamp = Number(row.last_seen || 0) || undefined;
  user.activeSessionStartedAt = row.active_started_at || undefined;
}

async function loadUsageRow(userId: 'person_1' | 'person_2'): Promise<UserUsageRow> {
  if (usageTableAvailable === false) return usageFromLegacyUser(userId);
  try {
    const res = await databaseFetch(
      `/rest/v1/${D1_USER_USAGE_TABLE}?user_id=eq.${userId}&select=user_id,continuous_used_seconds,daily_used_seconds,daily_usage_date,active,active_started_at,last_heartbeat,last_seen,updated_at,usage_version&limit=1`
    );
    const rows = await res.json() as any[];
    usageTableAvailable = true;
    const row = rows[0];
    if (!row) {
      const created = makeDefaultUsageRow(userId);
      await saveUsageRow(created);
      return created;
    }
    return {
      user_id: userId,
      continuous_used_seconds: Number(row.continuous_used_seconds || 0),
      daily_used_seconds: Number(row.daily_used_seconds || 0),
      daily_usage_date: row.daily_usage_date || null,
      active: Boolean(row.active),
      active_started_at: row.active_started_at == null ? null : Number(row.active_started_at),
      last_heartbeat: normalizePresenceTimestamp(row.last_heartbeat),
      last_seen: normalizePresenceTimestamp(row.last_seen),
      updated_at: typeof row.updated_at === 'string' ? row.updated_at : null,
      usage_version: Number(row.usage_version || 0),
    };
  } catch (error) {
    if (isMissingDataApiTableError(error)) {
      usageTableAvailable = false;
      return usageFromLegacyUser(userId);
    }
    throw error;
  }
}

async function loadAllUsageRows(): Promise<Record<'person_1' | 'person_2', UserUsageRow>> {
  if (usageTableAvailable === false) {
    return {
      person_1: usageFromLegacyUser('person_1'),
      person_2: usageFromLegacyUser('person_2'),
    };
  }
  try {
    const res = await databaseFetch(
      `/rest/v1/${D1_USER_USAGE_TABLE}?select=user_id,continuous_used_seconds,daily_used_seconds,daily_usage_date,active,active_started_at,last_heartbeat,last_seen,updated_at,usage_version`
    );
    const rows = await res.json() as any[];
    usageTableAvailable = true;
    const result = {
      person_1: makeDefaultUsageRow('person_1'),
      person_2: makeDefaultUsageRow('person_2'),
    };
    for (const row of rows) {
      if (row.user_id === 'person_1' || row.user_id === 'person_2') {
        result[row.user_id] = {
          user_id: row.user_id,
          continuous_used_seconds: Number(row.continuous_used_seconds || 0),
          daily_used_seconds: Number(row.daily_used_seconds || 0),
          daily_usage_date: row.daily_usage_date || null,
          active: Boolean(row.active),
          active_started_at: row.active_started_at == null ? null : Number(row.active_started_at),
          last_heartbeat: normalizePresenceTimestamp(row.last_heartbeat),
          last_seen: normalizePresenceTimestamp(row.last_seen),
          updated_at: typeof row.updated_at === 'string' ? row.updated_at : null,
          usage_version: Number(row.usage_version || 0),
        };
      }
    }
    for (const userId of ['person_1', 'person_2'] as const) {
      if (!rows.some((row) => row.user_id === userId)) await saveUsageRow(result[userId]);
    }
    return result;
  } catch (error) {
    if (isMissingDataApiTableError(error)) {
      usageTableAvailable = false;
      return {
        person_1: usageFromLegacyUser('person_1'),
        person_2: usageFromLegacyUser('person_2'),
      };
    }
    throw error;
  }
}

async function checkpointUsageAtomically(
  userId: 'person_1' | 'person_2',
  active: boolean,
  now = Date.now(),
): Promise<UserUsageRow | null> {
  if (usageCheckpointRpcAvailable === false) return null;

  try {
    const res = await databaseFetch('/rest/v1/rpc/synax_checkpoint_usage', {
      method: 'POST',
      body: JSON.stringify({
        p_user_id: userId,
        p_now_ms: now,
        p_active: active,
        p_today: getIndiaDateKey(now),
        p_grace_ms: 15000,
      }),
    });
    const payload = await res.json();
    const row = Array.isArray(payload) ? payload[0] : payload;
    if (!row) throw new Error('SYNAX timer RPC returned no usage row.');
    usageCheckpointRpcAvailable = true;
    return {
      user_id: userId,
      continuous_used_seconds: Number(row.continuous_used_seconds || 0),
      daily_used_seconds: Number(row.daily_used_seconds || 0),
      daily_usage_date: row.daily_usage_date || null,
      active: Boolean(row.active),
      active_started_at: row.active_started_at == null ? null : Number(row.active_started_at),
      last_heartbeat: normalizePresenceTimestamp(row.last_heartbeat),
      last_seen: normalizePresenceTimestamp(row.last_seen),
      updated_at: typeof row.updated_at === 'string' ? row.updated_at : null,
      usage_version: Number(row.usage_version || 0),
    };
  } catch (error) {
    const message = String(error instanceof Error ? error.message : error || '');
    if (/PGRST202|PGRST204|42883|function .*synax_checkpoint_usage.*does not exist|schema cache/i.test(message)) {
      usageCheckpointRpcAvailable = false;
      return null;
    }
    throw error;
  }
}

async function saveUsageRow(row: UserUsageRow) {
  mirrorUsageToLegacyUser(row);
  if (usageTableAvailable === false) {
    await saveDbSync();
    return;
  }
  try {
    await databaseFetch(`/rest/v1/${D1_USER_USAGE_TABLE}?on_conflict=user_id`, {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ ...row, updated_at: new Date().toISOString(), usage_version: Number(row.usage_version || 0) }),
    });
    usageTableAvailable = true;
  } catch (error) {
    if (isMissingDataApiTableError(error)) {
      usageTableAvailable = false;
      await saveDbSync();
      return;
    }
    throw error;
  }
}

// SYNAX uses India time for daily resets and display timestamps.
function getIndiaDateKey(timestamp = Date.now()): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date(timestamp));
}

function getIndiaDayStart(timestamp = Date.now()): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(new Date(timestamp));
  const values: Record<string, string> = {};
  for (const part of parts) values[part.type] = part.value;
  return Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day)) - (5.5 * 60 * 60 * 1000);
}

function activeElapsedSeconds(row: UserUsageRow, now: number): number {
  if (!row.active || !row.active_started_at) return 0;
  const lastHeartbeat = row.last_heartbeat || row.active_started_at;
  const effectiveEnd = Math.min(now, lastHeartbeat + 8000);
  return Math.max(0, Math.floor((effectiveEnd - row.active_started_at) / 1000));
}

/**
 * Daily-reset mode is the authoritative policy when the admin switch is on.
 * Keep timeStrategy for backward compatibility with older saved settings.
 */
function isDailyResetEnabled(): boolean {
  return db.settings.dailyResetAtMidnight === true || db.settings.timeStrategy === 'daily';
}

function normalizeTimeSettings() {
  // SYNAX uses one fixed policy: each configured allowance is a daily allowance
  // and is restored only by the scheduled 12:00 AM Asia/Kolkata reset.
  // Normal requests, refreshes, reconnects and heartbeats never reset usage.
  db.settings.dailyResetAtMidnight = true;
  db.settings.timeStrategy = 'daily';
}

function computeTimeStatusFromUsage(userId: 'person_1' | 'person_2', usage: UserUsageRow, now = Date.now()) {
  const user = db.users[userId] as any;
  const allowedMinutes = Number(user.allowedMinutes ?? 60);
  const hasLimit = allowedMinutes > 0;
  const allowedSeconds = hasLimit ? allowedMinutes * 60 : 86400;
  const strategy = isDailyResetEnabled() ? 'daily' : (db.settings.timeStrategy || 'continuous');
  let usedSeconds = 0;
  if (strategy === 'continuous') {
    usedSeconds = Number(usage.continuous_used_seconds || 0) + activeElapsedSeconds(usage, now);
  } else {
    // The request path never resets based on the calendar date. The scheduled
    // midnight job is the sole automatic reset authority.
    usedSeconds = Number(usage.daily_used_seconds || 0);
    if (usage.active && usage.active_started_at) {
      const lastHeartbeat = usage.last_heartbeat || usage.active_started_at;
      const effectiveEnd = Math.min(now, lastHeartbeat + 15000);
      usedSeconds += Math.max(0, Math.floor((effectiveEnd - Number(usage.active_started_at)) / 1000));
    }
  }
  const remainingSeconds = Math.max(0, allowedSeconds - usedSeconds);
  return {
    hasLimit,
    mode: strategy,
    allowedSeconds,
    remainingSeconds,
    isExpired: hasLimit && remainingSeconds <= 0,
    customMessage: db.settings.timeOverMessage,
    serverTimestamp: now,
    dailyUsageDate: usage.daily_usage_date || null,
    usageUpdatedAt: usage.updated_at || null,
    usageVersion: Number(usage.usage_version || 0),
    warnings: (db.settings.warningMinutes || [10, 5, 1]).map((m) => Number(m) * 60),
  };
}

async function getPersistentTimeRemaining(userId: 'person_1' | 'person_2') {
  const usage = await loadUsageRow(userId);
  return computeTimeStatusFromUsage(userId, usage);
}

async function setPersistentChatPresence(userId: 'person_1' | 'person_2', active: boolean) {
  const now = Date.now();

  // Atomically checkpoint the usage row in D1. This prevents one
  // Cloudflare isolate/reconnect from overwriting a newer timer state.
  const atomic = await checkpointUsageAtomically(userId, active, now);
  if (atomic) return computeTimeStatusFromUsage(userId, atomic, now);

  // The SYNAX timer is authoritative in D1. Never fall back to the old
  // in-memory usage model because a stale Worker isolate can resurrect time.
  if (usageCheckpointRpcAvailable === false) {
    throw new Error('SYNAX D1 schema is not installed. Apply migrations/0001_initial.sql.');
  }
  const usage = await loadUsageRow(userId);
  const wasActive = Boolean(usage.active);

  if (active) {
    if (!usage.active || !usage.active_started_at) usage.active_started_at = now;
    usage.active = true;
    usage.last_heartbeat = now;
  } else {
    const elapsed = activeElapsedSeconds(usage, now);
    if (wasActive && elapsed > 0 && usage.active_started_at) {
      usage.daily_used_seconds = Number(usage.daily_used_seconds || 0) + elapsed;
    }
    usage.active = false;
    usage.active_started_at = null;
    usage.last_heartbeat = now;
    if (wasActive) usage.last_seen = now;
  }

  await saveUsageRow(usage);
  return computeTimeStatusFromUsage(userId, usage, now);
}

async function getPersistentPresenceState(userId: 'person_1' | 'person_2') {
  const usage = await loadUsageRow(userId);
  const now = Date.now();
  const lastHeartbeat = normalizePresenceTimestamp(usage.last_heartbeat);
  const lastSeen = normalizePresenceTimestamp(usage.last_seen);
  const isOnline = Boolean(usage.active && isRecentlyHeartbeating(lastHeartbeat, now));
  return { active: isOnline, lastHeartbeat, lastSeen };
}

async function getPersistentPresenceSummary() {
  const rows = await loadAllUsageRows();
  const now = Date.now();
  const result: { person_1: boolean; person_2: boolean; lastSeen_1: number; lastSeen_2: number } = {
    person_1: false, person_2: false, lastSeen_1: 0, lastSeen_2: 0,
  };
  for (const userId of ['person_1', 'person_2'] as const) {
    const row = rows[userId];
    const online = Boolean(row.active && row.last_heartbeat && now - row.last_heartbeat <= 12000);
    result[userId] = online;
    result[userId === 'person_1' ? 'lastSeen_1' : 'lastSeen_2'] = Number(row.last_seen || 0);
  }
  return result;
}

async function resetPersistentUsage(userId: 'person_1' | 'person_2', now = Date.now()) {
  const usage = await loadUsageRow(userId);
  usage.continuous_used_seconds = 0;
  usage.daily_used_seconds = 0;
  usage.daily_usage_date = getIndiaDateKey(now);
  usage.last_seen = usage.last_seen || now;
  usage.last_heartbeat = usage.active ? now : usage.last_heartbeat;
  usage.active_started_at = usage.active ? now : null;
  await saveUsageRow(usage);
  return computeTimeStatusFromUsage(userId, usage, now);
}

/**
 * Abort abandoned multipart uploads so interrupted phone uploads do not keep
 * incomplete parts around forever. Only the user's private SYNAX bucket is used.
 */
export async function cleanupAbandonedR2Uploads(now = Date.now()): Promise<number> {
  if (!cloudflareEnv?.SYNAX_DB || !cloudflareEnv?.SYNAX_MEDIA) return 0;
  const cutoff = now - 48 * 60 * 60 * 1000;
  const stale = await cloudflareEnv.SYNAX_DB.prepare(
    'SELECT upload_id, object_key, r2_upload_id FROM synax_uploads WHERE completed = 0 AND created_at < ? ORDER BY created_at ASC LIMIT 100'
  ).bind(cutoff).all();
  let removed = 0;
  for (const row of stale.results || []) {
    try {
      await cloudflareEnv.SYNAX_MEDIA.resumeMultipartUpload(String(row.object_key), String(row.r2_upload_id)).abort();
    } catch (error) {
      // R2 may already have expired an upload. Its D1 manifest can still be removed.
      console.warn('SYNAX stale R2 multipart abort skipped:', error);
    }
    await cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_upload_parts WHERE upload_id = ?').bind(String(row.upload_id)).run();
    await cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_uploads WHERE upload_id = ? AND completed = 0').bind(String(row.upload_id)).run();
    removed += 1;
  }
  return removed;
}

/**
 * Reset both users' daily allowance at the India-local midnight boundary.
 * This is intentionally persisted in synax_user_usage so it works across
 * Cloudflare Worker isolates and survives refresh/reconnects.
 */
/** Remove short-lived operational rows so call signalling and login-throttle
 * bookkeeping cannot grow forever in the small D1 free database. */
export async function cleanupExpiredOperationalRows(now = Date.now()): Promise<{ callSignals: number; loginAttempts: number }> {
  const callSignalCutoff = new Date(now - 24 * 60 * 60 * 1000).toISOString();
  const loginAttemptCutoff = now - 24 * 60 * 60 * 1000;
  const [signals, attempts] = await Promise.all([
    cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_call_signals WHERE created_at < ?').bind(callSignalCutoff).run(),
    cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_login_attempts WHERE updated_at < ?').bind(loginAttemptCutoff).run(),
  ]);
  return {
    callSignals: Number(signals.meta?.changes || 0),
    loginAttempts: Number(attempts.meta?.changes || 0),
  };
}

export async function runDailyUsageReset(scheduledTime = Date.now()): Promise<{ reset: boolean; date: string }> {
  if (!db) {
    await initializeDatabase();
  } else {
    await refreshDbFromD1(true);
  }

  normalizeTimeSettings();
  const resetDate = getIndiaDateKey(scheduledTime);

  try {
    const res = await databaseFetch('/rest/v1/rpc/synax_reset_daily_usage', {
      method: 'POST',
      body: JSON.stringify({
        p_reset_date: resetDate,
        p_reset_at_ms: scheduledTime,
      }),
    });
    const payload = await res.json();
    const rows = Array.isArray(payload) ? payload : [];

    for (const row of rows) {
      if (row?.user_id !== 'person_1' && row?.user_id !== 'person_2') continue;
      const userId = row.user_id as 'person_1' | 'person_2';
      const usage: UserUsageRow = {
        user_id: userId,
        continuous_used_seconds: Number(row.continuous_used_seconds || 0),
        daily_used_seconds: Number(row.daily_used_seconds || 0),
        daily_usage_date: row.daily_usage_date || resetDate,
        active: Boolean(row.active),
        active_started_at: row.active_started_at == null ? null : Number(row.active_started_at),
        last_heartbeat: normalizePresenceTimestamp(row.last_heartbeat),
        last_seen: normalizePresenceTimestamp(row.last_seen),
        updated_at: typeof row.updated_at === 'string' ? row.updated_at : null,
        usage_version: Number(row.usage_version || 0),
      };
      const timeStatus = computeTimeStatusFromUsage(userId, usage, Date.now());
      broadcast({ type: 'time:tick', userId, timeStatus });
    }

    usageCheckpointRpcAvailable = true;
    console.log(`✦ SYNAX daily usage reset completed for ${resetDate}`);
    return { reset: true, date: resetDate };
  } catch (error) {
    const message = String(error instanceof Error ? error.message : error || '');
    if (!/PGRST202|PGRST204|42883|function .*synax_reset_daily_usage.*does not exist|schema cache/i.test(message)) {
      throw error;
    }

    throw new Error('SYNAX D1 schema is not installed. Apply migrations/0001_initial.sql.');
    /* const rows = await loadAllUsageRows();
    for (const userId of ['person_1', 'person_2'] as const) {
      const usage = rows[userId];
      if (usage.daily_usage_date === resetDate) continue;

      const heartbeat = normalizePresenceTimestamp(usage.last_heartbeat);
      const activeAtReset = Boolean(
        usage.active &&
        heartbeat > 0 &&
        heartbeat <= Date.now() + 15_000 &&
        heartbeat >= scheduledTime - 15_000
      );

      usage.daily_usage_date = resetDate;
      usage.daily_used_seconds = 0;
      if (activeAtReset) {
        usage.active = true;
        usage.active_started_at = scheduledTime;
      } else if (usage.active) {
        usage.active = false;
        usage.active_started_at = null;
        usage.last_seen = heartbeat || usage.last_seen || scheduledTime;
      }

      await saveUsageRow(usage);
      const timeStatus = computeTimeStatusFromUsage(userId, usage, Date.now());
      broadcast({ type: 'time:tick', userId, timeStatus });
    }

    console.log(`✦ SYNAX daily usage reset completed for ${resetDate} (fallback)`);
    return { reset: true, date: resetDate }; */
  }
}

async function getSessionFromD1(token: string): Promise<DbSchema['sessions'][string] | null> {
  if (!useD1 || sessionsTableAvailable === false) {
    await refreshDbFromD1(true);
    return db.sessions[token] || null;
  }
  const now = Date.now();
  const cached = sessionCache.get(token);
  if (cached && cached.expiresAt > now) return cached.session;

  try {
    const res = await databaseFetch(
      `/rest/v1/${D1_SESSIONS_TABLE}?token=eq.${encodeURIComponent(token)}&select=token,user_id,session_start,last_active,allowed_seconds,is_expired,active,ended_at&limit=1`
    );
    const rows = await res.json() as any[];
    sessionsTableAvailable = true;
    const row = rows[0];
    if (!row) {
      sessionCache.delete(token);
      return null;
    }
    const session = {
      token: row.token,
      userId: row.user_id,
      sessionStart: Number(row.session_start),
      lastActive: Number(row.last_active),
      allowedSeconds: Number(row.allowed_seconds),
      isExpired: Boolean(row.is_expired),
      active: Boolean(row.active),
      ...(row.ended_at == null ? {} : { endedAt: Number(row.ended_at) }),
    } as DbSchema['sessions'][string];
    sessionCache.set(token, { session, expiresAt: now + SESSION_CACHE_TTL_MS });
    return session;
  } catch (error) {
    if (!isMissingDataApiTableError(error)) throw error;
    sessionsTableAvailable = false;
    await refreshDbFromD1(true);
    return db.sessions[token] || null;
  }
}

async function saveSessionToD1(session: DbSchema['sessions'][string]) {
  sessionCache.set(session.token, { session, expiresAt: Date.now() + SESSION_CACHE_TTL_MS });
  db.sessions[session.token] = session;
  if (!useD1 || sessionsTableAvailable === false) {
    await saveDbSync();
    return;
  }
  try {
    await databaseFetch(`/rest/v1/${D1_SESSIONS_TABLE}?on_conflict=token`, {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({
        token: session.token,
        user_id: session.userId,
        session_start: session.sessionStart,
        last_active: session.lastActive,
        allowed_seconds: session.allowedSeconds,
        is_expired: session.isExpired,
        active: Boolean(session.active),
        ended_at: session.endedAt ?? null,
      }),
    });
    sessionsTableAvailable = true;
  } catch (error) {
    if (!isMissingDataApiTableError(error)) throw error;
    sessionsTableAvailable = false;
    await saveDbSync();
  }
}

async function deleteSessionFromD1(token: string) {
  sessionCache.delete(token);
  delete db.sessions[token];
  if (!useD1 || sessionsTableAvailable === false) {
    await saveDbSync();
    return;
  }
  try {
    await databaseFetch(`/rest/v1/${D1_SESSIONS_TABLE}?token=eq.${encodeURIComponent(token)}`, { method: 'DELETE' });
    sessionsTableAvailable = true;
  } catch (error) {
    if (!isMissingDataApiTableError(error)) throw error;
    sessionsTableAvailable = false;
    await saveDbSync();
  }
}

async function listSessionsFromD1() {
  if (!useD1 || sessionsTableAvailable === false) {
    await refreshDbFromD1(true);
    return Object.values(db.sessions);
  }
  try {
    const res = await databaseFetch(
      `/rest/v1/${D1_SESSIONS_TABLE}?select=token,user_id,session_start,last_active,allowed_seconds,is_expired,active,ended_at&order=session_start.desc`
    );
    sessionsTableAvailable = true;
    const rows = await res.json() as any[];
    return rows.map((row) => ({
      token: row.token,
      userId: row.user_id,
      sessionStart: Number(row.session_start),
      lastActive: Number(row.last_active),
      allowedSeconds: Number(row.allowed_seconds),
      isExpired: Boolean(row.is_expired),
      active: Boolean(row.active),
      ...(row.ended_at == null ? {} : { endedAt: Number(row.ended_at) }),
    }));
  } catch (error) {
    if (!isMissingDataApiTableError(error)) throw error;
    sessionsTableAvailable = false;
    await refreshDbFromD1(true);
    return Object.values(db.sessions);
  }
}

async function ensureD1StateRow(seed: DbSchema) {
  // INSERT OR IGNORE makes first-run initialization safe if two requests race
  // on separate Worker isolates. The winner's credentials/state remain canonical.
  const database = cloudflareEnv?.SYNAX_DB;
  if (!database) throw new Error('Cloudflare D1 binding SYNAX_DB is missing.');
  await database.prepare(
    'INSERT OR IGNORE INTO synax_state (id, state, updated_at) VALUES (?, ?, ?)'
  ).bind(D1_STATE_ID, JSON.stringify(seed), new Date().toISOString()).run();
  const current = await loadDbFromD1();
  if (!current) throw new Error('Unable to initialize the SYNAX D1 state row.');
  return current;
}

async function ensureStorageBucket() {
  // R2 buckets are created once through Wrangler/Dashboard and injected as a binding.
  if (!cloudflareEnv?.SYNAX_MEDIA) {
    throw new Error('Cloudflare R2 binding SYNAX_MEDIA is missing. Configure it in wrangler.jsonc.');
  }
}

async function initializeDatabase() {
  if (!cloudflareEnv?.SYNAX_DB) {
    throw new Error('SYNAX Cloudflare requires the SYNAX_DB D1 binding. Apply migrations/0001_initial.sql and configure wrangler.jsonc.');
  }
  if (!cloudflareEnv?.SYNAX_MEDIA) {
    throw new Error('SYNAX Cloudflare requires the SYNAX_MEDIA R2 binding.');
  }
  if (!cloudflareEnv?.SYNAX_MEDIA_SIGNING_SECRET || String(cloudflareEnv.SYNAX_MEDIA_SIGNING_SECRET).length < 32) {
    throw new Error('Set SYNAX_MEDIA_SIGNING_SECRET as a Worker secret with at least 32 characters.');
  }

  // Avoid hashing all three initial passwords on every Worker cold start.
  // Only create the initial state when this brand-new D1 database is empty.
  const existingState = await loadDbFromD1();
  if (existingState) {
    db = existingState;
  } else {
    const seed = await getInitialDb();
    db = await ensureD1StateRow(cloneDb(seed));
  }
  normalizeTimeSettings();

  // Do not load or seed the entire chat history during Worker startup.
  // Chat history is fetched asynchronously by the chat screen, which keeps
  // first paint/login fast and avoids a heavy D1 round-trip on every isolate.
  db.messages = Array.isArray(db.messages) ? db.messages : [];

  for (const id of ['person_1', 'person_2'] as const) {
    const user = db.users[id] as any;
    user.activeUsageSeconds ??= 0;
    user.activeSessionCount = 0;
    user.activeSessionStartedAt = undefined;
    user.sessionStartTimestamp = undefined;
  }

  // R2 bucket is provisioned outside the Worker and accessed only through its binding.
  await ensureStorageBucket();

  // Sessions are already persisted when they are created or updated. Rewriting
  // every session sequentially on every new Cloudflare isolate adds cold-start
  // latency and unnecessary D1 traffic, so startup only resets the
  // in-memory active flag.
  for (const session of Object.values(db.sessions) as any[]) session.active = false;
  lastRemoteSync = Date.now();
  console.log('✦ SYNAX Cloudflare persistence: D1 + R2');
}

async function refreshDbFromD1(force = false) {
  if (!useD1 || !db) return;
  const now = Date.now();
  if (!force && now - lastRemoteSync < STATE_REFRESH_TTL_MS) return;
  if (stateRefreshInFlight) return stateRefreshInFlight;

  stateRefreshInFlight = (async () => {
    try {
      const remote = await loadDbFromD1();
      if (remote) {
        db = remote;
        const beforeDailyReset = (db.settings as any)?.dailyResetAtMidnight;
        const beforeStrategy = db.settings.timeStrategy;
        normalizeTimeSettings();
        if (beforeDailyReset !== (db.settings as any)?.dailyResetAtMidnight || beforeStrategy !== db.settings.timeStrategy) {
          void saveDbSync();
        }
        lastRemoteSync = Date.now();
      }
    } catch (err) {
      // Keep the last known good state for transient D1 failures.
      console.error('Failed to refresh SYNAX state from D1:', err);
    } finally {
      stateRefreshInFlight = null;
    }
  })();
  return stateRefreshInFlight;
}

function saveDbSync(): Promise<void> {
  const snapshot = cloneDb(db);
  // Keep the queue usable after one failed write while retaining the error so
  // callers that promise persistence can avoid returning a false success.
  const writeAttempt = persistenceQueue
    .catch(() => undefined)
    .then(() => persistToD1(snapshot));

  persistenceQueue = writeAttempt.then(
    () => { lastPersistenceError = null; },
    (err) => {
      lastPersistenceError = err;
      console.error('Failed to persist SYNAX state to D1:', err);
    },
  );

  // Cloudflare may finish the HTTP response before a detached promise finishes.
  cloudflareExecutionContext?.waitUntil?.(persistenceQueue);
  return persistenceQueue;
}

async function flushPersistence() {
  await persistenceQueue;
  if (lastPersistenceError) {
    const detail = lastPersistenceError instanceof Error
      ? lastPersistenceError.message
      : String(lastPersistenceError);
    throw new Error(`SYNAX data persistence failed: ${detail.slice(0, 600)}`);
  }
}

function addLog(actor: string, action: string, details?: string, level: 'info' | 'warn' | 'alert' = 'info') {
  const log = {
    id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: Date.now(),
    actor,
    action,
    details,
    level,
  };
  db.logs.unshift(log);
  if (db.logs.length > 300) db.logs = db.logs.slice(0, 300);
  void saveDbSync();
}

// Call signaling is persisted in D1 so separate Cloudflare Worker
// invocations can exchange offers/answers/ICE candidates safely.
type CallSignalRow = {
  id: number;
  from_user_id: 'person_1' | 'person_2';
  target_user_id: 'person_1' | 'person_2';
  type: string;
  call_type?: 'voice' | 'video';
  payload: any;
  created_at: string;
};

const localCallSignals: CallSignalRow[] = [];
let localCallSignalId = 1;
const CALL_SIGNAL_MAX_AGE_MS = 10 * 60 * 1000;

function getOppositeUserId(userId: 'person_1' | 'person_2'): 'person_1' | 'person_2' {
  return userId === 'person_1' ? 'person_2' : 'person_1';
}

async function validateCallSignal(userId: 'person_1' | 'person_2', data: any, authoritativeTimeStatus?: any): Promise<string | null> {
  if (!data || typeof data.type !== 'string' || !data.type.startsWith('call:')) {
    return 'Invalid call signal.';
  }

  if (typeof data.callId !== 'string' || data.callId.length < 8 || data.callId.length > 128) {
    return 'Invalid call id.';
  }

  const callType = data.callType === 'video' ? 'video' : 'voice';
  const timeStatus = authoritativeTimeStatus || await getPersistentTimeRemaining(userId);
  if (timeStatus.isExpired) {
    if (callType === 'voice' && db.settings.restrictionsOnExpire.disableVoiceCalls) {
      return db.settings.timeOverMessage || 'Communication time has expired.';
    }
    if (callType === 'video' && db.settings.restrictionsOnExpire.disableVideoCalls) {
      return db.settings.timeOverMessage || 'Communication time has expired.';
    }
  }

  if (callType === 'voice' && !db.settings.featuresEnabled.voiceCalls) {
    return 'Voice calls are disabled by Admin.';
  }
  if (callType === 'video' && !db.settings.featuresEnabled.videoCalls) {
    return 'Video calls are disabled by Admin.';
  }
  return null;
}

async function storeCallSignal(signal: Omit<CallSignalRow, 'id' | 'created_at'>): Promise<number> {
  const createdAt = new Date().toISOString();

  if (useD1) {
    const res = await databaseFetch(`/rest/v1/${D1_CALL_SIGNALS_TABLE}`, {
      method: 'POST',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({ ...signal, created_at: createdAt }),
    });
    const rows = await res.json() as Array<{ id: number }>;
    return Number(rows[0]?.id || 0);
  }

  const row: CallSignalRow = { ...signal, id: localCallSignalId++, created_at: createdAt };
  localCallSignals.push(row);
  const cutoff = Date.now() - CALL_SIGNAL_MAX_AGE_MS;
  while (localCallSignals.length && Date.parse(localCallSignals[0].created_at) < cutoff) {
    localCallSignals.shift();
  }
  return row.id;
}

async function readCallSignals(
  targetUserId: 'person_1' | 'person_2',
  afterId: number,
  sinceIso: string,
  callId?: string
): Promise<CallSignalRow[]> {
  if (useD1) {
    const params = new URLSearchParams({
      target_user_id: `eq.${targetUserId}`,
      id: `gt.${Math.max(0, afterId)}`,
      created_at: `gte.${sinceIso}`,
      order: 'id.asc',
      limit: '100',
      select: 'id,from_user_id,target_user_id,type,call_type,payload,created_at',
    });
    if (callId) params.set('payload->>callId', `eq.${callId}`);
    const res = await databaseFetch(`/rest/v1/${D1_CALL_SIGNALS_TABLE}?${params.toString()}`);
    return await res.json() as CallSignalRow[];
  }

  const since = Date.parse(sinceIso) || 0;
  const cutoff = Date.now() - CALL_SIGNAL_MAX_AGE_MS;
  for (let i = localCallSignals.length - 1; i >= 0; i--) {
    if (Date.parse(localCallSignals[i].created_at) < cutoff) localCallSignals.splice(0, i + 1);
    else break;
  }
  return localCallSignals.filter(
    (row) => row.target_user_id === targetUserId && row.id > afterId && Date.parse(row.created_at) >= since && (!callId || row.payload?.callId === callId)
  ).slice(0, 100);
}

// Clear messages which have not reached D1 yet before an administrator clears
// canonical history. This prevents a queued offline retry from resurrecting old rows.
async function clearPendingMessagesFromRealtime(): Promise<void> {
  const binding = cloudflareEnv?.SYNAX_REALTIME_HUB;
  if (!binding) throw new Error('Cloudflare realtime Durable Object binding is unavailable.');
  const stub = binding.get(binding.idFromName('main'));
  const response = await stub.fetch(new Request('https://synax.internal/clear-pending', { method: 'POST' }));
  if (!response.ok) throw new Error('Unable to clear the pending realtime message queue.');
}

async function sendRealtimeAdminCommand(path: '/revoke-session' | '/revoke-user', payload: Record<string, string>): Promise<void> {
  const binding = cloudflareEnv?.SYNAX_REALTIME_HUB;
  if (!binding) throw new Error('Cloudflare realtime Durable Object binding is unavailable.');
  const stub = binding.get(binding.idFromName('main'));
  const response = await stub.fetch(new Request(`https://synax.internal${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  }));
  if (!response.ok) throw new Error(`Realtime ${path} command failed.`);
}

// Cloudflare realtime transport is handled by worker/realtime.ts (Durable Object).
function broadcast(payload: any, _filterFn?: any) {
  const binding = cloudflareEnv?.SYNAX_REALTIME_HUB;
  if (!binding) return;
  try {
    const id = binding.idFromName('main');
    const stub = binding.get(id);
    const request = new Request('https://synax.internal/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const promise = stub.fetch(request);
    cloudflareExecutionContext?.waitUntil?.(promise);
  } catch (err) {
    console.error('Realtime broadcast failed:', err);
  }
}

// Chat sends need an acknowledgement so the sender can immediately show
// DOUBLE TICKS when the recipient has a live authenticated WebSocket. Other
// realtime events stay fire-and-forget so they never block the API.
async function broadcastChatMessage(payload: any): Promise<{
  recipientOnline: boolean;
  delivered: boolean;
  message?: any;
  persistedToD1?: boolean;
  durability?: 'd1' | 'durable-pending-queue';
}> {
  const binding = cloudflareEnv?.SYNAX_REALTIME_HUB;
  if (!binding) {
    throw new Error('Cloudflare realtime Durable Object binding is unavailable.');
  }

  const id = binding.idFromName('main');
  const stub = binding.get(id);
  const request = new Request('https://synax.internal/broadcast', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const response = await stub.fetch(request);
  const data = await response.json().catch(() => ({})) as any;
  if (!response.ok) {
    throw new Error(String(data?.detail || data?.error || `Realtime hub returned HTTP ${response.status}`));
  }

  return {
    recipientOnline: Boolean(data?.recipientOnline),
    delivered: Boolean(data?.delivered),
    message: data?.message,
    persistedToD1: typeof data?.persistedToD1 === 'boolean' ? data.persistedToD1 : undefined,
    durability: data?.durability === 'd1' || data?.durability === 'durable-pending-queue' ? data.durability : undefined,
  };
}

async function recordCallChatEvent(params: {
  callId: string;
  eventType: 'call:offer' | 'call:answer' | 'call:reject' | 'call:end';
  callType: 'voice' | 'video';
  actorId: 'person_1' | 'person_2';
}): Promise<any | null> {
  const actor = db.users[params.actorId] as any;
  const label = params.callType === 'video' ? 'video call' : 'voice call';
  const textByEvent: Record<string, string> = {
    'call:offer': `📞 ${actor.name} started a ${label}.`,
    'call:answer': `✅ ${actor.name} joined the ${label}.`,
    'call:reject': `❌ ${actor.name} declined the ${label}.`,
    'call:end': `📞 ${actor.name} ended the ${label}.`,
  };
  const clientMessageId = `call_history_${params.callId}_${params.eventType.replace(':', '_')}`;
  const historyMessage = {
    id: `msg_call_${params.callId}_${params.eventType.replace(':', '_')}`,
    clientMessageId,
    senderId: 'system',
    type: 'system',
    text: textByEvent[params.eventType],
    timestamp: Date.now(),
    status: 'read',
    reactions: {},
  };
  const persisted = await insertMessageToD1(historyMessage, clientMessageId);
  db.messages = [...(db.messages || []).filter((m: any) => String(m.clientMessageId || '') !== clientMessageId), persisted]
    .sort((a: any, b: any) => Number(a.timestamp) - Number(b.timestamp));
  broadcast({ type: 'chat:new_message', message: persisted });
  return persisted;
}

async function loadPendingMessagesFromRealtime(timeoutMs = 4000): Promise<any[]> {
  const binding = cloudflareEnv?.SYNAX_REALTIME_HUB;
  // Local Node development has no Durable Object binding. In production the
  // binding is required, and if it exists but is unreachable we must not hide
  // that failure by claiming the pending queue is empty.
  if (!binding) return [];
  const id = binding.idFromName('main');
  const stub = binding.get(id);
  const response = await stub.fetch(new Request('https://synax.internal/pending-messages', {
    method: 'GET',
    headers: { 'Cache-Control': 'no-cache' },
    signal: AbortSignal.timeout(timeoutMs),
  }));
  if (!response.ok) {
    throw new Error(`Realtime pending-message queue returned HTTP ${response.status}.`);
  }
  const data = await response.json().catch(() => null) as any;
  if (!data || !Array.isArray(data.messages)) {
    throw new Error('Realtime pending-message queue returned an invalid response.');
  }
  return data.messages;
}

function mergePendingMessages(current: any[], pending: any[]): any[] {
  if (!pending.length) return current;
  const statusRank: Record<string, number> = { sent: 0, delivered: 1, read: 2 };
  const byKey = new Map<string, any>();
  const keyFor = (message: any) => String(message?.clientMessageId || message?.id || '');

  for (const message of current) byKey.set(keyFor(message), message);
  for (const message of pending) {
    const key = keyFor(message);
    if (!key) continue;
    const previous = byKey.get(key);
    if (!previous) {
      byKey.set(key, message);
      continue;
    }
    const previousRank = statusRank[String(previous.status)] ?? 0;
    const incomingRank = statusRank[String(message.status)] ?? 0;
    byKey.set(key, {
      // `previous` is canonical D1 history. A queued Durable Object copy
      // may have stale text/file metadata, so do not overwrite canonical fields.
      ...message,
      ...previous,
      status: incomingRank >= previousRank ? message.status : previous.status,
      clientMessageId: previous.clientMessageId || message.clientMessageId,
    });
  }

  return Array.from(byKey.values()).sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0));
}

// Middleware: Authenticate User
async function requireUserAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Missing token' });
    return;
  }
  const token = authHeader.split(' ')[1];
  let session: DbSchema['sessions'][string] | null = null;
  try {
    session = await getSessionFromD1(token);
  } catch (err) {
    console.error('Failed to validate user session:', err);
    res.status(503).json({ error: 'Authentication service temporarily unavailable' });
    return;
  }
  if (!session || (session.userId !== 'person_1' && session.userId !== 'person_2')) {
    res.status(401).json({ error: 'Invalid or expired session' });
    return;
  }
  await refreshDbFromD1();
  const userId = session.userId as 'person_1' | 'person_2';
  const user = db.users[userId];
  if (user.isLocked) {
    try {
      await setPersistentChatPresence(userId, false);
      await deleteSessionFromD1(token);
      await sendRealtimeAdminCommand('/revoke-session', { token });
    } catch (error) {
      console.error('Unable to revoke locked SYNAX session immediately:', error);
    }
    res.status(403).json({ error: 'USER_LOCKED', message: user.lockReason || 'This identity has been locked by the Administrator.' });
    return;
  }
  const timeStatus = await getPersistentTimeRemaining(userId);
  if (timeStatus.isExpired && db.settings.restrictionsOnExpire.lockSession) {
    try {
      await setPersistentChatPresence(userId, false);
      await deleteSessionFromD1(token);
      await sendRealtimeAdminCommand('/revoke-session', { token });
    } catch (error) {
      console.error('Unable to revoke expired SYNAX session immediately:', error);
    }
    res.status(403).json({ error: 'TIME_EXPIRED', message: db.settings.timeOverMessage, timeStatus });
    return;
  }
  // API requests by themselves do not make a user online.
  const now = Date.now();
  session.lastActive = now;
  (req as any).user = user;
  (req as any).session = session;
  (req as any).userId = userId;
  (req as any).timeStatus = timeStatus;
  next();
}

// Middleware: Authenticate Admin
async function requireAdminAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Admin unauthorized' });
    return;
  }
  const token = authHeader.split(' ')[1];
  let session: DbSchema['sessions'][string] | null = null;
  try {
    session = await getSessionFromD1(token);
  } catch (err) {
    console.error('Failed to validate admin session:', err);
    res.status(503).json({ error: 'Authentication service temporarily unavailable' });
    return;
  }
  if (!session || session.userId !== 'admin') {
    res.status(401).json({ error: 'Invalid admin credentials' });
    return;
  }
  await refreshDbFromD1();
  (req as any).session = session;
  next();
}

export async function createCloudflareHttpServer() {
  await initializeDatabase();
  const app = express();

  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Synax-File-Name, X-Synax-Content-Type, X-Synax-Upload-ID, X-Synax-Object-Name, Upload-Offset, Range');
    res.header('Access-Control-Expose-Headers', 'X-Synax-Server-Time, Upload-Offset, Content-Range, Accept-Ranges, ETag');
    res.header('X-Synax-Server-Time', String(Date.now()));
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
      return;
    }
    next();
  });

  app.post('/api/chat/background/upload', requireUserAuth, express.raw({ type: '*/*', limit: '10mb' }), async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    // Cloudflare's Node compatibility bridge can surface raw bodies as either
    // Buffer or Uint8Array. Normalize both forms instead of requiring
    // Buffer.isBuffer(), which could incorrectly report an empty upload.
    const rawBody = req.body as unknown;
    const buffer = rawBody instanceof Uint8Array
      ? Buffer.from(rawBody)
      : Buffer.isBuffer(rawBody)
        ? rawBody
        : null;
    const mimeType = String(req.headers['x-synax-content-type'] || req.headers['content-type'] || 'application/octet-stream').split(';')[0].trim().toLowerCase();
    let originalName = String(req.headers['x-synax-file-name'] || 'chat-background').trim();
    try { originalName = decodeURIComponent(originalName); } catch {}

    if (!buffer || buffer.length === 0) {
      res.status(400).json({ error: 'No background image selected.' });
      return;
    }
    if (!mimeType.startsWith('image/')) {
      res.status(400).json({ error: 'Only image files can be used as a chat background.' });
      return;
    }
    if (buffer.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: 'Chat background images must be 10 MB or smaller.' });
      return;
    }

    try {
      const match = originalName.match(/(\.[^.]+)$/);
      const mimeExt: Record<string, string> = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/webp': '.webp',
        'image/gif': '.gif',
        'image/avif': '.avif',
        'image/svg+xml': '.svg',
      };
      const ext = (match?.[1] || mimeExt[mimeType] || '.img').toLowerCase().replace(/[^a-z0-9.]/g, '');
      const objectName = `chat-backgrounds/${SYNAX_CHAT_ID}/${Date.now()}-${crypto.randomUUID()}${ext}`;
      await cloudflareEnv.SYNAX_MEDIA.put(objectName, new Uint8Array(buffer), {
        httpMetadata: {
          contentType: mimeType,
          cacheControl: 'private, max-age=31536000, immutable',
          contentDisposition: safeMediaContentDisposition(mimeType, originalName),
        },
        customMetadata: { owner: userId, purpose: 'chat-background' },
      });

      const previousBackground = await loadChatBackground();
      const backgroundUrl = await createSignedMediaUrl(objectName);
      const background: ChatBackgroundRecord = {
        chat_id: SYNAX_CHAT_ID,
        background_type: 'image',
        background_value: backgroundUrl,
        background_updated_at: Date.now(),
        updated_by: userId,
      };
      await saveChatBackground(background);
      if (previousBackground.background_type === 'image' && previousBackground.background_value !== background.background_value) {
        await deletePrivateR2Media(previousBackground.background_value);
      }

      broadcast({
        type: 'chat:background_updated',
        chatId: SYNAX_CHAT_ID,
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });

      res.setHeader('Cache-Control', 'no-store');
      res.json({
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });
    } catch (err: any) {
      const detail = err instanceof Error ? err.message : String(err || 'Unknown upload error');
      console.error('Failed to upload shared chat background:', detail);
      res.status(500).json({
        error: 'Chat background upload failed.',
        detail: detail.slice(0, 1200),
      });
    }
  });


  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Return short-lived WebRTC ICE credentials. A TURN relay is strongly preferred
  // for mobile carrier NATs, restrictive Wi-Fi, and symmetric NATs. The long-lived
  // Cloudflare TURN key never leaves the Worker. If TURN is not configured, SYNAX
  // still returns public STUN servers so same-network calls continue to work.
  app.get('/api/call/ice-servers', requireUserAuth, async (_req: Request, res: Response) => {
    const keyId = getConfiguredTurnKeyId();
    const apiToken = getConfiguredTurnApiToken();
    if (!keyId || !apiToken) {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ iceServers: FALLBACK_ICE_SERVERS, turnConfigured: false, expiresAt: Date.now() + 300_000 });
      return;
    }

    try {
      const response = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ttl: 86400 }),
        },
      );
      const data = await response.json().catch(() => ({} as any));
      if (!response.ok || !Array.isArray(data?.iceServers) || data.iceServers.length === 0) {
        throw new Error(`Cloudflare TURN credential request failed (HTTP ${response.status}).`);
      }
      res.setHeader('Cache-Control', 'private, no-store, max-age=0');
      res.json({ iceServers: data.iceServers, turnConfigured: true, expiresAt: Date.now() + 86400_000 });
    } catch (err) {
      console.error('SYNAX TURN credential generation failed:', err);
      res.setHeader('Cache-Control', 'no-store');
      // Graceful fallback keeps calls functional on networks where direct ICE works.
      res.json({
        iceServers: FALLBACK_ICE_SERVERS,
        turnConfigured: false,
        expiresAt: Date.now() + 300_000,
      });
    }
  });

  // Shared HTTP signaling fallback for WebRTC. This is the authoritative call
  // signaling path in production; it avoids process-local WebSocket fan-out.
  app.post('/api/call/signal', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    if (userId !== 'person_1' && userId !== 'person_2') {
      res.status(403).json({ error: 'Only user identities can place calls.' });
      return;
    }

    const data = req.body || {};
    const validationError = await validateCallSignal(userId, data, (req as any).timeStatus);
    if (validationError) {
      res.status(403).json({ type: 'call:error', error: validationError });
      return;
    }

    const targetUserId = getOppositeUserId(userId);
    const callType: 'voice' | 'video' = data.callType === 'video' ? 'video' : 'voice';

    // Keep the stored payload limited to signaling fields.
    const signalCreatedAt = new Date().toISOString();
    const payload = {
      type: data.type,
      callType,
      sdp: data.sdp,
      candidate: data.candidate,
      callerId: userId,
      fromUserId: userId,
      targetId: targetUserId,
      callId: data.callId,
      createdAt: signalCreatedAt,
      expiresAt: data.type === 'call:offer' ? Date.now() + 60_000 : undefined,
    };

    if (data.type === 'call:offer' || data.type === 'call:answer' || data.type === 'call:reject' || data.type === 'call:end') {
      try {
        await recordCallChatEvent({
          callId: String(data.callId),
          eventType: data.type,
          callType,
          actorId: userId,
        });
      } catch (historyError) {
        // History is best-effort; a temporary history outage must not break the call itself.
        console.warn('SYNAX call history record failed:', historyError);
      }
      if (data.type === 'call:offer') addLog(userId, `Initiated ${callType} call`, `To ${targetUserId}`);
    }

    try {
      const id = await storeCallSignal({
        from_user_id: userId,
        target_user_id: targetUserId,
        type: data.type,
        call_type: callType,
        payload,
      });

      // HTTP polling is the single authoritative delivery path for WebRTC
      // signaling. Do not also broadcast through WebSocket: doing both can
      // deliver duplicate answers/candidates and race the peer state machine.
      res.json({ success: true, id, createdAt: signalCreatedAt });
    } catch (err) {
      console.error('Failed to store call signal:', err);
      res.status(503).json({ type: 'call:error', error: 'Call signaling service is temporarily unavailable.' });
    }
  });

  app.get('/api/call/signals', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    if (userId !== 'person_1' && userId !== 'person_2') {
      res.status(403).json({ signals: [], error: 'Not a user session.' });
      return;
    }

      const afterId = Math.max(0, Number(req.query.after || 0));
    const sinceMs = Number(req.query.since || Date.now() - 5000);
    const requestedCallId = typeof req.query.callId === 'string' ? req.query.callId : undefined;
    const sinceIso = new Date(Number.isFinite(sinceMs) ? sinceMs : Date.now() - 5000).toISOString();

    try {
      const signals = await readCallSignals(userId, afterId, sinceIso, requestedCallId);
      res.json({ signals });
    } catch (err) {
      console.error('Failed to read call signals:', err);
      res.status(503).json({ signals: [], error: 'Call signaling service is temporarily unavailable.' });
    }
  });
  // ==========================================
  // PUBLIC API ROUTES
  // ==========================================

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true, persistence: 'cloudflare-d1+r2', initialized: Boolean(db), timestamp: Date.now() });
  });

  app.get('/api/time', requireUserAuth, async (req: Request, res: Response) => {
    try {
      // requireUserAuth already calculated the authoritative status. Reuse it
      // rather than issuing a second D1 usage query.
      res.json({ timeStatus: (req as any).timeStatus });
    } catch (err) {
      console.error('Failed to load time status:', err);
      res.status(503).json({ error: 'Time service temporarily unavailable.' });
    }
  });

  // Public identities for cinematic opening and user selection
  app.get('/api/public/identities', async (_req: Request, res: Response) => {
    await refreshDbFromD1();
    res.json({
      worldTitle: db.settings.worldTitle,
      worldSubtitle: db.settings.worldSubtitle,
      theme: db.settings.theme,
      accentColor: db.settings.accentColor,
      introDurationSeconds: db.settings.introDurationSeconds,
      settings: db.settings,
      person_1: {
        id: 'person_1',
        name: db.users.person_1.name,
        username: db.users.person_1.username,
        logo: db.users.person_1.logo,
        isLocked: db.users.person_1.isLocked,
      },
      person_2: {
        id: 'person_2',
        name: db.users.person_2.name,
        username: db.users.person_2.username,
        logo: db.users.person_2.logo,
        isLocked: db.users.person_2.isLocked,
      }
    });
  });

  // User Login (Person 1 or Person 2)
  app.post('/api/auth/login', async (req: Request, res: Response) => {
    const { userId, password } = req.body;
    if (userId !== 'person_1' && userId !== 'person_2') {
      res.status(400).json({ error: 'Invalid user selection. Only Person 1 and Person 2 exist.' });
      return;
    }

    const user = db.users[userId];
    let loginAttemptKey = '';
    try {
      const lockout = await getLoginLockout(req, userId);
      loginAttemptKey = lockout.key;
      if (lockout.lockedUntil > Date.now()) {
        const retryAfterSeconds = Math.max(1, Math.ceil((lockout.lockedUntil - Date.now()) / 1000));
        res.setHeader('Retry-After', String(retryAfterSeconds));
        res.status(429).json({ error: 'LOGIN_RATE_LIMITED', message: 'Too many incorrect attempts. Please try again later.' });
        return;
      }
    } catch (error) {
      console.error('SYNAX login rate-limit check failed:', error);
      res.status(503).json({ error: 'Login is temporarily unavailable. Please try again.' });
      return;
    }
    if (user.isLocked) {
      addLog(userId, 'Login Blocked', 'Attempted login while locked', 'alert');
      res.status(403).json({
        error: 'LOCKED',
        message: user.lockReason || 'This identity has been locked by the Administrator.'
      });
      return;
    }

    const isValid = await verifyPassword(password || '', user.passwordHash);
    if (!isValid) {
      try {
        await recordFailedLogin(loginAttemptKey);
      } catch (error) {
        console.error('SYNAX failed-login counter update failed:', error);
        res.status(503).json({ error: 'Login is temporarily unavailable. Please try again.' });
        return;
      }
      addLog(userId, 'Failed Login Attempt', 'Incorrect password entered', 'warn');
      res.status(401).json({ error: 'Incorrect password for this identity.' });
      return;
    }
    try {
      await clearFailedLogins(loginAttemptKey);
    } catch (error) {
      console.error('SYNAX login counter reset failed:', error);
      res.status(503).json({ error: 'Login is temporarily unavailable. Please try again.' });
      return;
    }

    // Login itself never consumes active-use time.
    // Reconcile first so stale active fields cannot make an offline user lose time.
    const timeStatus = await getPersistentTimeRemaining(userId);
    if (timeStatus.isExpired) {
      res.status(403).json({ error: 'TIME_EXPIRED', message: timeStatus.customMessage, timeStatus });
      return;
    }

    // IMPORTANT: logging in alone does NOT consume time.
    // The active-use timer starts only after this token successfully authenticates
    // a live WebSocket connection in the WebSocket handler below.
    const token = `synax_${userId}_${crypto.randomUUID()}_${crypto.randomUUID()}`;
    const newSession = {
      token,
      userId,
      sessionStart: Date.now(),
      lastActive: Date.now(),
      allowedSeconds: user.allowedMinutes * 60,
      isExpired: timeStatus.isExpired,
      active: false
    };
    db.sessions[token] = newSession;

    await saveSessionToD1(newSession);
    saveDbSync();
    addLog(userId, 'User Logged In', `Session started: ${user.name} entered the sanctuary`);
    // Worker requests may run in different isolates. Do not return the
    // login response until the shared session has been written to D1.
    await flushPersistence();

    const otherId = userId === 'person_1' ? 'person_2' : 'person_1';
    const otherPersistentPresence = await getPersistentPresenceState(otherId);
    const otherUser = {
      id: otherId,
      slot: db.users[otherId].slot,
      name: db.users[otherId].name,
      username: db.users[otherId].username,
      logo: db.users[otherId].logo,
      pfpUrl: db.users[otherId].pfpUrl,
      nickname: db.users[otherId].nickname,
      bio: db.users[otherId].bio,
      lastActiveTimestamp: Number(otherPersistentPresence.lastSeen || db.users[otherId].lastActiveTimestamp || 0) || undefined,
    };

    res.json({
      token,
      user: {
        id: user.id,
        slot: user.slot,
        name: user.name,
        username: user.username,
        logo: user.logo,
        pfpUrl: user.pfpUrl,
        nickname: user.nickname,
        bio: user.bio,
        allowedMinutes: user.allowedMinutes,
      },
      otherUser,
      timeStatus,
      settings: db.settings
    });
  });

  // Logout: close one active session and invalidate its token.
  app.post('/api/auth/logout', async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.json({ success: true });
      return;
    }
    const token = authHeader.split(' ')[1];
    let session: DbSchema['sessions'][string] | null = null;
    try {
      session = await getSessionFromD1(token);
    } catch (err) {
      console.error('Failed to load session for logout:', err);
      res.status(503).json({ error: 'Authentication service temporarily unavailable' });
      return;
    }
    if (!session) {
      res.json({ success: true });
      return;
    }
    session.endedAt = Date.now();
    session.active = false;
    if (session.userId === 'person_1' || session.userId === 'person_2') {
      try { await setPersistentChatPresence(session.userId, false); } catch (err) { console.error('Failed to stop persistent chat timer:', err); }
    }
    try {
      await deleteSessionFromD1(token);
      await sendRealtimeAdminCommand('/revoke-session', { token });
    } catch (err) {
      console.error('Failed to invalidate shared session/realtime socket:', err);
    }
    delete db.sessions[token];
    saveDbSync();
    await flushPersistence();
    // Realtime presence is owned by the Durable Object. Do not broadcast the
    // persistent timer table here: that snapshot can lag behind live sockets
    // and overwrite an authoritative ONLINE state in connected clients.
    res.json({ success: true });
  });

  // Admin Login. The privileged portal uses the same per-IP lockout protection
  // as the two private chat identities.
  app.post('/api/auth/admin-login', async (req: Request, res: Response) => {
    const { password } = req.body;
    let adminAttemptKey = '';
    try {
      const lockout = await getLoginLockout(req, 'admin');
      adminAttemptKey = lockout.key;
      if (lockout.lockedUntil > Date.now()) {
        const retryAfterSeconds = Math.max(1, Math.ceil((lockout.lockedUntil - Date.now()) / 1000));
        res.setHeader('Retry-After', String(retryAfterSeconds));
        res.status(429).json({ error: 'LOGIN_RATE_LIMITED', message: 'Too many incorrect attempts. Please try again later.' });
        return;
      }
    } catch (error) {
      console.error('SYNAX admin login rate-limit check failed:', error);
      res.status(503).json({ error: 'Admin login is temporarily unavailable. Please try again.' });
      return;
    }

    const isValid = await verifyPassword(password || '', db.admin.passwordHash);
    if (!isValid) {
      try { await recordFailedLogin(adminAttemptKey); }
      catch (error) {
        console.error('SYNAX admin failed-login counter update failed:', error);
        res.status(503).json({ error: 'Admin login is temporarily unavailable. Please try again.' });
        return;
      }
      addLog('Admin Portal', 'Admin Login Failed', 'Incorrect admin password attempt', 'alert');
      res.status(401).json({ error: 'Incorrect Administrator password.' });
      return;
    }
    try { await clearFailedLogins(adminAttemptKey); }
    catch (error) {
      console.error('SYNAX admin login counter reset failed:', error);
      res.status(503).json({ error: 'Admin login is temporarily unavailable. Please try again.' });
      return;
    }

    const token = `synax_admin_${crypto.randomUUID()}_${crypto.randomUUID()}`;
    const adminSession = {
      token,
      userId: 'admin' as const,
      sessionStart: Date.now(),
      lastActive: Date.now(),
      allowedSeconds: 86400 * 365,
      isExpired: false
    };
    db.sessions[token] = adminSession;

    await saveSessionToD1(adminSession);
    saveDbSync();
    addLog('Admin Portal', 'Admin Login Success', 'Admin authenticated into System Controls');
    // Ensure the token exists in shared storage before the frontend starts
    // requesting /api/admin/* from another Worker isolate.
    await flushPersistence();

    res.json({
      token,
      role: 'admin',
      settings: db.settings
    });
  });

  // Current session status verification
  app.get('/api/auth/me', async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token' });
      return;
    }
    const token = authHeader.split(' ')[1];
    let session: DbSchema['sessions'][string] | null = null;
    try {
      session = await getSessionFromD1(token);
    } catch (err) {
      console.error('Failed to validate session:', err);
      res.status(503).json({ error: 'Authentication service temporarily unavailable' });
      return;
    }
    if (!session) {
      res.status(401).json({ error: 'Session expired' });
      return;
    }

    if (session.userId === 'admin') {
      res.json({ role: 'admin', settings: db.settings });
      return;
    }

    const userId = session.userId as 'person_1' | 'person_2';
    const user = db.users[userId];
    const otherId = userId === 'person_1' ? 'person_2' : 'person_1';
    const otherUser = db.users[otherId];
    const otherPersistentPresence = await getPersistentPresenceState(otherId);
    const timeStatus = await getPersistentTimeRemaining(userId);

    res.json({
      token,
      user: {
        id: user.id,
        slot: user.slot,
        name: user.name,
        username: user.username,
        logo: user.logo,
        pfpUrl: user.pfpUrl,
        nickname: user.nickname,
        bio: user.bio,
        isLocked: user.isLocked,
        lockReason: user.lockReason,
        allowedMinutes: user.allowedMinutes,
      },
      otherUser: {
        id: otherId,
        slot: otherUser.slot,
        name: otherUser.name,
        username: otherUser.username,
        logo: otherUser.logo,
        pfpUrl: otherUser.pfpUrl,
        nickname: otherUser.nickname,
        bio: otherUser.bio,
        lastActiveTimestamp: Number(otherPersistentPresence.lastSeen || otherUser.lastActiveTimestamp || 0) || undefined,
      },
      timeStatus,
      settings: db.settings
    });
  });

  // Update own PFP & profile info (User can ONLY edit their own PFP/bio, not the other person's, and not the logo!)
  app.post('/api/profile/update', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const { pfpUrl, nickname, bio } = req.body;
    const user = db.users[userId];
    const previousPfpUrl = user.pfpUrl;

    if (pfpUrl !== undefined) {
      if (typeof pfpUrl !== 'string' || pfpUrl.length > 2048) {
        res.status(400).json({ error: 'Profile image reference is invalid.' });
        return;
      }
      user.pfpUrl = pfpUrl;
    }
    if (nickname !== undefined) user.nickname = String(nickname).slice(0, 48);
    if (bio !== undefined) user.bio = String(bio).slice(0, 300);

    addLog(userId, 'Profile Updated', `Updated personal PFP / profile information`);
    try {
      await saveDbSync();
      await flushPersistence();
      if (pfpUrl !== undefined && previousPfpUrl !== user.pfpUrl) {
        await deletePrivateR2Media(previousPfpUrl);
      }
    } catch (error) {
      console.error('Failed to persist SYNAX profile update:', error);
      res.status(503).json({ error: 'Profile update could not be saved. Please retry.' });
      return;
    }

    // Broadcast profile change only after it is durably saved.
    broadcast({
      type: 'profile:updated',
      userId,
      profile: {
        id: user.id,
        name: user.name,
        pfpUrl: user.pfpUrl,
        nickname: user.nickname,
        bio: user.bio
      }
    });

    res.json({ success: true, user });
  });

  // ==========================================
  // CHAT & MESSAGING API
  // ==========================================

  // ==========================================
  // SHARED CHAT BACKGROUND API
  // ==========================================

  app.get('/api/chat/background', requireUserAuth, async (_req: Request, res: Response) => {
    try {
      const background = await loadChatBackground();
      res.json({
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: background.updated_by,
      });
    } catch (err: any) {
      console.error('Failed to load shared chat background:', err);
      res.status(503).json({ error: 'Chat background is temporarily unavailable.' });
    }
  });

  app.post('/api/chat/background/preset', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const backgroundId = String(req.body?.backgroundId || '').trim();
    if (!ALLOWED_CHAT_BACKGROUND_PRESETS.has(backgroundId)) {
      res.status(400).json({ error: 'Invalid chat background preset.' });
      return;
    }
    try {
      const previousBackground = await loadChatBackground();
      const background: ChatBackgroundRecord = {
        chat_id: SYNAX_CHAT_ID,
        background_type: 'preset',
        background_value: backgroundId,
        background_updated_at: Date.now(),
        updated_by: userId,
      };
      await saveChatBackground(background);
      if (previousBackground.background_type === 'image') await deletePrivateR2Media(previousBackground.background_value);
      broadcast({
        type: 'chat:background_updated',
        chatId: SYNAX_CHAT_ID,
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });
      res.json({
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });
    } catch (err) {
      console.error('Failed to save preset chat background:', err);
      res.status(503).json({ error: 'Unable to save chat background.' });
    }
  });

  app.delete('/api/chat/background', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    try {
      const previousBackground = await loadChatBackground();
      const background: ChatBackgroundRecord = {
        chat_id: SYNAX_CHAT_ID,
        background_type: 'preset',
        background_value: 'stars',
        background_updated_at: Date.now(),
        updated_by: userId,
      };
      await saveChatBackground(background);
      if (previousBackground.background_type === 'image') await deletePrivateR2Media(previousBackground.background_value);
      broadcast({
        type: 'chat:background_updated',
        chatId: SYNAX_CHAT_ID,
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });
      res.json({
        backgroundType: background.background_type,
        backgroundValue: background.background_value,
        updatedAt: background.background_updated_at,
        updatedBy: userId,
      });
    } catch (err) {
      console.error('Failed to reset shared chat background:', err);
      res.status(503).json({ error: 'Unable to reset chat background.' });
    }
  });

  // Small recovery endpoint used while the chat is open. The WebSocket remains
  // the fast path; this only retrieves the recent window so a missed event is
  // repaired without repeatedly downloading the entire conversation history.
  app.get('/api/messages/recent', requireUserAuth, async (req: Request, res: Response) => {
    const now = Date.now();
    const requestedSince = Number(req.query.since);
    // Keep a 15-second overlap for delayed persistence/clock skew, but bound
    // the range so this endpoint cannot accidentally scan the full history.
    const since = Number.isFinite(requestedSince) && requestedSince > 0
      ? Math.max(now - 120_000, Math.min(requestedSince, now) - 15_000)
      : now - 60_000;

    const select = 'id,client_message_id,sender_id,type,text,file_url,file_name,file_size,audio_duration,timestamp,status,reactions,reply_to,is_pinned,is_edited,deleted';
    const path = `/rest/v1/${D1_MESSAGES_TABLE}?select=${select}` +
      `&timestamp=gte.${Math.floor(since)}&order=timestamp.asc,id.asc&limit=250`;

    const [canonicalResult, pendingResult] = await Promise.allSettled([
      databaseFetch(path, {
        headers: { 'Cache-Control': 'no-cache' },
        signal: AbortSignal.timeout(3000),
      })
        .then(async (response) => {
          const rows = await response.json() as D1MessageRow[];
          if (!Array.isArray(rows)) throw new Error('D1 returned an invalid recent-message response.');
          return rows.map(rowToChatMessage);
        }),
      // The Durable Object queue is the source of truth for messages that have
      // been accepted but are still waiting for D1 persistence. Keep this
      // best-effort and bounded so an unhealthy realtime request never blocks
      // already-persisted recent messages.
      loadPendingMessagesFromRealtime(900).catch(() => []),
    ]);

    const canonical = canonicalResult.status === 'fulfilled' ? canonicalResult.value : [];
    const pending = pendingResult.status === 'fulfilled'
      ? pendingResult.value.filter((message: any) => Number(message?.timestamp || 0) >= since)
      : [];

    if (canonicalResult.status === 'rejected' && pending.length === 0) {
      console.warn('SYNAX recent-message recovery failed:', canonicalResult.reason);
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.status(503).json({
        error: 'Recent message recovery is temporarily unavailable.',
        detail: canonicalResult.reason instanceof Error ? canonicalResult.reason.message : String(canonicalResult.reason),
      });
      return;
    }

    const messages = mergePendingMessages(canonical, pending);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.json({ messages, serverTime: now });
  });

  // Get messages from the canonical D1 chat table. This avoids the
  // cross-isolate overwrite/race problems of keeping the conversation inside
  // a Cloudflare Worker global variable.
  app.get('/api/messages', requireUserAuth, async (_req: Request, res: Response) => {
    try {
      const messages = await loadMessagesFromD1();
      db.messages = messages;
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      // Safe diagnostics help distinguish a successful empty history response
      // from a storage failure. No keys or secrets are exposed here.
      const databaseName = 'SYNAX D1';
      res.json({
        messages,
        historyDiagnostics: {
          source: `public.${D1_MESSAGES_TABLE}`,
          count: messages.length,
          databaseName,
        },
      });
    } catch (err) {
      console.error('Failed to load messages:', err);
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.status(503).json({
        error: 'Chat storage temporarily unavailable.',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Send a message. clientMessageId makes retries idempotent so a lost network
  // response never creates duplicate messages.
  app.post('/api/messages', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const otherId = userId === 'person_1' ? 'person_2' : 'person_1';
    const { text, type, fileUrl, fileName, fileSize, audioDuration, replyTo } = req.body;
    const clientMessageId = typeof req.body?.clientMessageId === 'string' ? req.body.clientMessageId.trim() : '';
    const timeStatus = (req as any).timeStatus || await getPersistentTimeRemaining(userId);

    if (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableMessaging) {
      res.status(403).json({
        error: 'TIME_EXPIRED',
        message: db.settings.timeOverMessage || 'Sanctuary communication time has expired.',
        timeStatus
      });
      return;
    }

    if (!db.settings.featuresEnabled.messages) {
      res.status(403).json({ error: 'Messaging is temporarily disabled by Admin.' });
      return;
    }
    if (type === 'voice') {
      if (!db.settings.featuresEnabled.voiceMessages) {
        res.status(403).json({ error: 'Voice messages are disabled by Admin.' });
        return;
      }
      if (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableVoiceMessages) {
        res.status(403).json({ error: 'Voice messages are restricted due to expired sanctuary time.' });
        return;
      }
    }
    if (type === 'image') {
      if (!db.settings.featuresEnabled.imageSharing) {
        res.status(403).json({ error: 'Image sharing is disabled by Admin.' });
        return;
      }
      if (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableImages) {
        res.status(403).json({ error: 'Image sharing is restricted due to expired sanctuary time.' });
        return;
      }
    }
    if (type === 'video') {
      if (!db.settings.featuresEnabled.imageSharing) {
        res.status(403).json({ error: 'Photo/video sharing is disabled by Admin.' });
        return;
      }
      if (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableImages) {
        res.status(403).json({ error: 'Video sharing is restricted due to expired sanctuary time.' });
        return;
      }
    }
    if (type === 'file') {
      if (!db.settings.featuresEnabled.fileSharing) {
        res.status(403).json({ error: 'File sharing is disabled by Admin.' });
        return;
      }
      if (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableFiles) {
        res.status(403).json({ error: 'File sharing is restricted due to expired sanctuary time.' });
        return;
      }
    }

    // Delivery state is advanced by the realtime layer. Do not perform an extra
    // D1 presence read before every message send.
    const now = Date.now();
    const generatedId = `msg_${now}_${Math.random().toString(36).slice(2, 8)}`;
    const validClientMessageId = clientMessageId && /^[A-Za-z0-9._:-]{8,140}$/.test(clientMessageId)
      ? clientMessageId
      : null;
    const newMessage = {
      id: generatedId,
      clientMessageId: validClientMessageId || undefined,
      senderId: userId,
      type: type || 'text',
      text: text || '',
      fileUrl: fileUrl || undefined,
      fileName: fileName || undefined,
      fileSize: fileSize || undefined,
      audioDuration: audioDuration || undefined,
      timestamp: now,
      status: 'sent' as 'sent' | 'delivered' | 'read',
      reactions: {},
      replyTo: replyTo ? {
        id: replyTo.id,
        text: replyTo.text,
        senderName: replyTo.senderName
      } : undefined
    };

    try {
      // The API still performs authentication, expiry, and feature checks
      // before this point. The Durable Object writes the message to its
      // persistent pending queue first, then attempts a canonical D1 save
      // before acknowledging it. If D1 is unavailable, the durable queue
      // is retained and retried by the alarm; history merges that queue with
      // canonical rows so a refresh does not silently drop the message.
      const delivery = await broadcastChatMessage({
        type: 'chat:enqueue_message',
        message: newMessage,
      });

      let responseMessage = (delivery.message || newMessage) as any;
      if (delivery.delivered && responseMessage.status !== 'read') responseMessage = { ...responseMessage, status: 'delivered' };

      db.messages = [...(db.messages || []).filter((m: any) =>
        m.id !== responseMessage.id && (!validClientMessageId || m.clientMessageId !== validClientMessageId)
      ), responseMessage].sort((a: any, b: any) => Number(a.timestamp) - Number(b.timestamp));

      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.json({
        success: true,
        message: responseMessage,
        delivery: {
          recipientOnline: delivery.recipientOnline,
          delivered: delivery.delivered,
          persistedToD1: delivery.persistedToD1,
          durability: delivery.durability,
        },
      });
    } catch (err) {
      console.error('Realtime enqueue failed; using durable D1 fallback:', err);
      // The realtime hub must never turn an otherwise-valid message into a 503.
      // Persist the message directly, then make a best-effort realtime fan-out.
      // The optimistic client bubble is reconciled against this canonical row.
      try {
        const persistedMessage = await insertMessageToD1(newMessage, validClientMessageId);
        db.messages = [...(db.messages || []).filter((m: any) =>
          m.id !== persistedMessage.id && (!validClientMessageId || m.clientMessageId !== validClientMessageId)
        ), persistedMessage]
          .sort((a: any, b: any) => Number(a.timestamp) - Number(b.timestamp));

        // Do not let a second realtime failure undo the successful database send.
        // broadcast() is intentionally fire-and-forget and swallows transport errors.
        broadcast({ type: 'chat:new_message', message: persistedMessage });

        res.setHeader('Cache-Control', 'no-store, max-age=0');
        res.json({
          success: true,
          message: {
            ...persistedMessage,
            clientMessageId: persistedMessage?.clientMessageId || validClientMessageId || undefined,
          },
          delivery: { recipientOnline: false, delivered: false },
        });
      } catch (fallbackError) {
        console.error('Failed to persist fallback message:', fallbackError);
        res.status(503).json({
          error: 'Message storage temporarily unavailable.',
          detail: fallbackError instanceof Error ? fallbackError.message : String(fallbackError),
        });
      }
    }
  });

  // Mark partner messages as read. When messageIds are supplied, only those
  // messages are advanced; this lets the client use true viewport-based read
  // receipts instead of marking an entire history read merely because the tab
  // became visible.
  app.post('/api/messages/mark-read', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const otherId = userId === 'person_1' ? 'person_2' : 'person_1';
    const messageIds = Array.isArray(req.body?.messageIds) ? req.body.messageIds : undefined;
    try {
      const readCount = await markMessagesReadInD1(otherId, messageIds);
      if (readCount > 0) {
        broadcast({
          type: 'chat:messages_read',
          readerId: userId,
          senderId: otherId,
          messageIds: Array.isArray(messageIds) ? messageIds : undefined,
        });
      }
      res.json({ success: true, count: readCount });
    } catch (err) {
      console.error('Failed to mark messages read:', err);
      res.status(503).json({ error: 'Chat storage temporarily unavailable.' });
    }
  });

  // Lightweight live presence snapshot used as a reconciliation fallback.
  // WebSocket/Durable Object remains the fastest path; this endpoint ensures the
  // UI can recover from a dropped presence event without requiring a refresh.
  app.get('/api/presence/state', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const otherId = userId === 'person_1' ? 'person_2' : 'person_1';
    try {
      const [self, other] = await Promise.all([
        getPersistentPresenceState(userId),
        getPersistentPresenceState(otherId),
      ]);
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.json({
        serverTimestamp: Date.now(),
        self: { isOnline: self.active, lastSeen: self.lastSeen },
        other: { id: otherId, isOnline: other.active, lastSeen: other.lastSeen },
      });
    } catch (err) {
      console.error('Failed to load live presence state:', err);
      res.status(503).json({ error: 'Presence service temporarily unavailable.' });
    }
  });

  // Lightweight authoritative receipt reconciliation. This endpoint returns
  // only the current user's latest outgoing message statuses, allowing the UI
  // to recover from a missed WebSocket delivery/read event without downloading
  // the entire chat history every few seconds.
  app.get('/api/messages/receipts', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    try {
      const response = await databaseFetch(
        `/rest/v1/${D1_MESSAGES_TABLE}?sender_id=eq.${userId}&select=id,status&order=timestamp.desc&limit=100`,
        { headers: { 'Cache-Control': 'no-cache' } },
      );
      const rows = await response.json().catch(() => []);
      res.json({
        receipts: Array.isArray(rows)
          ? rows.map((row: any) => ({ id: String(row.id), status: row.status }))
          : [],
      });
    } catch (err) {
      console.error('Failed to load message receipts:', err);
      res.status(503).json({
        error: 'Chat receipt service temporarily unavailable.',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Toggle reaction on a message.
  app.post('/api/messages/:id/reaction', requireUserAuth, async (req: Request, res: Response) => {
    if (!db.settings.featuresEnabled.reactions) {
      res.status(403).json({ error: 'Reactions are disabled by Admin.' });
      return;
    }
    const userId = (req as any).userId as string;
    const { id } = req.params;
    const { emoji } = req.body;
    if (typeof emoji !== 'string' || emoji.length > 32) {
      res.status(400).json({ error: 'Invalid reaction.' });
      return;
    }
    try {
      const msg = await findMessageById(id);
      if (!msg) {
        res.status(404).json({ error: 'Message not found' });
        return;
      }
      const reactions = { ...(msg.reactions || {}) };
      if (reactions[userId] === emoji) delete reactions[userId];
      else reactions[userId] = emoji;
      const updated = await updateMessageInD1(id, { reactions });
      broadcast({ type: 'chat:reaction_update', messageId: id, reactions });
      res.json({ success: true, reactions, message: updated || msg });
    } catch (err) {
      console.error('Failed to update reaction:', err);
      res.status(503).json({ error: 'Chat storage temporarily unavailable.' });
    }
  });

  // Edit message.
  app.put('/api/messages/:id', requireUserAuth, async (req: Request, res: Response) => {
    if (!db.settings.featuresEnabled.editing) {
      res.status(403).json({ error: 'Editing is disabled by Admin.' });
      return;
    }
    const userId = (req as any).userId as string;
    const { id } = req.params;
    const { text } = req.body;
    if (typeof text !== 'string' || text.trim().length === 0 || text.length > 10000) {
      res.status(400).json({ error: 'Invalid message text.' });
      return;
    }
    try {
      const msg = await findMessageById(id);
      if (!msg) {
        res.status(404).json({ error: 'Message not found' });
        return;
      }
      if (msg.senderId !== userId) {
        res.status(403).json({ error: 'You can only edit your own messages.' });
        return;
      }
      const updated = await updateMessageInD1(id, { text, is_edited: true });
      const editedMessage = updated || { ...msg, text, isEdited: true };
      broadcast({
        type: 'chat:message_edited',
        messageId: id,
        clientMessageId: editedMessage.clientMessageId || msg.clientMessageId,
        text: editedMessage.text ?? text,
        isEdited: true,
        message: editedMessage,
      });
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.json({ success: true, message: editedMessage });
    } catch (err) {
      console.error('Failed to edit message:', err);
      res.status(503).json({ error: 'Chat storage temporarily unavailable.' });
    }
  });

  // Delete message.
  app.delete('/api/messages/:id', requireUserAuth, async (req: Request, res: Response) => {
    if (!db.settings.featuresEnabled.deleting) {
      res.status(403).json({ error: 'Deleting messages is disabled by Admin.' });
      return;
    }
    const userId = (req as any).userId as string;
    const { id } = req.params;
    try {
      const msg = await findMessageById(id);
      if (!msg) {
        res.status(404).json({ error: 'Message not found' });
        return;
      }
      if (msg.senderId !== userId) {
        res.status(403).json({ error: 'You can only delete your own messages.' });
        return;
      }
      const updated = await updateMessageInD1(id, { deleted: true, text: 'This message was deleted', file_url: null });
      if (!updated) throw new Error('Message deletion was not confirmed by D1.');
      await deletePrivateR2Media(msg.fileUrl);
      broadcast({ type: 'chat:message_deleted', messageId: id });
      res.json({ success: true });
    } catch (err) {
      console.error('Failed to delete message:', err);
      res.status(503).json({ error: 'Chat storage temporarily unavailable.' });
    }
  });

  // Pin / unpin message.
  app.post('/api/messages/:id/pin', requireUserAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      const msg = await findMessageById(id);
      if (!msg) {
        res.status(404).json({ error: 'Message not found' });
        return;
      }
      const isPinned = !Boolean(msg.isPinned);
      await updateMessageInD1(id, { is_pinned: isPinned });
      broadcast({ type: 'chat:message_pinned', messageId: id, isPinned });
      res.json({ success: true, isPinned });
    } catch (err) {
      console.error('Failed to pin message:', err);
      res.status(503).json({ error: 'Chat storage temporarily unavailable.' });
    }
  });

  // Presence + authoritative server timer. The state is stored in D1 so
  // a heartbeat is not lost when Cloudflare sends the next request to another isolate.
  app.post('/api/presence/chat', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const active = req.body?.active !== false;
    try {
      const timeStatus = await setPersistentChatPresence(userId, active);
      const lastSeen = Date.now();
      // Persistent usage/timer heartbeat is separate from realtime presence.
      // Do not broadcast a partial presence object here because it can overwrite
      // the other user's live state. The Durable Object is the single source of
      // truth for ONLINE (chatActive socket) and DELIVERY (connected socket).
      const presence = { userId, isOnline: active, lastSeen };
      broadcast({ type: 'time:tick', userId, timeStatus });
      res.json({ success: true, presence, timeStatus });
    } catch (err) {
      console.error('Failed to update persistent presence/time:', err);
      res.status(503).json({ error: 'Presence/time service temporarily unavailable.' });
    }
  });


  // Private R2 media delivery. The signed URL is a bearer capability: it is
  // intentionally unguessable and stored in the message row for durable history.
  // Never make the R2 bucket public or expose its credentials to the browser.
  app.get('/api/media', async (req: Request, res: Response) => {
    try {
      const objectKey = String(req.query.key || '');
      const signature = String(req.query.sig || '');
      if (!objectKey || objectKey.length > 700 || objectKey.includes('..') || objectKey.startsWith('/') || !/^(media|chat-backgrounds)\/[A-Za-z0-9_./-]+$/.test(objectKey)) {
        return res.status(400).json({ error: 'Invalid media reference.' });
      }
      const expected = await signMediaKey(objectKey);
      const valid = signature.length === expected.length && /^[a-f0-9]+$/i.test(signature) &&
        await crypto.subtle.verify(
          'HMAC',
          await crypto.subtle.importKey('raw', new TextEncoder().encode(String(cloudflareEnv.SYNAX_MEDIA_SIGNING_SECRET)), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']),
          Uint8Array.from(signature.match(/.{2}/g) || [], (part) => parseInt(part, 16)),
          new TextEncoder().encode(objectKey),
        );
      if (!valid) return res.status(403).json({ error: 'This media link is invalid.' });

      const bucket = cloudflareEnv.SYNAX_MEDIA;
      const rangeHeader = String(req.headers.range || '');
      let range: { offset: number; length: number } | undefined;
      let responseStatus = 200;
      let totalSize: number | null = null;
      if (rangeHeader) {
        const head = await bucket.head(objectKey);
        if (!head) return res.status(404).json({ error: 'Media not found.' });
        totalSize = Number(head.size);
        const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
        if (!match || (!match[1] && !match[2])) {
          res.setHeader('Content-Range', `bytes */${totalSize}`);
          return res.status(416).end();
        }
        let startByte: number;
        let endByte: number;
        if (!match[1]) {
          const suffixLength = Number(match[2]);
          startByte = Math.max(0, totalSize - suffixLength);
          endByte = totalSize - 1;
        } else {
          startByte = Number(match[1]);
          endByte = match[2] ? Math.min(Number(match[2]), totalSize - 1) : totalSize - 1;
        }
        if (!Number.isSafeInteger(startByte) || !Number.isSafeInteger(endByte) || startByte < 0 || endByte < startByte || startByte >= totalSize) {
          res.setHeader('Content-Range', `bytes */${totalSize}`);
          return res.status(416).end();
        }
        range = { offset: startByte, length: endByte - startByte + 1 };
        responseStatus = 206;
      }

      const object = await bucket.get(objectKey, range ? { range } : undefined);
      if (!object) return res.status(404).json({ error: 'Media not found.' });
      const body = Buffer.from(await object.arrayBuffer());
      const contentType = object.httpMetadata?.contentType || 'application/octet-stream';
      res.status(responseStatus);
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Length', String(body.length));
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Cache-Control', 'private, max-age=3600, immutable');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
      if (object.httpMetadata?.contentDisposition) {
        res.setHeader('Content-Disposition', object.httpMetadata.contentDisposition);
      }
      if (object.httpEtag) res.setHeader('ETag', object.httpEtag);
      if (range && totalSize !== null) {
        res.setHeader('Content-Range', `bytes ${range.offset}-${range.offset + range.length - 1}/${totalSize}`);
      }
      return res.end(body);
    } catch (error) {
      console.error('Private R2 media read failed:', error);
      return res.status(503).json({ error: 'Media is temporarily unavailable.' });
    }
  });

  const MEDIA_PART_SIZE = 5 * 1024 * 1024;
  const MAX_MEDIA_SIZE = 50 * 1024 * 1024;

  // Start an authenticated R2 multipart upload. The browser only receives an
  // opaque upload ID and object key; all R2 operations remain in this Worker.
  app.post('/api/upload/resumable', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const timeStatus = (req as any).timeStatus || await getPersistentTimeRemaining(userId);
    const fileName = safeInlineFileName(String(req.body?.fileName || 'upload.bin'));
    const mimeType = String(req.body?.mimeType || 'application/octet-stream').split(';')[0].trim().toLowerCase();
    const kind = req.body?.kind === 'video' || req.body?.kind === 'image' ? req.body.kind : 'file';
    const fileSize = Number(req.body?.fileSize || 0);

    if (timeStatus.isExpired && db.settings.restrictionsOnExpire.lockSession) {
      return res.status(403).json({ error: 'TIME_EXPIRED', message: db.settings.timeOverMessage, timeStatus });
    }
    if ((kind === 'video' || kind === 'image') && (!db.settings.featuresEnabled.imageSharing || (timeStatus.isExpired && db.settings.restrictionsOnExpire.disableImages))) {
      return res.status(403).json({ error: 'Photo/video sharing is unavailable for this account.' });
    }
    if (!Number.isSafeInteger(fileSize) || fileSize <= MEDIA_PART_SIZE || fileSize > MAX_MEDIA_SIZE) {
      return res.status(400).json({ error: 'Resumable media must be larger than 5 MB and no larger than 50 MB.' });
    }

    const objectKey = `media/${userId}/${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}${safeObjectExtension(fileName)}`;
    const uploadId = crypto.randomUUID();
    try {
      const multipart = await cloudflareEnv.SYNAX_MEDIA.createMultipartUpload(objectKey, {
        httpMetadata: {
          contentType: mimeType || 'application/octet-stream',
          contentDisposition: safeMediaContentDisposition(mimeType, fileName),
          cacheControl: 'private, max-age=3600, immutable',
        },
        customMetadata: { owner: userId, originalName: fileName, kind },
      });
      // Use our own opaque ID in the client protocol. The R2 multipart ID is
      // stored only in D1 so a browser cannot directly operate on the bucket.
      await cloudflareEnv.SYNAX_DB.prepare(
        'INSERT INTO synax_uploads (upload_id, object_key, r2_upload_id, user_id, file_name, content_type, file_size, uploaded_size, created_at, completed) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0)'
      ).bind(uploadId, objectKey, multipart.uploadId, userId, fileName, mimeType || 'application/octet-stream', fileSize, Date.now()).run();

      res.setHeader('Cache-Control', 'no-store');
      return res.json({
        uploadId,
        objectName: objectKey,
        fileName,
        mimeType,
        fileSize,
        chunkSize: MEDIA_PART_SIZE,
        timeStatus: { serverTimestamp: Date.now(), remainingSeconds: timeStatus.remainingSeconds, isExpired: timeStatus.isExpired },
      });
    } catch (error) {
      console.error('Failed to prepare R2 multipart upload:', error);
      return res.status(503).json({ error: 'Unable to prepare media upload.' });
    }
  });

  app.post('/api/upload/resumable/offset', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const uploadId = String(req.body?.uploadId || '');
    const objectKey = String(req.body?.objectName || '');
    if (!uploadId || !objectKey) return res.status(400).json({ error: 'Missing upload reference.' });
    try {
      const row = await cloudflareEnv.SYNAX_DB.prepare(
        'SELECT upload_id, object_key, file_size, uploaded_size, completed FROM synax_uploads WHERE upload_id = ? AND user_id = ? LIMIT 1'
      ).bind(uploadId, userId).first();
      if (!row || row.object_key !== objectKey) return res.status(404).json({ error: 'Upload not found.' });
      res.setHeader('Cache-Control', 'no-store');
      return res.json({ offset: row.completed ? Number(row.file_size) : Number(row.uploaded_size || 0), completed: Boolean(row.completed) });
    } catch (error) {
      console.error('Failed to read R2 upload offset:', error);
      return res.status(503).json({ error: 'Unable to check upload progress.' });
    }
  });

  app.patch('/api/upload/resumable/chunk', requireUserAuth, express.raw({ type: '*/*', limit: '5.5mb' }), async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const uploadId = String(req.headers['x-synax-upload-id'] || '');
    const objectKey = String(req.headers['x-synax-object-name'] || '');
    const offset = Number(req.headers['upload-offset'] || 0);
    const body = req.body as unknown;
    const chunk = body instanceof Uint8Array ? new Uint8Array(body) : Buffer.isBuffer(body) ? new Uint8Array(body) : new Uint8Array();
    if (!uploadId || !objectKey || !Number.isSafeInteger(offset) || offset < 0 || chunk.byteLength === 0) {
      return res.status(400).json({ error: 'Invalid upload chunk.' });
    }
    try {
      const row = await cloudflareEnv.SYNAX_DB.prepare(
        'SELECT upload_id, object_key, r2_upload_id, user_id, file_size, uploaded_size, completed FROM synax_uploads WHERE upload_id = ? AND user_id = ? LIMIT 1'
      ).bind(uploadId, userId).first();
      if (!row || row.object_key !== objectKey || row.completed) return res.status(404).json({ error: 'Upload not found or already completed.' });
      const currentOffset = Number(row.uploaded_size || 0);
      if (offset !== currentOffset) {
        res.setHeader('Upload-Offset', String(currentOffset));
        return res.status(409).json({ error: 'Upload offset changed.', offset: currentOffset });
      }
      const expectedLength = Math.min(MEDIA_PART_SIZE, Number(row.file_size) - currentOffset);
      if (currentOffset % MEDIA_PART_SIZE !== 0 || chunk.byteLength !== expectedLength || chunk.byteLength > MEDIA_PART_SIZE) {
        return res.status(400).json({ error: 'Invalid media chunk size or alignment.' });
      }

      const partNumber = Math.floor(currentOffset / MEDIA_PART_SIZE) + 1;
      const multipart = cloudflareEnv.SYNAX_MEDIA.resumeMultipartUpload(objectKey, String(row.r2_upload_id));
      const uploadedPart = await multipart.uploadPart(partNumber, chunk);
      const nextOffset = currentOffset + chunk.byteLength;
      await cloudflareEnv.SYNAX_DB.batch([
        cloudflareEnv.SYNAX_DB.prepare(
          'INSERT INTO synax_upload_parts (upload_id, part_number, etag, part_size) VALUES (?, ?, ?, ?) ON CONFLICT(upload_id, part_number) DO UPDATE SET etag = excluded.etag, part_size = excluded.part_size'
        ).bind(uploadId, partNumber, uploadedPart.etag, chunk.byteLength),
        cloudflareEnv.SYNAX_DB.prepare(
          'UPDATE synax_uploads SET uploaded_size = ? WHERE upload_id = ? AND uploaded_size = ? AND completed = 0'
        ).bind(nextOffset, uploadId, currentOffset),
      ]);
      const latest = await cloudflareEnv.SYNAX_DB.prepare('SELECT uploaded_size FROM synax_uploads WHERE upload_id = ?').bind(uploadId).first();
      const latestOffset = Number(latest?.uploaded_size || 0);
      res.setHeader('Upload-Offset', String(latestOffset));
      if (latestOffset !== nextOffset) return res.status(409).json({ error: 'Upload was updated by another request.', offset: latestOffset });
      res.setHeader('Cache-Control', 'no-store');
      return res.status(204).end();
    } catch (error) {
      console.error('R2 multipart chunk upload failed:', error);
      return res.status(503).json({ error: 'The media chunk could not be saved. Retry the upload.' });
    }
  });

  app.post('/api/upload/resumable/complete', requireUserAuth, async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const uploadId = String(req.body?.uploadId || '');
    const objectKey = String(req.body?.objectName || '');
    if (!uploadId || !objectKey) return res.status(400).json({ error: 'Missing upload reference.' });
    try {
      const row = await cloudflareEnv.SYNAX_DB.prepare(
        'SELECT upload_id, object_key, r2_upload_id, file_size, file_name, uploaded_size, completed FROM synax_uploads WHERE upload_id = ? AND user_id = ? LIMIT 1'
      ).bind(uploadId, userId).first();
      if (!row || row.object_key !== objectKey) return res.status(404).json({ error: 'Upload not found.' });
      if (!row.completed) {
        if (Number(row.uploaded_size) !== Number(row.file_size)) return res.status(409).json({ error: 'Upload is incomplete.' });
        const partsRows = await cloudflareEnv.SYNAX_DB.prepare(
          'SELECT part_number, etag, part_size FROM synax_upload_parts WHERE upload_id = ? ORDER BY part_number ASC'
        ).bind(uploadId).all();
        const parts = partsRows.results || [];
        const expectedCount = Math.ceil(Number(row.file_size) / MEDIA_PART_SIZE);
        if (parts.length !== expectedCount) return res.status(409).json({ error: 'Some media chunks are missing.' });
        for (let index = 0; index < parts.length; index += 1) {
          const expectedPartSize = Math.min(MEDIA_PART_SIZE, Number(row.file_size) - index * MEDIA_PART_SIZE);
          if (Number(parts[index].part_number) !== index + 1 || Number(parts[index].part_size) !== expectedPartSize || !parts[index].etag) {
            return res.status(409).json({ error: 'The uploaded media parts failed verification.' });
          }
        }
        let object = await cloudflareEnv.SYNAX_MEDIA.head(objectKey);
        if (!object) {
          const multipart = cloudflareEnv.SYNAX_MEDIA.resumeMultipartUpload(objectKey, String(row.r2_upload_id));
          await multipart.complete(parts.map((part: any) => ({ partNumber: Number(part.part_number), etag: String(part.etag) })));
          object = await cloudflareEnv.SYNAX_MEDIA.head(objectKey);
        }
        if (!object || Number(object.size) !== Number(row.file_size)) throw new Error('R2 object size did not match the uploaded file size.');
        await cloudflareEnv.SYNAX_DB.prepare('UPDATE synax_uploads SET completed = 1 WHERE upload_id = ? AND user_id = ?').bind(uploadId, userId).run();
        await cloudflareEnv.SYNAX_DB.prepare('DELETE FROM synax_upload_parts WHERE upload_id = ?').bind(uploadId).run();
      }
      const fileUrl = await createSignedMediaUrl(objectKey);
      res.setHeader('Cache-Control', 'no-store');
      return res.json({ fileUrl, fileName: row.file_name, fileSize: Number(row.file_size) });
    } catch (error) {
      console.error('Failed to complete R2 multipart upload:', error);
      return res.status(503).json({ error: 'Unable to finish media upload.' });
    }
  });

  // Small attachments and voice notes are written directly to R2. Large
  // images/videos use the multipart route above to avoid buffering 50 MB.
  app.post('/api/upload', requireUserAuth, express.raw({ type: '*/*', limit: '25mb' }), async (req: Request, res: Response) => {
    const userId = (req as any).userId as 'person_1' | 'person_2';
    const rawBody = req.body as unknown;
    const buffer = rawBody instanceof Uint8Array
      ? Buffer.from(rawBody)
      : Buffer.isBuffer(rawBody) ? rawBody : null;
    const mimeType = String(req.headers['content-type'] || 'application/octet-stream').split(';')[0].trim().toLowerCase();
    let originalName = String(req.headers['x-synax-file-name'] || 'upload.bin').trim();
    try { originalName = decodeURIComponent(originalName); } catch {}
    if (!buffer || buffer.length === 0) return res.status(400).json({ error: 'No file uploaded.' });
    if (buffer.length > 25 * 1024 * 1024) return res.status(413).json({ error: 'Files sent through the direct upload route must be 25 MB or smaller.' });

    try {
      const objectKey = `media/${userId}/${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}${safeObjectExtension(originalName)}`;
      await cloudflareEnv.SYNAX_MEDIA.put(objectKey, new Uint8Array(buffer), {
        httpMetadata: {
          contentType: mimeType,
          contentDisposition: safeMediaContentDisposition(mimeType, originalName),
          cacheControl: 'private, max-age=3600, immutable',
        },
        customMetadata: { owner: userId, originalName: safeInlineFileName(originalName) },
      });
      return res.json({
        fileUrl: await createSignedMediaUrl(objectKey),
        fileName: safeInlineFileName(originalName),
        fileSize: buffer.length,
        mimeType,
      });
    } catch (error) {
      console.error('R2 direct upload failed:', error);
      return res.status(503).json({ error: 'File upload failed. Please retry.' });
    }
  });

  // ==========================================
  // ADMIN PANEL CONTROLS API
  // ==========================================

  // Admin Overview
  app.get('/api/admin/overview', requireAdminAuth, async (_req: Request, res: Response) => {
    const p1Time = await getPersistentTimeRemaining('person_1');
    const p2Time = await getPersistentTimeRemaining('person_2');
    const presence = await getPersistentPresenceSummary();
    const messages = await loadMessagesFromD1();

    res.json({
      users: {
        person_1: {
          ...db.users.person_1,
          passwordHash: undefined,
          timeStatus: p1Time
        },
        person_2: {
          ...db.users.person_2,
          passwordHash: undefined,
          timeStatus: p2Time
        }
      },
      settings: db.settings,
      presence,
      totalMessages: messages.length,
      logs: db.logs.slice(0, 50)
    });
  });

  // Admin: Update Identities & Passwords
  app.put('/api/admin/users', requireAdminAuth, async (req: Request, res: Response) => {
    const { person_1, person_2 } = req.body;
    for (const candidate of [person_1?.password, person_2?.password]) {
      if (typeof candidate === 'string' && candidate.trim() && candidate.trim().length < 12) {
        return res.status(400).json({ error: 'User passwords must be at least 12 characters long.' });
      }
    }

    if (person_1) {
      const u1 = db.users.person_1;
      if (person_1.name) u1.name = person_1.name;
      if (person_1.username) u1.username = person_1.username;
      if (person_1.password && person_1.password.trim().length > 0) {
        u1.passwordHash = await hashPassword(String(person_1.password));
      }
      if (person_1.logo) u1.logo = person_1.logo;
      if (person_1.allowedMinutes !== undefined) u1.allowedMinutes = Number(person_1.allowedMinutes);
    }

    if (person_2) {
      const u2 = db.users.person_2;
      if (person_2.name) u2.name = person_2.name;
      if (person_2.username) u2.username = person_2.username;
      if (person_2.password && person_2.password.trim().length > 0) {
        u2.passwordHash = await hashPassword(String(person_2.password));
      }
      if (person_2.logo) u2.logo = person_2.logo;
      if (person_2.allowedMinutes !== undefined) u2.allowedMinutes = Number(person_2.allowedMinutes);
    }

    saveDbSync();
    addLog('Admin', 'Updated Person Identities / Credentials', 'Names, logos or limits modified');
    await flushPersistence();

    broadcast({
      type: 'identities:updated',
      person_1: {
        name: db.users.person_1.name,
        logo: db.users.person_1.logo,
        allowedMinutes: db.users.person_1.allowedMinutes
      },
      person_2: {
        name: db.users.person_2.name,
        logo: db.users.person_2.logo,
        allowedMinutes: db.users.person_2.allowedMinutes
      }
    });

    res.json({ success: true, users: db.users });
  });

  // Admin: Lock / Unlock User
  app.post('/api/admin/user/:id/lock', requireAdminAuth, async (req: Request, res: Response) => {
    const userId = req.params.id as 'person_1' | 'person_2';
    const { isLocked, lockReason } = req.body;

    if (userId !== 'person_1' && userId !== 'person_2') {
      res.status(400).json({ error: 'Invalid user' });
      return;
    }

    db.users[userId].isLocked = !!isLocked;
    db.users[userId].lockReason = lockReason || undefined;

    saveDbSync();
    addLog('Admin', isLocked ? `Locked ${db.users[userId].name}` : `Unlocked ${db.users[userId].name}`, lockReason, isLocked ? 'alert' : 'info');
    await flushPersistence();
    if (isLocked) {
      try {
        await setPersistentChatPresence(userId, false);
        const sessions = await listSessionsFromD1();
        for (const session of sessions) {
          if (session.userId === userId) await deleteSessionFromD1(session.token);
        }
        await sendRealtimeAdminCommand('/revoke-user', { userId });
      } catch (error) {
        console.error('Failed to fully revoke locked SYNAX account sessions:', error);
      }
    }

    broadcast({
      type: 'user:lock_state',
      userId,
      isLocked: db.users[userId].isLocked,
      lockReason: db.users[userId].lockReason
    });

    res.json({ success: true, user: db.users[userId] });
  });

  // Admin: Reset Time / Grant Extra Time
  app.post('/api/admin/user/:id/reset-time', requireAdminAuth, async (req: Request, res: Response) => {
    const userId = req.params.id as 'person_1' | 'person_2';
    const { setMinutes, addMinutes, resetSession } = req.body;

    if (userId !== 'person_1' && userId !== 'person_2') {
      res.status(400).json({ error: 'Invalid user' });
      return;
    }

    const user = db.users[userId] as any;

    // SET EXACT LIMIT:
    // adminSetTimeLimit() sends { setMinutes: N }. The previous endpoint
    // ignored this field, so the input appeared to save but the server kept
    // the old limit. Treat setMinutes as an absolute configured limit.
    let didSetLimit = false;
    if (setMinutes !== undefined && setMinutes !== null && setMinutes !== '') {
      const parsed = Number(setMinutes);
      if (!Number.isFinite(parsed) || parsed < 1) {
        res.status(400).json({ error: 'Time limit must be at least 1 minute.' });
        return;
      }

      user.allowedMinutes = Math.max(1, Math.floor(parsed));
      didSetLimit = true;

      // Keep any in-memory session records consistent with the new configured limit.
      for (const session of Object.values(db.sessions) as any[]) {
        if (session.userId === userId) {
          session.allowedSeconds = user.allowedMinutes * 60;
          try { await saveSessionToD1(session); } catch (err) { console.error('Failed to update shared session limit:', err); }
        }
      }
    }

    // RESET CONSUMED USAGE (does not change configured limit).
    if (resetSession) {
      await resetPersistentUsage(userId);
      user.activeUsageSeconds = 0;
      user.dailyUsageSeconds = 0;
      user.dailyUsageDate = getIndiaDateKey();
      user.sessionStartTimestamp = undefined;
      user.activeSessionStartedAt = undefined;
    }

    // ADD / REMOVE TIME FROM THE CONFIGURED LIMIT.
    if (addMinutes !== undefined && addMinutes !== null) {
      const delta = Number(addMinutes);
      if (!Number.isFinite(delta)) {
        res.status(400).json({ error: 'Invalid time adjustment.' });
        return;
      }

      user.allowedMinutes = Math.max(
        1,
        Math.floor(Number(user.allowedMinutes || 60) + delta)
      );

      for (const session of Object.values(db.sessions) as any[]) {
        if (session.userId === userId) {
          session.allowedSeconds = user.allowedMinutes * 60;
          try { await saveSessionToD1(session); } catch (err) { console.error('Failed to update shared session limit:', err); }
        }
      }
    }

    saveDbSync();

    const newStatus = await getPersistentTimeRemaining(userId);

    const action = didSetLimit
      ? `Set exact limit to ${user.allowedMinutes}m`
      : `Adjusted time`;

    addLog(
      'Admin',
      `${action} for ${user.name}`,
      `Reset usage: ${!!resetSession}; Added: ${addMinutes || 0}m`
    );
    await flushPersistence();

    // Immediately push the updated authoritative timer to connected devices.
    broadcast({
      type: 'time:tick',
      userId,
      timeStatus: newStatus
    });

    // Also push the updated configured limit to identity/admin views.
    broadcast({
      type: 'identities:updated',
      person_1: {
        name: db.users.person_1.name,
        logo: db.users.person_1.logo,
        allowedMinutes: db.users.person_1.allowedMinutes
      },
      person_2: {
        name: db.users.person_2.name,
        logo: db.users.person_2.logo,
        allowedMinutes: db.users.person_2.allowedMinutes
      }
    });

    res.json({
      success: true,
      timeStatus: newStatus,
      user: {
        ...user,
        passwordHash: undefined
      }
    });
  });

  // Admin: Update App & Communication Settings
  app.put('/api/admin/settings', requireAdminAuth, async (req: Request, res: Response) => {
    const newSettings = req.body;
    if (!newSettings || typeof newSettings !== 'object' || Array.isArray(newSettings)) {
      res.status(400).json({ error: 'Invalid settings payload.' });
      return;
    }
    for (const nestedKey of ['restrictionsOnExpire', 'featuresEnabled'] as const) {
      const value = newSettings[nestedKey];
      if (value !== undefined && (!value || typeof value !== 'object' || Array.isArray(value))) {
        res.status(400).json({ error: `Invalid ${nestedKey} settings.` });
        return;
      }
    }

    db.settings = {
      ...db.settings,
      ...newSettings,
      restrictionsOnExpire: {
        ...db.settings.restrictionsOnExpire,
        ...(newSettings.restrictionsOnExpire || {})
      },
      featuresEnabled: {
        ...db.settings.featuresEnabled,
        ...(newSettings.featuresEnabled || {})
      }
    };

    saveDbSync();
    addLog('Admin', 'Settings Updated', 'Appearance, time rules or communication features updated');
    await flushPersistence();

    res.setHeader('Cache-Control', 'no-store, max-age=0');
    broadcast({
      type: 'settings:updated',
      settings: db.settings
    });

    res.json({ success: true, settings: db.settings });
  });

  // Admin: Read messages and active sessions without user-only auth.
  app.get('/api/admin/messages', requireAdminAuth, async (_req: Request, res: Response) => {
    try {
      const messages = await loadMessagesFromD1();
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.json({ messages });
    } catch (err) {
      console.error('Failed to load admin messages:', err);
      res.status(503).json({
        error: 'Chat storage temporarily unavailable.',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.get('/api/admin/sessions', requireAdminAuth, async (_req: Request, res: Response) => {
    try {
      const sessions = (await listSessionsFromD1()).map((s: any) => ({
        userId: s.userId,
        sessionStart: s.sessionStart,
        lastActive: s.lastActive,
        allowedSeconds: s.allowedSeconds,
        isExpired: s.isExpired,
        active: Boolean(s.active),
      }));
      res.json({ sessions });
    } catch (err) {
      console.error('Failed to list shared sessions:', err);
      res.status(503).json({ sessions: [], error: 'Session service temporarily unavailable' });
    }
  });

  // Admin: Factory reset. Restores default identities/settings/chat/time and keeps the admin logged in.
  app.post('/api/admin/reset-defaults', requireAdminAuth, async (_req: Request, res: Response) => {
    const currentAdminSessions = Object.values(db.sessions).filter((s: any) => s.userId === 'admin');
    const fresh = await getInitialDb();
    db = fresh;
    await clearMessagesInD1(db.messages);
    await resetPersistentUsage('person_1');
    await resetPersistentUsage('person_2');
    for (const s of currentAdminSessions) {
      db.sessions[s.token] = s;
    }
    saveDbSync();
    for (const s of currentAdminSessions) {
      try { await saveSessionToD1(s as any); } catch (err) { console.error('Failed to preserve admin session:', err); }
    }
    await flushPersistence();
    broadcast({ type: 'settings:updated', settings: db.settings });
    broadcast({ type: 'identities:updated', person_1: db.users.person_1, person_2: db.users.person_2 });
    broadcast({ type: 'chat:history_cleared' });
    for (const id of ['person_1', 'person_2'] as const) {
      void getPersistentTimeRemaining(id).then((timeStatus) => broadcast({ type: 'time:tick', userId: id, timeStatus })).catch(() => undefined);
    }
    res.json({ success: true, settings: db.settings });
  });

  // Admin: Clear Chat History
  app.post('/api/admin/messages/clear', requireAdminAuth, async (_req: Request, res: Response) => {
    const freshSystemMessage = {
      id: `msg_clr_${Date.now()}`,
      senderId: 'system',
      type: 'system',
      text: '✦ Chat history was cleared by the Administrator. A fresh chapter begins.',
      timestamp: Date.now(),
      status: 'read',
      reactions: {}
    };
    try {
      await clearMessagesInD1([freshSystemMessage]);
      db.messages = [freshSystemMessage];
      addLog('Admin', 'Chat History Cleared', 'All previous messages purged');
      await flushPersistence();
      broadcast({ type: 'chat:history_cleared' });
      res.json({ success: true });
    } catch (err) {
      console.error('Failed to clear messages:', err);
      res.status(503).json({
        error: 'Chat storage temporarily unavailable.',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Admin: View Audit Logs
  app.get('/api/admin/logs', requireAdminAuth, (_req: Request, res: Response) => {
    res.json({ logs: db.logs });
  });

  // Admin: Change Administrator Password
  app.post('/api/admin/change-password', requireAdminAuth, async (req: Request, res: Response) => {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || typeof newPassword !== 'string' || newPassword.trim().length < 12) {
      res.status(400).json({ error: 'New password must be at least 12 characters long.' });
      return;
    }

    if (!await verifyPassword(currentPassword || '', db.admin.passwordHash)) {
      res.status(401).json({ error: 'Current administrator password is incorrect.' });
      return;
    }

    db.admin.passwordHash = await hashPassword(newPassword.trim());
    saveDbSync();
    addLog('Admin', 'Password Changed', 'Master administrator password successfully updated');
    await flushPersistence();
    res.json({ success: true });
  });

  // Never let Express turn API exceptions into an HTML error page. The React
  // client expects JSON from /api/*; returning HTML causes errors such as
  // "Unexpected token '<'" when the client calls response.json().
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('SYNAX API unhandled error:', err);
    if (req.path === '/api' || req.path.startsWith('/api/')) {
      if (res.headersSent) return next(err);
      const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
      res.status(status).json({
        error: 'SYNAX API request failed.',
        detail: err instanceof Error ? err.message : String(err || 'Unknown server error'),
      });
      return;
    }
    next(err);
  });

  // Cloudflare Worker serves the SPA static assets independently.
  // This Express server is used only for the API routes.
  return http.createServer(app);
}

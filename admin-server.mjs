/**
 * 勿改名为 server.mjs：Vercel Express 检测器会同时匹配根目录 index.mjs 与 server.mjs，
 * 导致双入口构建并触发 CLI 报错（如 reading 'fsPath'）。
 */
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, '.env'), override: true });

const port = Number(process.env.LOCAL_BACKEND_PORT || 8787);
const allowOrigin = process.env.LOCAL_BACKEND_ORIGIN || 'http://localhost:5173';
const supabaseUrl = String(process.env.SUPABASE_URL || '').trim();
const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const llmBaseUrl = String(process.env.VLLM_BASE_URL || '').trim().replace(/\/+$/, '');
const llmApiKey = String(process.env.VLLM_API_KEY || '').trim();
const llmModelId = String(process.env.VLLM_MODEL_ID || '').trim();
const INTERNAL_TEST_EMAILS = new Set([
  'liumengyu594@gmail.com',
  'service@tangbuy.net',
  'eriahhhhh@gmail.com',
  'sinslust@163.com',
  'arhuhibegu08666@gmail.com',
  'leocarnon@gmail.com',
  'dorammamazing@gmail.com',
  'g31jess@gmail.com',
  'llinweiran@gmail.com',
  'doravm9413@gmail.com',
  '4577368@gmail.com',
]);

if (!supabaseUrl || !serviceRoleKey) {
  console.error('[backend-local] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');

}

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const app = express();
app.use(cors({ origin: allowOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));

const ADMIN_SESSION_COOKIE = 'tb_admin_session';
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const ADMIN_SESSION_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const ADMIN_SESSION_SECRET = String(
  process.env.ADMIN_SESSION_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY || '',
).trim();

function parseCookies(req) {
  const raw = String(req.headers?.cookie || '');
  const out = {};
  if (!raw) return out;
  for (const token of raw.split(';')) {
    const idx = token.indexOf('=');
    if (idx <= 0) continue;
    const k = token.slice(0, idx).trim();
    const v = token.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v || '');
  }
  return out;
}

function toBase64Url(input) {
  return Buffer.from(input).toString('base64url');
}

function fromBase64Url(input) {
  return Buffer.from(input, 'base64url').toString('utf8');
}

function signAdminSession(payload) {
  const body = toBase64Url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', ADMIN_SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyAdminSession(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', ADMIN_SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload = null;
  try {
    payload = JSON.parse(fromBase64Url(body));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (!payload.exp || Date.now() > Number(payload.exp)) return null;
  if (!payload.u) return null;
  return payload;
}

function makeSessionCookieValue(token, maxAgeMs) {
  const attrs = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (process.env.VERCEL === '1') attrs.push('Secure');
  if (maxAgeMs > 0) attrs.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  return attrs.join('; ');
}

function clearSessionCookieValue() {
  const attrs = [`${ADMIN_SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (process.env.VERCEL === '1') attrs.push('Secure');
  return attrs.join('; ');
}

function verifyScryptPassword(rawPassword, storedHash) {
  const password = String(rawPassword || '');
  const hashText = String(storedHash || '');
  const [algo, salt, digest] = hashText.split('$');
  if (algo !== 'scrypt' || !salt || !digest) return false;
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(derived, 'hex');
  const b = Buffer.from(digest, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function requireAdminAuth(req, res, next) {
  try {
    const cookies = parseCookies(req);
    const token = cookies[ADMIN_SESSION_COOKIE];
    const payload = verifyAdminSession(token);
    if (!payload) return res.status(401).json({ ok: false, error: 'Admin auth required', code: 'ADMIN_AUTH_REQUIRED' });
    const username = String(payload.u || '').trim();
    const { data, error } = await supabase
      .from('admin_accounts')
      .select('username, is_active')
      .eq('username', username)
      .limit(1)
      .maybeSingle();
    if (error || !data?.username || data.is_active === false) {
      return res.status(401).json({ ok: false, error: 'Admin auth required', code: 'ADMIN_AUTH_REQUIRED' });
    }
    req.adminUser = { username: data.username };
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Admin auth required', code: 'ADMIN_AUTH_REQUIRED' });
  }
}

// Vercel：HTML 放在 public/admin/ 由 CDN 提供；函数内无物理文件，sendFile 会 404。用 302 指到静态 URL。
if (process.env.VERCEL === '1') {
  app.get('/', (_req, res) => res.redirect(302, '/admin/index.html'));
  app.get('/admin', (_req, res) => res.redirect(302, '/admin/index.html'));
  app.get('/admin/', (_req, res) => res.redirect(302, '/admin/index.html'));
}

function normalizeTrendsPayload(data) {
  if (Array.isArray(data)) return data;
  if (data == null) return [];
  if (typeof data === 'string') {
    try {
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isInternalTestEmail(email) {
  return INTERNAL_TEST_EMAILS.has(normalizeEmail(email));
}

function clampDays(inputDays) {
  return Math.max(1, Math.min(365, Number(inputDays) || 30));
}

/** 随仓库打包的只读 schema；Vercel 上不可写盘，刷新时写入 /tmp（仅当次实例有效） */
const nlqSchemaBundledPath = path.join(__dirname, 'admin_nlq_schema.md');
const nlqSchemaPersistPath =
  process.env.VERCEL === '1' ? path.join('/tmp', 'admin_nlq_schema.md') : nlqSchemaBundledPath;
let nlqSchemaText = (() => {
  try {
    return fs.readFileSync(nlqSchemaBundledPath, 'utf8');
  } catch {
    return '';
  }
})();

function tryReloadNlqSchemaFromFile() {
  try {
    const text = fs.readFileSync(nlqSchemaBundledPath, 'utf8');
    if (String(text || '').trim()) nlqSchemaText = text;
  } catch (_) {}
}

function tableRank(tableName) {
  const key = String(tableName || '').toLowerCase();
  const priority = [
    'users',
    'user_stats',
    'user_prompt_logs',
    'share_links',
    'share_link_visits',
    'share_link_oauth_attributions',
    'ai_model_reply_logs',
  ];
  const idx = priority.indexOf(key);
  return idx >= 0 ? idx : priority.length + 1;
}

function buildSchemaMarkdownFromRows(rows) {
  const arr = Array.isArray(rows) ? rows : [];
  const grouped = new Map();
  for (const r of arr) {
    const schema = String(r?.table_schema || '').trim();
    const table = String(r?.table_name || '').trim();
    const col = String(r?.column_name || '').trim();
    const type = String(r?.data_type || '').trim();
    if (!schema || !table || !col) continue;
    const key = `${schema}.${table}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push({ col, type });
  }

  const keys = Array.from(grouped.keys()).sort((a, b) => {
    const [sa, ta] = a.split('.');
    const [sb, tb] = b.split('.');
    const ra = tableRank(ta);
    const rb = tableRank(tb);
    if (ra !== rb) return ra - rb;
    if (sa !== sb) return sa.localeCompare(sb);
    return ta.localeCompare(tb);
  });

  const lines = [
    '# Admin NLQ Schema (auto-generated)',
    '',
    `Updated at: ${new Date().toISOString()}`,
    '',
    'Use this schema to answer admin natural-language questions by generating SELECT SQL only.',
    '',
    '## Tables',
    '',
  ];
  for (const key of keys) {
    lines.push(`- \`${key}\``);
    for (const c of grouped.get(key) || []) {
      lines.push(`  - \`${c.col}\` ${c.type}`);
    }
    lines.push('');
  }

  lines.push('## SQL Rules', '');
  lines.push('1. SELECT/CTE only, no DML/DDL.');
  lines.push('2. Relative dates (today/yesterday/last N days) use Asia/Shanghai (UTC+8).');
  lines.push('3. For list/detail requests, avoid random single row; use aggregation or explicit ordering.');
  lines.push('');
  return lines.join('\n');
}

async function recallSqlFromMemory(question) {
  const normalized = normalizeQuestionForMemory(question);
  if (!normalized) return null;
  try {
    const exact = await supabase
      .from('nlq_query_memory')
      .select('id, question, normalized_question, sql_text, success_count, last_used_at')
      .eq('normalized_question', normalized)
      .limit(1)
      .maybeSingle();
    if (!exact.error && exact.data?.sql_text) {
      return { ...exact.data, match_score: 1, match_type: 'exact' };
    }
  } catch (_) {}

  try {
    const cand = await supabase
      .from('nlq_query_memory')
      .select('id, question, normalized_question, sql_text, success_count, last_used_at')
      .order('last_used_at', { ascending: false })
      .limit(120);
    if (cand.error || !Array.isArray(cand.data) || cand.data.length === 0) return null;
    const qTokens = tokenizeQuestion(question);
    let best = null;
    for (const row of cand.data) {
      const score = jaccardSimilarity(qTokens, tokenizeQuestion(row.normalized_question || row.question || ''));
      if (score < 0.35) continue;
      if (!best || score > best.match_score) {
        best = { ...row, match_score: score, match_type: 'similar' };
      }
    }
    return best;
  } catch (_) {
    return null;
  }
}

async function touchMemoryHit(id) {
  if (!id) return;
  try {
    const now = new Date().toISOString();
    const { data } = await supabase.from('nlq_query_memory').select('success_count').eq('id', id).limit(1).maybeSingle();
    const successCount = Math.max(1, Number(data?.success_count) || 1) + 1;
    await supabase
      .from('nlq_query_memory')
      .update({ success_count: successCount, last_used_at: now })
      .eq('id', id);
  } catch (_) {}
}

/** Stored in nlq_query_memory.sql_text when the NLQ path was RPC (not admin_execute_select_sql). */
const NLQ_RPC_MEMORY_PREFIX = '__NLQ_RPC__:';

function buildNlqRpcMemoryText(rpc, args) {
  const r = String(rpc || '').trim();
  if (!r) return '';
  const a = args && typeof args === 'object' ? args : {};
  return `${NLQ_RPC_MEMORY_PREFIX}${JSON.stringify({ rpc: r, args: a })}`;
}

async function upsertMemorySql(question, sql) {
  const normalized = normalizeQuestionForMemory(question);
  if (!normalized || !sql) return;
  try {
    const now = new Date().toISOString();
    const existing = await supabase
      .from('nlq_query_memory')
      .select('id, success_count')
      .eq('normalized_question', normalized)
      .limit(1)
      .maybeSingle();
    if (!existing.error && existing.data?.id) {
      const successCount = Math.max(1, Number(existing.data.success_count) || 1) + 1;
      await supabase
        .from('nlq_query_memory')
        .update({
          question,
          sql_text: sql,
          success_count: successCount,
          last_used_at: now,
        })
        .eq('id', existing.data.id);
      return;
    }
    await supabase
      .from('nlq_query_memory')
      .insert({
        question,
        sql_text: sql,
        normalized_question: normalized,
        success_count: 1,
        last_used_at: now,
      });
  } catch (_) {}
}

function sanitizeNlqQuestion(q) {
  return String(q || '').replace(/\s+/g, ' ').trim().slice(0, 500);
}

function normalizeQuestionForMemory(q) {
  return String(q || '')
    .toLowerCase()
    .replace(/[，。！？、,.!?;:：]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);
}

function tokenizeQuestion(q) {
  const base = normalizeQuestionForMemory(q);
  const parts = base
    .split(' ')
    .map((x) => x.trim())
    .filter((x) => x.length >= 2);
  const cjkOnly = base.replace(/\s+/g, '');
  for (let i = 0; i < cjkOnly.length - 1; i += 1) {
    const bg = cjkOnly.slice(i, i + 2);
    if (bg.length === 2) parts.push(bg);
  }
  return parts;
}

function jaccardSimilarity(aTokens, bTokens) {
  const a = new Set(aTokens);
  const b = new Set(bTokens);
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter += 1;
  const union = a.size + b.size - inter;
  return union > 0 ? inter / union : 0;
}

function parseNlqDecision(text) {
  const raw = String(text || '').trim();
  const cleaned = raw
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try {
      return JSON.parse(m[0]);
    } catch {
      return null;
    }
  }
}

async function askLlmForSql(question, historyTurns = []) {
  if (!llmBaseUrl || !llmApiKey || !llmModelId) {
    throw new Error('Missing VLLM_BASE_URL / VLLM_API_KEY / VLLM_MODEL_ID for NLQ');
  }
  tryReloadNlqSchemaFromFile();
  const system = [
    'You are a strict Text-to-SQL planner for a Supabase admin backend.',
    'Output JSON only. No markdown, no code fence, no comments.',
    'Generate ONE SELECT/CTE SQL statement for PostgreSQL.',
    'Never output INSERT/UPDATE/DELETE/DDL.',
    'If question is unsafe/out-of-scope, return {"mode":"reject","reason":"..."}',
    'If user asks for emails/list/details, do not return one random email.',
    'Use array_agg/jsonb_agg/string_agg to return all matched emails (or clear top-N with explicit order and limit).',
    'For today registrations + emails, return both count and full email list in one row.',
    'For relative dates like today/yesterday/last N days, use Asia/Shanghai (UTC+8).',
    'For anonymous-user related questions, use start boundary from yesterday 00:00 Asia/Shanghai unless explicitly overridden by the user.',
    '',
    'Schema:',
    nlqSchemaText || '(schema text unavailable)',
  ].join('\n');
  const history = historyTurns
    .slice(-MAX_NLQ_TURNS)
    .map((t, i) => {
      const q = String(t?.question || '').slice(0, 220);
      const a = String(t?.action || '').slice(0, 220);
      return `${i + 1}. Q: ${q}\n   Action: ${a}`;
    })
    .join('\n');
  const user = `Conversation context:
${history || '(empty)'}

Latest question: ${question}
Return format:
{"mode":"sql","sql":"SELECT ...","explanation":"short"}
OR {"mode":"rpc","rpc":"admin_overview","args":{"p_days":30},"explanation":"short"}
OR {"mode":"reject","reason":"..."}
Strictly return a single valid JSON object only.
`;
  const maxAttempts = 2;
  let lastRaw = '';
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const payload = {
      model: llmModelId,
      stream: false,
      temperature: attempt === 1 ? 0.1 : 0,
      max_tokens: attempt === 1 ? 1000 : 1200,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    };
    const res = await fetch(`${llmBaseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${llmApiKey}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`LLM upstream ${res.status}: ${text.slice(0, 300)}`);
    }
    const data = await res.json();
    const content = String(data?.choices?.[0]?.message?.content || '');
    lastRaw = content;
    const decision = parseNlqDecision(content);
    if (decision && typeof decision === 'object') return decision;
  }
  const preview = String(lastRaw || '').slice(0, 240);
  throw new Error(`Failed to parse LLM SQL decision (invalid JSON). preview=${preview}`);
}

function parseAnswerMarkdown(text) {
  const s = String(text || '').trim();
  if (!s) return '';
  try {
    const parsed = JSON.parse(s);
    if (parsed && typeof parsed === 'object' && typeof parsed.answer_markdown === 'string') {
      return String(parsed.answer_markdown || '').trim();
    }
  } catch (_) {}
  return s;
}

function normalizeNarrativeMarkdown(text) {
  const s = String(text || '').trim();
  if (!s) return '';
  const cleaned = s
    .split('\n')
    .filter((line) => !/^\s{0,3}#{1,6}\s+/.test(line))
    .join('\n')
    .replace(/\n[ \t]+\n/g, '\n\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return cleaned;
}

async function askLlmForAnswerMarkdown(question, rows) {
  if (!llmBaseUrl || !llmApiKey || !llmModelId) return '';
  const safeRows = Array.isArray(rows) ? rows.slice(0, 30) : [];
  const system = [
    'You are a data analyst assistant for an admin dashboard.',
    'Write concise Chinese markdown for business users.',
    'Do not expose raw field names unless unavoidable.',
    'Use readable labels and interpretation.',
    'Do not output markdown headings (#, ##, ###).',
    'Output in plain markdown paragraphs/lists only: overall performance + key metrics + brief interpretation.',
    'Output JSON only: {"answer_markdown":"..."}',
  ].join('\n');
  const user = [
    `用户问题：${question}`,
    `查询结果(JSON)：${JSON.stringify(safeRows)}`,
    '请输出：',
    '1) 整体表现（1-2句）',
    '2) 具体指标说明（markdown 列表）',
    '3) 解读（1句，可选）',
    '不要加任何标题。',
  ].join('\n');
  const payload = {
    model: llmModelId,
    stream: false,
    temperature: 0.2,
    max_tokens: 700,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
  };
  try {
    const res = await fetch(`${llmBaseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${llmApiKey}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return '';
    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content || '';
    return normalizeNarrativeMarkdown(parseAnswerMarkdown(content));
  } catch (_) {
    return '';
  }
}

const allowedNlqRpc = new Set([
  'admin_overview',
  'admin_trends',
  'admin_conversation_usage',
  'admin_share_insights',
  'admin_share_list',
  'admin_url_inputs',
  'admin_prompt_logs_by_email',
  'admin_users',
]);

const nlqSessions = new Map();
const MAX_NLQ_SESSIONS = 200;
const MAX_NLQ_TURNS = 8;

function createNlqSessionId() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `nlq_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function sanitizeSessionId(v) {
  const id = String(v || '').trim();
  if (!id) return '';
  return id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
}

function sqlQuote(value) {
  return `'${String(value ?? '').replace(/'/g, "''")}'`;
}

function getNlqSessionTurns(sessionId) {
  const turns = nlqSessions.get(sessionId);
  return Array.isArray(turns) ? turns : [];
}

function appendNlqTurn(sessionId, turn) {
  const turns = getNlqSessionTurns(sessionId);
  turns.push(turn);
  if (turns.length > MAX_NLQ_TURNS) turns.splice(0, turns.length - MAX_NLQ_TURNS);
  nlqSessions.set(sessionId, turns);
  if (nlqSessions.size > MAX_NLQ_SESSIONS) {
    const first = nlqSessions.keys().next();
    if (!first.done) nlqSessions.delete(first.value);
  }
}

function buildNlqAnswerText(question, rows) {
  const q = String(question || '').trim();
  const arr = Array.isArray(rows) ? rows : [];
  if (arr.length === 0) return `针对“${q}”，未查询到数据。`;

  const first = arr[0];
  if (first && typeof first === 'object' && !Array.isArray(first)) {
    if (
      first.conversations_with_urls != null &&
      first.records_with_urls != null &&
      first.unique_urls != null &&
      first.url_list != null
    ) {
      const urls = Array.isArray(first.url_list) ? first.url_list : [];
      const listText = urls.length ? urls.map((u) => `- ${u}`).join('\n') : '- 无';
      return [
        `输入过网址的对话数：${first.conversations_with_urls}`,
        `包含网址的对话记录数：${first.records_with_urls}`,
        `涉及的网址数量：${first.unique_urls}`,
        '网址列表：',
        listText,
      ].join('\n');
    }
    if (first.email_users != null && first.anonymous_users != null) {
      return `邮箱用户：${first.email_users}\n匿名用户：${first.anonymous_users}`;
    }
    if (first.anonymous_active_3d_users != null) {
      return `匿名用户连续三天活跃人数：${first.anonymous_active_3d_users}`;
    }
    if (first.today_anonymous_users != null) {
      const ids = Array.isArray(first.today_anonymous_users)
        ? first.today_anonymous_users
        : String(first.today_anonymous_users || '')
            .split(/[;,，、\s]+/)
            .filter(Boolean);
      return `今日使用产品的匿名用户：${ids.length ? ids.join('、') : '无'}`;
    }
    if (
      first.top_user != null &&
      first.total_prompts != null &&
      first.avg_daily_prompts != null
    ) {
      return `使用对话最多的用户是：${first.top_user}\n使用次数：${first.total_prompts}\n平均每日使用次数：${first.avg_daily_prompts}`;
    }
    const countVal = first.today_registered_count ?? first.registered_count ?? first.total_users ?? first.count;
    const emailsVal = first.today_registered_emails ?? first.registered_emails ?? first.emails ?? first.email_list;
    if ((/今日|今天/.test(q) && /注册/.test(q) && /邮箱/.test(q)) || (countVal != null && emailsVal != null)) {
      const emails = Array.isArray(emailsVal)
        ? emailsVal.filter((x) => String(x || '').trim())
        : String(emailsVal || '')
            .split(/[;,，、\s]+/)
            .filter((x) => String(x || '').trim());
      const count = Number.isFinite(Number(countVal)) ? Number(countVal) : emails.length;
      const emailText = emails.length ? emails.join('、') : '无';
      return `今日注册用户数：${count}\n邮箱为：${emailText}`;
    }
    const keys = Object.keys(first);
    if (keys.length === 1) {
      const k = keys[0];
      const v = first[k];
      const singleAlias = {
        yesterday_new_users: '昨日新增用户数',
        today_registered_count: '今日注册用户数',
        total_users: '累计注册用户数',
        count: '数量',
      };
      if (/累计|总|total/i.test(q) && /注册|用户/i.test(q)) {
        return `截止当前累计注册用户数为：${v}`;
      }
      return `${singleAlias[k] || '查询结果'}：${v}`;
    }
    const keyAlias = {
      email: '邮箱',
      user_email: '邮箱',
      user_identity: '用户',
      top_user: '用户',
      date: '日期',
      created_at: '时间',
      count: '数量',
      total: '总数',
      total_users: '总用户数',
      total_prompts: '使用次数',
      avg_daily_prompts: '平均每日使用次数',
      yesterday_new_users: '昨日新增用户数',
      today_registered_count: '今日注册用户数',
      today_registered_emails: '邮箱',
    };
    const formatValue = (v) => {
      if (v == null) return '无';
      if (Array.isArray(v)) return v.map((x) => String(x)).join('、') || '无';
      if (typeof v === 'object') return JSON.stringify(v);
      return String(v);
    };
    const lines = arr.slice(0, 20).map((row) => {
      if (!row || typeof row !== 'object' || Array.isArray(row)) return String(row);
      return Object.entries(row)
        .map(([k, v]) => `${keyAlias[k] || k}：${formatValue(v)}`)
        .join('\n');
    });
    const head = `共查询到 ${arr.length} 条记录：`;
    return `${head}\n${lines.join('\n\n')}`;
  }
  return `针对“${q}”，查询结果为：${String(first)}`;
}

function questionWantsDetailList(question) {
  const q = String(question || '');
  return /明细|清单|列表|都有谁|分别|逐条|详情|详细/.test(q);
}

function rowToDetailLine(row) {
  if (row == null) return '';
  if (typeof row !== 'object' || Array.isArray(row)) return String(row);
  const entries = Object.entries(row);
  if (entries.length === 0) return '';
  const fmtTs = (raw) => {
    if (!raw) return '';
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) return String(raw);
    return new Intl.DateTimeFormat('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(d);
  };
  const keyMap = {
    email: '邮箱',
    is_anonymous: '用户类型',
    is_vip: 'VIP用户',
    user_id: '用户ID',
    total_urls: '网址数量',
    prompt_with_urls_count: '含网址提问次数',
    prompt_count: '提问次数',
    website_urls: '涉及网址',
    first_mention_at: '首次提及（北京时间）',
    last_mention_at: '最近提及（北京时间）',
  };
  const lines = [];
  for (const [k, v] of entries) {
    const label = keyMap[k] || k;
    if (k === 'is_anonymous') {
      lines.push(`${label}：${v ? '匿名用户' : '已授权用户'}`);
      continue;
    }
    if (k === 'is_vip') {
      lines.push(`${label}：${v ? '是' : '否'}`);
      continue;
    }
    if (k === 'email') {
      lines.push(`${label}：${v ? String(v) : '匿名用户（未绑定邮箱）'}`);
      continue;
    }
    if (k === 'first_mention_at' || k === 'last_mention_at') {
      lines.push(`${label}：${fmtTs(v)}`);
      continue;
    }
    if (Array.isArray(v)) {
      lines.push(`${label}：${v.length ? v.map((x) => String(x)).join('、') : '无'}`);
      continue;
    }
    if (v && typeof v === 'object') {
      lines.push(`${label}：${JSON.stringify(v)}`);
      continue;
    }
    lines.push(`${label}：${String(v ?? '')}`);
  }
  return lines.join('\n');
}

function appendDetailListIfNeeded(question, rows, narrative) {
  if (!questionWantsDetailList(question)) return String(narrative || '');
  const arr = Array.isArray(rows) ? rows : [];
  const lines = [];
  for (const row of arr) {
    if (!row || typeof row !== 'object') continue;
    const vals = Object.values(row);
    for (const v of vals) {
      if (Array.isArray(v)) {
        for (const item of v) {
          const s = String(item || '').trim();
          if (s) lines.push(s);
        }
      } else {
        const s = rowToDetailLine(row).trim();
        if (s) lines.push(s);
        break;
      }
    }
  }
  const uniq = Array.from(new Set(lines)).filter(Boolean).slice(0, 200);
  if (uniq.length === 0) return String(narrative || '');
  const listText = uniq.map((x) => `- ${x}`).join('\n');
  const prefix = String(narrative || '').trim();
  return `${prefix ? `${prefix}\n\n` : ''}明细清单：\n${listText}`;
}

function matchPresetQuestion(question) {
  const q = String(question || '');
  if ((/累计/.test(q) && /用户|注册/.test(q)) || /累计注册了多少用户/.test(q)) {
    return 'cumulative_user_split';
  }
  if ((/今日|今天/.test(q) && /注册/.test(q) && /邮箱/.test(q)) || /today.*register.*email/i.test(q)) {
    return 'today_registered_count_and_emails';
  }
  if ((/使用|对话/.test(q) && /最多|最高|top/.test(q) && /平均每日|日均/.test(q)) || /top.*user.*daily/i.test(q)) {
    return 'top_user_prompts_with_daily_avg';
  }
  if (/匿名/.test(q) && /连续三天/.test(q) && /活跃/.test(q)) {
    return 'anonymous_active_3d_users';
  }
  if (/今日|今天/.test(q) && /匿名/.test(q) && /用户|都有谁|名单/.test(q)) {
    return 'today_anonymous_user_list';
  }
  if ((/多少对话|多少个对话/.test(q) && /网址|链接/.test(q) && /列表|清单/.test(q)) || (/网址列表/.test(q) && /对话/.test(q))) {
    return 'url_conversation_counts_and_list';
  }
  return '';
}

/**
 * Paginated fetch of all Auth users (local admin only). Used when SQL RPCs are missing.
 */
async function fetchAllAuthUsersForAdmin(options = {}) {
  const excludeInternal = options.excludeInternal === true;
  const createdAtGteIso = String(options.createdAtGteIso || '').trim();
  const allUsers = [];
  let p = 1;
  const perFetch = 200;
  while (p <= 200) {
    const { data, error } = await supabase.auth.admin.listUsers({ page: p, perPage: perFetch });
    if (error) throw new Error(error.message);
    const batch = data?.users || [];
    if (batch.length === 0) break;
    allUsers.push(...batch);
    if (batch.length < perFetch) break;
    p += 1;
  }
  let users = allUsers;
  if (createdAtGteIso) {
    const minTs = new Date(createdAtGteIso).getTime();
    if (!Number.isNaN(minTs)) {
      users = users.filter((u) => new Date(u.created_at || 0).getTime() >= minTs);
    }
  }
  if (excludeInternal) {
    users = users.filter((u) => !isInternalTestEmail(u.email));
  }
  return users;
}

async function countDistinctAnonymousVisitors() {
  const seen = new Set();
  const pageSize = 1000;
  let offset = 0;
  for (;;) {
    const { data, error } = await supabase
      .from('share_link_visits')
      .select('visitor_user_id, visitor_email, created_at')
      .eq('visitor_is_anonymous', true)
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);
    if (error) throw new Error(error.message || 'query share_link_visits failed');
    const rows = Array.isArray(data) ? data : [];
    if (rows.length === 0) break;
    for (const r of rows) {
      const uid = String(r?.visitor_user_id || '').trim().toLowerCase();
      const em = normalizeEmail(r?.visitor_email || '');
      if (uid) {
        seen.add(`uid:${uid}`);
      } else if (em) {
        seen.add(`em:${em}`);
      }
    }
    if (rows.length < pageSize) break;
    offset += pageSize;
    if (offset > 300000) break;
  }
  return seen.size;
}

async function loadVipUserIdSet() {
  const vip = new Set();
  const { data: statsRows, error } = await supabase.from('user_stats').select('user_id, is_vip');
  if (error) {
    console.warn('[admin] user_stats read (vip set):', error.message);
    return vip;
  }
  for (const row of statsRows || []) {
    if (row?.user_id && row.is_vip) vip.add(String(row.user_id));
  }
  return vip;
}

/** Resolve user_id → email / anonymous for admin model-reply rows (batched getUserById). */
async function mapUserIdsToAuthInfo(userIds) {
  const unique = [...new Set((userIds || []).map((id) => String(id || '').trim()).filter(Boolean))];
  const map = new Map();
  await Promise.all(
    unique.map(async (uid) => {
      try {
        const { data, error } = await supabase.auth.admin.getUserById(uid);
        if (error || !data?.user) {
          map.set(uid, { email: '', is_anonymous: false });
          return;
        }
        const u = data.user;
        map.set(uid, {
          email: String(u.email || '').trim(),
          is_anonymous: !!u.is_anonymous,
        });
      } catch (_) {
        map.set(uid, { email: '', is_anonymous: false });
      }
    }),
  );
  return map;
}

async function buildOverviewFallback() {
  const users = await fetchAllAuthUsersForAdmin({
    excludeInternal: false,
  });
  const vipSet = await loadVipUserIdSet();
  const now = Date.now();
  const d7 = now - 7 * 86400000;
  const d30 = now - 30 * 86400000;
  const merged = users.filter((u) => !u.is_anonymous);
  const total_users = merged.length;
  const vip_users = merged.filter((u) => vipSet.has(String(u.id))).length;
  const vip_ratio = total_users === 0 ? 0 : Math.round((vip_users / total_users) * 10000) / 100;
  const new_users_7d = merged.filter((u) => new Date(u.created_at || 0).getTime() >= d7).length;
  const new_users_30d = merged.filter((u) => new Date(u.created_at || 0).getTime() >= d30).length;

  // Today's new users (Shanghai timezone)
  const todayShanghai = new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const todayStart = new Date(todayShanghai + ' 00:00:00');
  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);
  const new_users_today = merged.filter((u) => new Date(u.created_at || 0).getTime() >= todayStart.getTime()).length;
  const yesterday_new_users = merged.filter((u) => {
    const ts = new Date(u.created_at || 0).getTime();
    return ts >= yesterdayStart.getTime() && ts < todayStart.getTime();
  }).length;

  // Anonymous visitors from share_link_visits (distinct users, not visit rows)
  let total_anon_visitors = 0;
  try {
    total_anon_visitors = await countDistinctAnonymousVisitors();
  } catch (e) {
    console.warn('[admin] anon visitors count:', e?.message);
  }

  // Share attributed emails (from oauth_attributions)
  let share_attributed_emails = 0;
  try {
    const { data: attrData, error: attrErr } = await supabase
      .from('share_link_oauth_attributions')
      .select('id', { count: 'exact', head: true });
    if (!attrErr) share_attributed_emails = attrData?.count || 0;
  } catch (e) {
    console.warn('[admin] share attributed emails count:', e?.message);
  }

  // Inquiry stats
  let total_inquiries = 0;
  let replied_inquiries = 0;
  let inquiries_today = 0;
  try {
    const { data: inqData, error: inqErr } = await supabase
      .from('product_inquiries')
      .select('id, status, created_at', { count: 'exact' });
    if (!inqErr && inqData) {
      total_inquiries = inqData.length;
      replied_inquiries = inqData.filter((r) => r.status === 'replied').length;
      inquiries_today = inqData.filter((r) => new Date(r.created_at).getTime() >= todayStart.getTime()).length;
    }
  } catch (e) {
    console.warn('[admin] inquiries count:', e?.message);
  }

  return {
    total_users,
    vip_users,
    vip_ratio,
    new_users_7d,
    new_users_30d,
    new_users_today,
    yesterday_new_users,
    total_anon_visitors,
    share_attributed_emails,
    total_inquiries,
    replied_inquiries,
    inquiries_today,
    _source: 'auth_admin_fallback',
  };
}

async function buildUserTrendsFallback(days) {
  const n = Math.max(1, Math.min(365, Number(days) || 30));
  const users = await fetchAllAuthUsersForAdmin({
    excludeInternal: false,
  });
  const vipSet = await loadVipUserIdSet();
  const end = new Date();
  const endUtc = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate()));
  const startUtc = new Date(endUtc);
  startUtc.setUTCDate(startUtc.getUTCDate() - (n - 1));
  const dayMap = new Map();
  for (let i = 0; i < n; i += 1) {
    const d = new Date(startUtc);
    d.setUTCDate(d.getUTCDate() + i);
    const k = d.toISOString().slice(0, 10);
    dayMap.set(k, { date: k, new_users: 0, new_vip_users: 0 });
  }
  for (const u of users) {
    const ts = new Date(u.created_at || 0).getTime();
    if (Number.isNaN(ts)) continue;
    const day = new Date(ts).toISOString().slice(0, 10);
    const row = dayMap.get(day);
    if (!row) continue;
    row.new_users += 1;
    if (vipSet.has(String(u.id))) row.new_vip_users += 1;
  }
  return Array.from(dayMap.values());
}

async function fetchAllPromptLogsSince(sinceIso) {
  const all = [];
  const pageSize = 1000;
  let offset = 0;
  for (;;) {
    const { data, error } = await supabase
      .from('user_prompt_logs')
      .select('user_id, conversation_id, created_at')
      .gte('created_at', sinceIso)
      .order('created_at', { ascending: true })
      .range(offset, offset + pageSize - 1);
    if (error) throw error;
    const batch = data || [];
    all.push(...batch);
    if (batch.length < pageSize) break;
    offset += pageSize;
    if (offset > 200000) break;
  }
  return all;
}

async function buildConversationUsageFallback(days) {
  const n = Math.max(1, Math.min(365, days));
  const users = await fetchAllAuthUsersForAdmin({
    excludeInternal: false,
  });
  const anonById = new Map();
  for (const u of users) {
    anonById.set(String(u.id), !!u.is_anonymous);
  }
  const allowedUserIds = new Set(users.map((u) => String(u.id)));
  const vipById = new Map();
  const { data: statsRows, error: statsErr } = await supabase.from('user_stats').select('user_id, is_vip');
  if (statsErr) {
    console.warn('[admin] user_stats read (conversation fallback):', statsErr.message);
  }
  for (const row of statsRows || []) {
    if (row?.user_id) vipById.set(String(row.user_id), !!row.is_vip);
  }

  const end = new Date();
  const endUtc = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate()));
  const startUtc = new Date(endUtc);
  startUtc.setUTCDate(startUtc.getUTCDate() - (n - 1));
  const sinceIso = startUtc.toISOString();

  let logs = [];
  try {
    logs = await fetchAllPromptLogsSince(sinceIso);
  } catch (e) {
    console.warn('[admin] user_prompt_logs read (conversation fallback):', e?.message || e);
  }

  const dayKeys = [];
  for (let i = 0; i < n; i++) {
    const d = new Date(startUtc);
    d.setUTCDate(d.getUTCDate() + i);
    dayKeys.push(d.toISOString().slice(0, 10));
  }

  const bucket = new Map();
  for (const key of dayKeys) {
    bucket.set(key, {
      total_prompts: 0,
      active_users: new Set(),
      anonymous_active_users: new Set(),
      authorized_active_users: new Set(),
      distinct_conversations: new Set(),
      vip_prompts: 0,
      free_prompts: 0,
      anonymous_prompts: 0,
      authorized_prompts: 0,
    });
  }

  for (const row of logs) {
    const t = row?.created_at ? new Date(row.created_at) : null;
    if (!t || Number.isNaN(t.getTime())) continue;
    const dayKey = t.toISOString().slice(0, 10);
    const b = bucket.get(dayKey);
    if (!b) continue;
    const uid = String(row.user_id || '');
    if (!allowedUserIds.has(uid)) continue;
    const isAnon = anonById.get(uid) === true;
    const isVip = vipById.get(uid) === true;
    b.total_prompts += 1;
    b.active_users.add(uid);
    if (isAnon) {
      b.anonymous_active_users.add(uid);
      b.anonymous_prompts += 1;
    } else {
      b.authorized_active_users.add(uid);
      b.authorized_prompts += 1;
    }
    if (isVip) b.vip_prompts += 1;
    else b.free_prompts += 1;
    const cid = row.conversation_id;
    if (cid != null && String(cid).trim() !== '') b.distinct_conversations.add(String(cid));
  }

  const series = dayKeys.map((date) => {
    const b = bucket.get(date);
    return {
      date,
      total_prompts: b.total_prompts,
      active_users: b.active_users.size,
      anonymous_active_users: b.anonymous_active_users.size,
      authorized_active_users: b.authorized_active_users.size,
      distinct_conversations: b.distinct_conversations.size,
      vip_prompts: b.vip_prompts,
      free_prompts: b.free_prompts,
      anonymous_prompts: b.anonymous_prompts,
      authorized_prompts: b.authorized_prompts,
    };
  });
  return { series, _source: 'table_scan_fallback' };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'backend-local' });
});

app.post('/admin/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const remember = !!req.body?.remember;
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'username and password are required' });
    }
    const { data, error } = await supabase
      .from('admin_accounts')
      .select('username, password_hash, is_active')
      .eq('username', username)
      .limit(1)
      .maybeSingle();
    if (error || !data?.username || data.is_active === false) {
      return res.status(401).json({ ok: false, error: 'Invalid username or password' });
    }
    const ok = verifyScryptPassword(password, data.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: 'Invalid username or password' });
    const maxAgeMs = remember ? ADMIN_SESSION_REMEMBER_TTL_MS : ADMIN_SESSION_TTL_MS;
    const payload = {
      u: data.username,
      iat: Date.now(),
      exp: Date.now() + maxAgeMs,
      r: remember ? 1 : 0,
    };
    const token = signAdminSession(payload);
    res.setHeader('Set-Cookie', makeSessionCookieValue(token, maxAgeMs));
    return res.json({ ok: true, data: { username: data.username, remember } });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/admin/auth/logout', (_req, res) => {
  res.setHeader('Set-Cookie', clearSessionCookieValue());
  return res.json({ ok: true });
});

app.get('/admin/auth/session', async (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies[ADMIN_SESSION_COOKIE];
  const payload = verifyAdminSession(token);
  if (!payload) return res.status(401).json({ ok: false, error: 'Not logged in' });
  const username = String(payload.u || '').trim().toLowerCase();
  const { data, error } = await supabase
    .from('admin_accounts')
    .select('username, is_active')
    .eq('username', username)
    .limit(1)
    .maybeSingle();
  if (error || !data?.username || data.is_active === false) {
    return res.status(401).json({ ok: false, error: 'Not logged in' });
  }
  return res.json({ ok: true, data: { username: data.username } });
});

app.use('/admin/api', requireAdminAuth);

app.get('/admin/api/overview', async (_req, res) => {
  try {
    const fallback = await buildOverviewFallback();
    return res.json({ ok: true, data: fallback });
  } catch (e) {
    console.error('[admin] /admin/api/overview:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/trends', async (req, res) => {
  try {
    const days = clampDays(req.query.days);
    const data = await buildUserTrendsFallback(days);
    return res.json({ ok: true, data });
  } catch (e) {
    console.error('[admin] /admin/api/trends:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/conversation-usage', async (req, res) => {
  try {
    const days = clampDays(req.query.days);
    const { series } = await buildConversationUsageFallback(days);
    return res.json({ ok: true, data: series });
  } catch (e) {
    console.error('[admin] /admin/api/conversation-usage:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/share-insights', async (req, res) => {
  try {
    const days = clampDays(req.query.days);
    const { data, error } = await supabase.rpc('admin_share_insights', { p_days: days });
    if (error) {
      console.error('[admin] admin_share_insights:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    const payload = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    return res.json({
      ok: true,
      data: {
        summary: payload.summary || {},
        funnel: Array.isArray(payload.funnel) ? payload.funnel : [],
        daily: Array.isArray(payload.daily) ? payload.daily : [],
      },
    });
  } catch (e) {
    console.error('[admin] /admin/api/share-insights:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/prompt-logs', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.max(1, Math.min(100, Number(req.query.pageSize) || 20));
    const email = String(req.query.email || '').trim();
    const { data, error } = await supabase.rpc('admin_prompt_logs_by_email', {
      p_email: email,
      p_page: page,
      p_page_size: pageSize,
    });
    if (error) {
      console.error('[admin] admin_prompt_logs_by_email:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    if (data && typeof data === 'object' && data.error) {
      return res.status(400).json({ ok: false, error: data.message || data.error, code: data.error, data });
    }
    return res.json({ ok: true, data });
  } catch (e) {
    console.error('[admin] /admin/api/prompt-logs:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/share-list', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.max(1, Math.min(50, Number(req.query.pageSize) || 20));
    const keyword = String(req.query.keyword || '').trim();
    const { data, error } = await supabase.rpc('admin_share_list', {
      p_page: page,
      p_page_size: pageSize,
      p_keyword: keyword,
    });
    if (error) {
      console.error('[admin] admin_share_list:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    const payload = data && typeof data === 'object' ? data : {};
    let rows = payload.rows;
    if (typeof rows === 'string') {
      try {
        const parsed = JSON.parse(rows);
        rows = Array.isArray(parsed) ? parsed : [];
      } catch {
        rows = [];
      }
    } else if (!Array.isArray(rows)) {
      rows = [];
    }
    return res.json({
      ok: true,
      data: {
        page: payload.page ?? page,
        page_size: payload.page_size ?? pageSize,
        total: payload.total ?? 0,
        rows,
      },
    });
  } catch (e) {
    console.error('[admin] /admin/api/share-list:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/url-inputs', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.max(1, Math.min(100, Number(req.query.pageSize) || 20));
    const keyword = String(req.query.keyword || '').trim();
    const { data, error } = await supabase.rpc('admin_url_inputs', {
      p_page: page,
      p_page_size: pageSize,
      p_keyword: keyword,
    });
    if (error) {
      console.error('[admin] admin_url_inputs:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    const payload = data && typeof data === 'object' ? data : {};
    let rows = payload.rows;
    if (typeof rows === 'string') {
      try {
        const parsed = JSON.parse(rows);
        rows = Array.isArray(parsed) ? parsed : [];
      } catch {
        rows = [];
      }
    } else if (!Array.isArray(rows)) {
      rows = [];
    }
    return res.json({
      ok: true,
      data: {
        page: payload.page ?? page,
        page_size: payload.page_size ?? pageSize,
        total: payload.total ?? 0,
        rows,
      },
    });
  } catch (e) {
    console.error('[admin] /admin/api/url-inputs:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/model-usage', async (req, res) => {
  try {
    const days = clampDays(req.query.days);
    const sql = `
      WITH logs AS (
        SELECT *
        FROM public.ai_model_reply_logs
        WHERE created_at >= now() - make_interval(days => ${days})
      )
      SELECT
        model_id,
        model_route,
        count(*)::int AS total_replies,
        count(*) FILTER (WHERE coalesce(has_image, false))::int AS image_replies,
        count(DISTINCT user_id)::int AS distinct_users,
        count(DISTINCT conversation_id)::int AS distinct_conversations,
        max(created_at) AS last_seen_at
      FROM logs
      GROUP BY model_id, model_route
      ORDER BY total_replies DESC, model_id ASC, model_route ASC
    `.trim();
    const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
    if (error) {
      console.error('[admin] model usage:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    return res.json({ ok: true, data: { days, rows: Array.isArray(data?.rows) ? data.rows : [] } });
  } catch (e) {
    console.error('[admin] /admin/api/model-usage:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/model-replies', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.max(1, Math.min(100, Number(req.query.pageSize) || 20));
    const days = clampDays(req.query.days);
    const offset = (page - 1) * pageSize;
    const to = offset + pageSize - 1;
    const modelId = String(req.query.modelId || '').trim();
    const keyword = String(req.query.keyword || '').trim();
    const keywordLower = keyword.toLowerCase();
    let matchedUserIdsByEmail = [];
    if (keyword && keyword.includes('@')) {
      const users = await fetchAllAuthUsersForAdmin({ excludeInternal: false });
      matchedUserIdsByEmail = users
        .filter((u) => normalizeEmail(u.email).includes(keywordLower))
        .map((u) => String(u.id || '').trim())
        .filter(Boolean)
        .slice(0, 500);
    }

    const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    let query = supabase
      .from('ai_model_reply_logs')
      .select('id, created_at, user_id, conversation_id, model_id, model_route, has_image, user_prompt_preview, assistant_reply_preview', { count: 'exact' })
      .gte('created_at', sinceIso)
      .order('created_at', { ascending: false })
      .order('id', { ascending: false })
      .range(offset, to);

    if (modelId) query = query.eq('model_id', modelId);
    if (keyword) {
      if (matchedUserIdsByEmail.length > 0) {
        query = query.in('user_id', matchedUserIdsByEmail);
      } else {
        const like = `%${keyword}%`;
        query = query.or(
          `conversation_id.ilike.${like},user_id.ilike.${like},user_prompt_preview.ilike.${like},assistant_reply_preview.ilike.${like}`,
        );
      }
    }

    let { data, error, count } = await query;
    if (error && /user_prompt_preview|assistant_reply_preview/i.test(error.message || '')) {
      let fallback = supabase
        .from('ai_model_reply_logs')
        .select('id, created_at, user_id, conversation_id, model_id, model_route, has_image', { count: 'exact' })
        .gte('created_at', sinceIso)
        .order('created_at', { ascending: false })
        .order('id', { ascending: false })
        .range(offset, to);
      if (modelId) fallback = fallback.eq('model_id', modelId);
      if (keyword) {
        if (matchedUserIdsByEmail.length > 0) {
          fallback = fallback.in('user_id', matchedUserIdsByEmail);
        } else {
          const like = `%${keyword}%`;
          fallback = fallback.or(`conversation_id.ilike.${like},user_id.ilike.${like}`);
        }
      }
      const fallbackRes = await fallback;
      data = (fallbackRes.data || []).map((r) => ({ ...r, user_prompt_preview: '', assistant_reply_preview: '' }));
      error = fallbackRes.error;
      count = fallbackRes.count;
    }
    if (error) {
      console.error('[admin] model replies:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }

    const total = Number(count) || 0;
    const rowsRaw = Array.isArray(data) ? data : [];
    const authMap = await mapUserIdsToAuthInfo(rowsRaw.map((r) => r.user_id));
    const rows = rowsRaw.map((r) => {
      const uid = String(r.user_id || '');
      const info = authMap.get(uid) || { email: '', is_anonymous: false };
      return {
        ...r,
        user_email: info.email,
        user_is_anonymous: info.is_anonymous,
      };
    });
    return res.json({ ok: true, data: { page, page_size: pageSize, total, rows } });
  } catch (e) {
    console.error('[admin] /admin/api/model-replies:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/admin/api/nlq', async (req, res) => {
  try {
    const question = sanitizeNlqQuestion(req.body?.question);
    if (!question) return res.status(400).json({ ok: false, error: 'question is required' });
    const inputSessionId = sanitizeSessionId(req.body?.session_id);
    const sessionId = inputSessionId || createNlqSessionId();
    const historyTurns = getNlqSessionTurns(sessionId);
    const nextTurn = historyTurns.length + 1;
    const preset = matchPresetQuestion(question);
    if (preset === 'today_registered_count_and_emails') {
      const sql = `
        SELECT
          count(*)::int AS today_registered_count,
          coalesce(array_agg(u.email ORDER BY u.created_at DESC) FILTER (WHERE coalesce(u.email, '') <> ''), '{}') AS today_registered_emails
        FROM auth.users u
        WHERE u.created_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai')
          AND u.created_at < ((date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') + interval '1 day') AT TIME ZONE 'Asia/Shanghai')
          AND coalesce(u.is_anonymous, false) = false
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
      appendNlqTurn(sessionId, { question, action: 'preset:today_registered_count_and_emails' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (preset === 'cumulative_user_split') {
      const sql = `
        SELECT
          count(*) FILTER (WHERE coalesce(u.is_anonymous, false) = false)::int AS email_users,
          count(*) FILTER (
            WHERE coalesce(u.is_anonymous, false) = true
              AND u.created_at >= ((date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') - interval '1 day') AT TIME ZONE 'Asia/Shanghai')
          )::int AS anonymous_users
        FROM auth.users u
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      appendNlqTurn(sessionId, { question, action: 'preset:cumulative_user_split' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (preset === 'top_user_prompts_with_daily_avg') {
      const sql = `
        WITH user_usage AS (
          SELECT
            pl.user_id,
            count(*)::int AS total_prompts,
            count(DISTINCT ((pl.created_at AT TIME ZONE 'Asia/Shanghai')::date))::int AS active_days
          FROM public.user_prompt_logs pl
          GROUP BY pl.user_id
        )
        SELECT
          coalesce(u.email, uu.user_id::text) AS top_user,
          uu.total_prompts,
          round((uu.total_prompts::numeric / greatest(uu.active_days, 1)), 2) AS avg_daily_prompts
        FROM user_usage uu
        LEFT JOIN auth.users u ON u.id = uu.user_id
        ORDER BY uu.total_prompts DESC
        LIMIT 1
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
      appendNlqTurn(sessionId, { question, action: 'preset:top_user_prompts_with_daily_avg' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (preset === 'anonymous_active_3d_users') {
      const sql = `
        WITH anon_days AS (
          SELECT
            pl.user_id,
            (pl.created_at AT TIME ZONE 'Asia/Shanghai')::date AS d
          FROM public.user_prompt_logs pl
          JOIN auth.users u ON u.id = pl.user_id
          WHERE coalesce(u.is_anonymous, false) = true
            AND pl.created_at >= ((date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') - interval '1 day') AT TIME ZONE 'Asia/Shanghai')
          GROUP BY pl.user_id, (pl.created_at AT TIME ZONE 'Asia/Shanghai')::date
        ),
        seq AS (
          SELECT
            user_id,
            d,
            d - (row_number() OVER (PARTITION BY user_id ORDER BY d))::int AS grp
          FROM anon_days
        ),
        streak AS (
          SELECT user_id, count(*) AS streak_days
          FROM seq
          GROUP BY user_id, grp
        )
        SELECT count(DISTINCT user_id)::int AS anonymous_active_3d_users
        FROM streak
        WHERE streak_days >= 3
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      appendNlqTurn(sessionId, { question, action: 'preset:anonymous_active_3d_users' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (preset === 'today_anonymous_user_list') {
      const sql = `
        SELECT
          coalesce(
            array_agg(DISTINCT coalesce(u.email, pl.user_id::text) ORDER BY coalesce(u.email, pl.user_id::text)),
            '{}'
          ) AS today_anonymous_users
        FROM public.user_prompt_logs pl
        JOIN auth.users u ON u.id = pl.user_id
        WHERE coalesce(u.is_anonymous, false) = true
          AND pl.created_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai')
          AND pl.created_at < ((date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') + interval '1 day') AT TIME ZONE 'Asia/Shanghai')
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      appendNlqTurn(sessionId, { question, action: 'preset:today_anonymous_user_list' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (preset === 'url_conversation_counts_and_list') {
      const sql = `
        WITH url_logs AS (
          SELECT
            pl.id,
            pl.conversation_id,
            j.url::text AS url
          FROM public.user_prompt_logs pl
          CROSS JOIN LATERAL jsonb_array_elements_text(
            CASE
              WHEN jsonb_typeof(pl.extracted_urls) = 'array' THEN pl.extracted_urls
              ELSE '[]'::jsonb
            END
          ) AS j(url)
        ),
        uniq AS (
          SELECT DISTINCT nullif(trim(url), '') AS url
          FROM url_logs
          WHERE nullif(trim(url), '') IS NOT NULL
        )
        SELECT
          (SELECT count(DISTINCT conversation_id)::int FROM url_logs) AS conversations_with_urls,
          (SELECT count(DISTINCT id)::int FROM url_logs) AS records_with_urls,
          (SELECT count(*)::int FROM uniq) AS unique_urls,
          coalesce((SELECT array_agg(url ORDER BY url) FROM uniq), '{}') AS url_list
      `.trim().replace(/\s+/g, ' ');
      const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code });
      }
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      await upsertMemorySql(question, sql);
      appendNlqTurn(sessionId, { question, action: 'preset:url_conversation_counts_and_list' });
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'preset',
          question,
          mode: 'sql',
          sql,
          explanation: 'preset',
          row_count: data?.row_count ?? rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, buildNlqAnswerText(question, rows)),
        },
      });
    }

    const memoryHit = await recallSqlFromMemory(question);
    if (memoryHit?.sql_text) {
      const raw = String(memoryHit.sql_text || '').trim();
      if (raw.startsWith(NLQ_RPC_MEMORY_PREFIX)) {
        let payload = null;
        try {
          payload = JSON.parse(raw.slice(NLQ_RPC_MEMORY_PREFIX.length));
        } catch (_) {
          payload = null;
        }
        const rpc = String(payload?.rpc || '').trim();
        const args = payload?.args && typeof payload.args === 'object' ? payload.args : {};
        if (rpc && allowedNlqRpc.has(rpc)) {
          const { data, error } = await supabase.rpc(rpc, args);
          if (!error) {
            const rows = Array.isArray(data) ? data : [data];
            const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
            appendNlqTurn(sessionId, { question, action: `memory_rpc:${rpc}` });
            await touchMemoryHit(memoryHit.id);
            return res.json({
              ok: true,
              data: {
                session_id: sessionId,
                context_turns: nextTurn,
                hit_source: 'memory',
                memory_match: memoryHit.match_type || 'exact',
                question,
                mode: 'rpc',
                rpc,
                args,
                explanation: 'memory_reuse',
                row_count: rows.length,
                rows,
                answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
              },
            });
          }
        }
      } else {
        const sql = raw;
        const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
        if (!error && data && data.ok === true) {
          const rows = Array.isArray(data.rows) ? data.rows : [];
          const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
          appendNlqTurn(sessionId, { question, action: `memory_sql:${sql.slice(0, 180)}` });
          await touchMemoryHit(memoryHit.id);
          return res.json({
            ok: true,
            data: {
              session_id: sessionId,
              context_turns: nextTurn,
              hit_source: 'memory',
              memory_match: memoryHit.match_type || 'exact',
              question,
              mode: 'sql',
              sql,
              explanation: 'memory_reuse',
              row_count: data.row_count ?? rows.length,
              rows,
              answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
            },
          });
        }
      }
    }

    const decision = await askLlmForSql(question, historyTurns);
    const mode = String(decision.mode || '').toLowerCase();
    if (mode === 'rpc') {
      const rpc = String(decision.rpc || '').trim();
      if (!allowedNlqRpc.has(rpc)) {
        return res.status(400).json({ ok: false, error: `RPC not allowed: ${rpc}`, decision });
      }
      const args = decision.args && typeof decision.args === 'object' ? decision.args : {};
      const { data, error } = await supabase.rpc(rpc, args);
      if (error) {
        return res.status(500).json({ ok: false, error: error.message, code: error.code, decision });
      }
      await upsertMemorySql(question, buildNlqRpcMemoryText(rpc, args));
      appendNlqTurn(sessionId, { question, action: `rpc:${rpc}` });
      const rows = Array.isArray(data) ? data : [data];
      const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
      return res.json({
        ok: true,
        data: {
          session_id: sessionId,
          context_turns: nextTurn,
          hit_source: 'ai',
          question,
          mode: 'rpc',
          rpc,
          args,
          explanation: decision.explanation || '',
          row_count: rows.length,
          rows,
          answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
        },
      });
    }
    if (mode !== 'sql') {
      return res.status(400).json({
        ok: false,
        error: decision.reason || 'Question rejected by NLQ policy',
        decision,
      });
    }
    const sql = String(decision.sql || '').trim();
    if (!sql) {
      return res.status(400).json({ ok: false, error: 'LLM did not return SQL', decision });
    }

    const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
    if (error) {
      console.error('[admin] admin_execute_select_sql:', error.message, error);
      return res.status(500).json({ ok: false, error: error.message, code: error.code, sql });
    }
    if (!data || data.ok !== true) {
      return res.status(400).json({
        ok: false,
        error: data?.error || 'SQL executor rejected query',
        sql,
        decision,
      });
    }

    appendNlqTurn(sessionId, { question, action: `sql:${sql.slice(0, 200)}` });
    const rows = Array.isArray(data.rows) ? data.rows : [];
    await upsertMemorySql(question, sql);
    const aiMarkdown = await askLlmForAnswerMarkdown(question, rows);
    return res.json({
      ok: true,
      data: {
        session_id: sessionId,
        context_turns: nextTurn,
        hit_source: 'ai',
        question,
        mode: 'sql',
        sql,
        explanation: decision.explanation || '',
        row_count: data.row_count ?? 0,
        rows,
        answer_text: appendDetailListIfNeeded(question, rows, aiMarkdown || buildNlqAnswerText(question, rows)),
      },
    });
  } catch (e) {
    console.error('[admin] /admin/api/nlq:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/admin/api/nlq/context/reset', (req, res) => {
  const inputSessionId = sanitizeSessionId(req.body?.session_id);
  if (inputSessionId) nlqSessions.delete(inputSessionId);
  const sessionId = createNlqSessionId();
  nlqSessions.set(sessionId, []);
  return res.json({ ok: true, data: { session_id: sessionId } });
});

app.post('/admin/api/nlq/schema/refresh', async (_req, res) => {
  try {
    const sql = `
      SELECT
        c.table_schema,
        c.table_name,
        c.column_name,
        c.data_type,
        c.ordinal_position
      FROM information_schema.columns c
      WHERE c.table_schema IN ('public', 'auth')
        AND c.table_name NOT LIKE 'pg_%'
      ORDER BY c.table_schema, c.table_name, c.ordinal_position
    `.trim().replace(/\s+/g, ' ');
    const { data, error } = await supabase.rpc('admin_execute_select_sql', { p_sql: sql });
    if (error) {
      return res.status(500).json({ ok: false, error: error.message, code: error.code });
    }
    if (!data || data.ok !== true) {
      return res.status(400).json({ ok: false, error: data?.error || 'Schema query rejected' });
    }
    const rows = Array.isArray(data.rows) ? data.rows : [];
    if (rows.length === 0) {
      return res.status(400).json({ ok: false, error: 'No schema rows returned' });
    }
    const md = buildSchemaMarkdownFromRows(rows);
    fs.writeFileSync(nlqSchemaPersistPath, md, 'utf8');
    nlqSchemaText = md;
    return res.json({
      ok: true,
      data: {
        path: nlqSchemaPersistPath,
        table_columns: rows.length,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/**
 * When RPC admin_users fails (SQL not applied / schema drift), use Auth Admin API + user_stats.
 */
async function listUsersFallback({ page, pageSize, keyword, vipOnly }) {
  const vipMap = new Map();
  const { data: statsRows, error: statsErr } = await supabase.from('user_stats').select('user_id, is_vip');
  if (statsErr) {
    console.warn('[admin] user_stats read (fallback):', statsErr.message);
  }
  for (const row of statsRows || []) {
    if (row?.user_id) vipMap.set(String(row.user_id), !!row.is_vip);
  }

  const allUsers = await fetchAllAuthUsersForAdmin({
    excludeInternal: false,
  });

  const kw = keyword.toLowerCase();
  let rows = allUsers
    .filter((u) => !u.is_anonymous)
    .map((u) => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      is_vip: vipMap.get(String(u.id)) === true,
      is_internal: isInternalTestEmail(u.email),
    }))
    .filter((r) => {
      if (vipOnly && !r.is_vip) return false;
      if (!kw) return true;
      const em = String(r.email || '').toLowerCase();
      return em.includes(kw) || String(r.id).toLowerCase().includes(kw);
    })
    .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));

  const total = rows.length;
  const start = (page - 1) * pageSize;
  rows = rows.slice(start, start + pageSize);

  return { page, page_size: pageSize, total, rows, _source: 'auth_admin_fallback' };
}

const ADMIN_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isAdminUuidQuery(s) {
  return ADMIN_UUID_RE.test(String(s || '').trim());
}

function normalizeAuthUserForAdmin360(u) {
  if (!u) return null;
  const app = u.app_metadata || {};
  const meta = u.user_metadata || {};
  const isAnonymous =
    !!u.is_anonymous ||
    app.provider === 'anonymous' ||
    meta.provider === 'anonymous' ||
    String(app.provider || '').toLowerCase() === 'anonymous';
  return {
    id: u.id,
    email: u.email || null,
    created_at: u.created_at,
    last_sign_in_at: u.last_sign_in_at,
    is_anonymous: !!isAnonymous,
    provider: app.provider || meta.provider || null,
  };
}

function groupPromptLogsByConversation(logs) {
  const arr = Array.isArray(logs) ? logs : [];
  const map = new Map();
  for (const row of arr) {
    const cid = row.conversation_id ? String(row.conversation_id) : '(无 conversation_id)';
    if (!map.has(cid)) {
      map.set(cid, {
        conversation_id: cid,
        turns: [],
        first_at: row.created_at,
        last_at: row.created_at,
      });
    }
    const g = map.get(cid);
    g.turns.push(row);
    const t = new Date(row.created_at).getTime();
    if (t < new Date(g.first_at).getTime()) g.first_at = row.created_at;
    if (t > new Date(g.last_at).getTime()) g.last_at = row.created_at;
  }
  for (const g of map.values()) {
    g.turns.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    g.turn_count = g.turns.length;
  }
  return [...map.values()].sort((a, b) => new Date(b.last_at) - new Date(a.last_at));
}

function groupAiRepliesByConversation(rows) {
  const arr = Array.isArray(rows) ? rows : [];
  const map = new Map();
  for (const row of arr) {
    const cid = row.conversation_id ? String(row.conversation_id) : '(无 conversation_id)';
    if (!map.has(cid)) map.set(cid, []);
    map.get(cid).push(row);
  }
  for (const list of map.values()) {
    list.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  }
  return map;
}

async function resolveAdminUser360Query(q) {
  const raw = String(q || '').trim();
  if (!raw) return { status: 'empty' };
  if (isAdminUuidQuery(raw)) {
    const { data, error } = await supabase.auth.admin.getUserById(raw);
    if (error || !data?.user) return { status: 'not_found' };
    return { status: 'ok', user: data.user };
  }
  const all = await fetchAllAuthUsersForAdmin();
  const lower = raw.toLowerCase();
  const exact = all.find((u) => String(u.email || '').toLowerCase() === lower);
  if (exact) return { status: 'ok', user: exact };
  const partial = all.filter((u) => {
    const em = String(u.email || '').toLowerCase();
    return em.includes(lower) || String(u.id).toLowerCase() === lower;
  });
  if (partial.length === 1) return { status: 'ok', user: partial[0] };
  if (partial.length > 1) {
    return {
      status: 'ambiguous',
      candidates: partial.slice(0, 40).map((u) => ({
        id: u.id,
        email: u.email,
        created_at: u.created_at,
      })),
    };
  }
  return { status: 'not_found' };
}

async function buildUser360Payload(authUser) {
  const uid = String(authUser.id);
  const profile = normalizeAuthUserForAdmin360(authUser);

  const { data: statsRow } = await supabase.from('user_stats').select('*').eq('user_id', uid).maybeSingle();

  const { data: inquiries } = await supabase
    .from('product_inquiries')
    .select(
      'id, user_id, user_email, product_snapshot, whatsapp, demand, status, reply_content, reply_at, created_at, updated_at',
    )
    .eq('user_id', uid)
    .order('created_at', { ascending: false })
    .limit(100);

  const { data: promptLogsRaw } = await supabase
    .from('user_prompt_logs')
    .select('id, conversation_id, content_preview, extracted_urls, created_at')
    .eq('user_id', uid)
    .order('created_at', { ascending: false })
    .limit(800);

  const prompt_logs = Array.isArray(promptLogsRaw) ? promptLogsRaw : [];
  const conversations = groupPromptLogsByConversation(prompt_logs);
  let aiRepliesRaw = [];
  try {
    const rs = await supabase
      .from('ai_model_reply_logs')
      .select(
        'id, conversation_id, created_at, model_id, model_route, has_image, user_prompt_preview, assistant_reply_preview',
      )
      .eq('user_id', uid)
      .order('created_at', { ascending: false })
      .limit(800);
    if (rs.error && /user_prompt_preview|assistant_reply_preview/i.test(String(rs.error.message || ''))) {
      const legacy = await supabase
        .from('ai_model_reply_logs')
        .select('id, conversation_id, created_at, model_id, model_route, has_image')
        .eq('user_id', uid)
        .order('created_at', { ascending: false })
        .limit(800);
      aiRepliesRaw = (legacy.data || []).map((x) => ({ ...x, user_prompt_preview: '', assistant_reply_preview: '' }));
    } else {
      aiRepliesRaw = Array.isArray(rs.data) ? rs.data : [];
    }
  } catch (e) {
    aiRepliesRaw = [];
  }
  const aiRepliesByConversation = groupAiRepliesByConversation(aiRepliesRaw);
  for (const c of conversations) {
    c.ai_replies = aiRepliesByConversation.get(String(c.conversation_id || '(无 conversation_id)')) || [];
    c.ai_reply_count = c.ai_replies.length;
  }

  const { data: shareLinks } = await supabase
    .from('share_links')
    .select('id, short_code, created_at, owner_email')
    .eq('owner_user_id', uid);

  const links = Array.isArray(shareLinks) ? shareLinks : [];
  const linkIds = links.map((l) => l.id).filter(Boolean);

  const visitStats = {
    total_visits: 0,
    distinct_visitors: 0,
    anonymous_visit_rows: 0,
    email_identified_visit_rows: 0,
    distinct_truncated: false,
  };
  let visitsSample = [];
  let visitsTruncated = false;

  if (linkIds.length) {
    const { count: vcount } = await supabase
      .from('share_link_visits')
      .select('*', { count: 'exact', head: true })
      .in('share_link_id', linkIds);
    visitStats.total_visits = Number(vcount) || 0;

    const FETCH_CAP = 4000;
    const { data: vrows, error: vErr } = await supabase
      .from('share_link_visits')
      .select('visitor_user_id, visitor_email, visitor_is_anonymous, created_at, share_link_id')
      .in('share_link_id', linkIds)
      .order('created_at', { ascending: false })
      .limit(FETCH_CAP);

    if (!vErr && Array.isArray(vrows)) {
      if (vrows.length >= FETCH_CAP) {
        visitsTruncated = true;
        visitStats.distinct_truncated = true;
      }
      visitsSample = vrows.slice(0, 60);
      const seen = new Set();
      for (const r of vrows) {
        if (r?.visitor_user_id) seen.add(String(r.visitor_user_id));
      }
      visitStats.distinct_visitors = seen.size;
      for (const r of vrows) {
        if (r?.visitor_is_anonymous) visitStats.anonymous_visit_rows += 1;
        const em = String(r?.visitor_email || '').trim();
        if (em && !r?.visitor_is_anonymous) visitStats.email_identified_visit_rows += 1;
      }
    }
  }

  let oauthAsSharer = [];
  let oauthAsAttributed = [];
  try {
    const { data: o1 } = await supabase
      .from('share_link_oauth_attributions')
      .select(
        'id, share_link_id, short_code, sharer_user_id, sharer_email, attributed_user_id, visitor_email, oauth_provider, created_at',
      )
      .eq('sharer_user_id', uid)
      .order('created_at', { ascending: false })
      .limit(100);
    oauthAsSharer = Array.isArray(o1) ? o1 : [];
  } catch (e) {
    console.warn('[admin] user-360 oauth sharer:', e?.message);
  }
  try {
    const { data: o2 } = await supabase
      .from('share_link_oauth_attributions')
      .select(
        'id, share_link_id, short_code, sharer_user_id, sharer_email, attributed_user_id, visitor_email, oauth_provider, created_at',
      )
      .eq('attributed_user_id', uid)
      .order('created_at', { ascending: false })
      .limit(50);
    oauthAsAttributed = Array.isArray(o2) ? o2 : [];
  } catch (e) {
    console.warn('[admin] user-360 oauth attributed:', e?.message);
  }

  return {
    profile,
    stats: statsRow || null,
    inquiries: Array.isArray(inquiries) ? inquiries : [],
    prompt_logs,
    prompt_log_count: prompt_logs.length,
    ai_replies: aiRepliesRaw,
    ai_reply_count: aiRepliesRaw.length,
    conversations,
    conversation_count: conversations.length,
    share: {
      has_share_link: links.length > 0,
      links,
      visit_stats: visitStats,
      visits_sample: visitsSample,
      visits_truncated: visitsTruncated,
      oauth_as_sharer: oauthAsSharer,
      oauth_as_attributed: oauthAsAttributed,
    },
  };
}

app.get('/admin/api/user-360', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    const resolved = await resolveAdminUser360Query(q);
    if (resolved.status === 'empty') {
      return res.status(400).json({ ok: false, error: '请填写邮箱或用户 ID（UUID）' });
    }
    if (resolved.status === 'not_found') {
      return res.status(404).json({ ok: false, error: '未找到用户' });
    }
    if (resolved.status === 'ambiguous') {
      return res.status(409).json({
        ok: false,
        error: '多条匹配，请使用完整邮箱或 UUID',
        candidates: resolved.candidates,
      });
    }
    const payload = await buildUser360Payload(resolved.user);
    return res.json({ ok: true, data: payload });
  } catch (e) {
    console.error('[admin] /admin/api/user-360:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/admin/api/users', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.max(1, Math.min(100, Number(req.query.pageSize) || 20));
    const keyword = String(req.query.keyword || '').trim();
    const vipOnly = String(req.query.vipOnly || '') === '1' || String(req.query.vipOnly || '').toLowerCase() === 'true';
    const fallback = await listUsersFallback({ page, pageSize, keyword, vipOnly });
    return res.json({ ok: true, data: fallback });
  } catch (e) {
    console.error('[admin] /admin/api/users:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// 本地：public/admin 作为 /admin；线上由 Vercel CDN 提供 public/**（见上方重定向）
if (process.env.VERCEL !== '1') {
  app.use('/admin', express.static(path.join(__dirname, 'public', 'admin')));
}

/**
 * Supabase RPC proxy (local-only)
 * body: { args?: Record<string, any> }
 */
app.post('/supabase/rpc/:fn', async (req, res) => {
  const fn = String(req.params.fn || '').trim();
  if (!fn) return res.status(400).json({ ok: false, error: 'Missing RPC function name' });
  const args = req.body?.args && typeof req.body.args === 'object' ? req.body.args : {};
  const { data, error } = await supabase.rpc(fn, args);
  if (error) return res.status(500).json({ ok: false, error: error.message });
  return res.json({ ok: true, data });
});

/**
 * Supabase query proxy (local-only)
 * body:
 * {
 *   table: string,
 *   select?: string,
 *   filters?: [{ column, op, value }],
 *   order?: { column, ascending?: boolean },
 *   limit?: number,
 *   single?: boolean
 * }
 */
app.post('/supabase/query', async (req, res) => {
  const body = req.body || {};
  const table = String(body.table || '').trim();
  if (!table) return res.status(400).json({ ok: false, error: 'table is required' });

  const select = String(body.select || '*');
  let q = supabase.from(table).select(select);

  const filters = Array.isArray(body.filters) ? body.filters : [];
  for (const f of filters) {
    const column = String(f?.column || '').trim();
    const op = String(f?.op || 'eq').trim();
    const value = f?.value;
    if (!column) continue;
    if (typeof q[op] === 'function') {
      q = q[op](column, value);
    }
  }

  if (body.order?.column) {
    q = q.order(String(body.order.column), { ascending: body.order.ascending !== false });
  }
  if (Number.isFinite(body.limit) && Number(body.limit) > 0) {
    q = q.limit(Number(body.limit));
  }
  if (body.single) {
    q = q.single();
  }

  const { data, error } = await q;
  if (error) return res.status(500).json({ ok: false, error: error.message });
  return res.json({ ok: true, data });
});

// ────────────────────────────────────────────
// 询盘管理 API（Admin）
// ────────────────────────────────────────────

/** 列出所有询盘（分页，支持按 status 筛选） */
app.get('/admin/api/inquiries', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize) || 20));
    const statusFilter = String(req.query.status || '').trim();
    const keyword = String(req.query.keyword || '').trim();

    let q = supabase
      .from('product_inquiries')
      .select('id, user_id, user_email, product_snapshot, whatsapp, demand, status, reply_content, reply_at, replied_by, reply_messages, reply_count, user_seen_reply_count, created_at, updated_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range((page - 1) * pageSize, page * pageSize - 1);

    if (statusFilter === 'submitted' || statusFilter === 'replied') {
      q = q.eq('status', statusFilter);
    }
    if (keyword) {
      q = q.or(`user_email.ilike.%${keyword}%,whatsapp.ilike.%${keyword}%,demand.ilike.%${keyword}%`);
    }

    let { data, error, count } = await q;
    if (error && /reply_messages|reply_count|user_seen_reply_count/i.test(String(error.message || ''))) {
      let fallback = supabase
        .from('product_inquiries')
        .select('id, user_id, user_email, product_snapshot, whatsapp, demand, status, reply_content, reply_at, replied_by, created_at, updated_at', { count: 'exact' })
        .order('created_at', { ascending: false })
        .range((page - 1) * pageSize, page * pageSize - 1);
      if (statusFilter === 'submitted' || statusFilter === 'replied') fallback = fallback.eq('status', statusFilter);
      if (keyword) fallback = fallback.or(`user_email.ilike.%${keyword}%,whatsapp.ilike.%${keyword}%,demand.ilike.%${keyword}%`);
      const rs = await fallback;
      data = (rs.data || []).map((r) => ({
        ...r,
        reply_messages: r.reply_content ? [{ content: r.reply_content, at: r.reply_at, by: r.replied_by }] : [],
        reply_count: r.reply_content ? 1 : 0,
        user_seen_reply_count: 0,
      }));
      error = rs.error;
      count = rs.count;
    }
    if (error) return res.status(500).json({ ok: false, error: error.message });
    return res.json({ ok: true, data: { rows: data || [], total: count || 0, page, pageSize } });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/** 管理员回复询盘 */
app.post('/admin/api/inquiries/:id/reply', async (req, res) => {
  try {
    const inquiryId = String(req.params.id || '').trim();
    const replyContent = String(req.body?.reply_content || '').trim();
    if (!inquiryId) return res.status(400).json({ ok: false, error: 'inquiry id is required' });
    if (!replyContent) return res.status(400).json({ ok: false, error: 'reply_content is required' });

    const nowIso = new Date().toISOString();
    const replier = 'TangbuyDropshipping';
    let { data: oldRow, error: oldErr } = await supabase
      .from('product_inquiries')
      .select('reply_messages, reply_count')
      .eq('id', inquiryId)
      .maybeSingle();
    if (oldErr && /reply_messages|reply_count/i.test(String(oldErr.message || ''))) {
      const legacy = await supabase
        .from('product_inquiries')
        .select('id')
        .eq('id', inquiryId)
        .maybeSingle();
      oldRow = legacy.data ? { reply_messages: [], reply_count: 0 } : null;
      oldErr = legacy.error;
    }
    if (oldErr) return res.status(500).json({ ok: false, error: oldErr.message });
    if (!oldRow) return res.status(404).json({ ok: false, error: 'inquiry not found' });

    const history = Array.isArray(oldRow.reply_messages) ? oldRow.reply_messages : [];
    const nextHistory = [...history, { content: replyContent, at: nowIso, by: replier }];
    const nextCount = Math.max(Number(oldRow.reply_count) || 0, history.length) + 1;

    let { data, error } = await supabase
      .from('product_inquiries')
      .update({
        status: 'replied',
        reply_content: replyContent,
        reply_at: nowIso,
        replied_by: replier,
        reply_messages: nextHistory,
        reply_count: nextCount,
      })
      .eq('id', inquiryId)
      .select('id, status, reply_content, reply_at, replied_by, reply_messages, reply_count')
      .maybeSingle();
    if (error && /reply_messages|reply_count/i.test(String(error.message || ''))) {
      const legacy = await supabase
        .from('product_inquiries')
        .update({
          status: 'replied',
          reply_content: replyContent,
          reply_at: nowIso,
          replied_by: replier,
        })
        .eq('id', inquiryId)
        .select('id, status, reply_content, reply_at, replied_by')
        .maybeSingle();
      data = legacy.data ? { ...legacy.data, reply_messages: [{ content: replyContent, at: nowIso, by: replier }], reply_count: 1 } : null;
      error = legacy.error;
    }

    if (error) return res.status(500).json({ ok: false, error: error.message });
    if (!data) return res.status(404).json({ ok: false, error: 'inquiry not found' });
    return res.json({ ok: true, data });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/**
 * Supabase upsert proxy (local-only)
 * body: { table: string, rows: object|object[], onConflict?: string }
 */
app.post('/supabase/upsert', async (req, res) => {
  const table = String(req.body?.table || '').trim();
  const rows = req.body?.rows;
  const onConflict = String(req.body?.onConflict || '').trim();
  if (!table) return res.status(400).json({ ok: false, error: 'table is required' });
  if (!rows || (Array.isArray(rows) && rows.length === 0)) {
    return res.status(400).json({ ok: false, error: 'rows is required' });
  }

  const { data, error } = await supabase
    .from(table)
    .upsert(rows, onConflict ? { onConflict } : undefined)
    .select('*');
  if (error) return res.status(500).json({ ok: false, error: error.message });
  return res.json({ ok: true, data });
});

export default app;

if (process.env.VERCEL !== '1') {
  app.listen(port, () => {
    console.log(`[backend-local] running at http://localhost:${port}`);
  });
}

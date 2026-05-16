import crypto from 'node:crypto';
import { analyze } from '../../lib/detect.js';
import { getSupabase, hashApiKey, currentMonthKey } from '../../lib/supabase.js';

const FREE_MONTHLY_LIMIT = 2000;
const PLAN_LIMITS = {
  growth: 100_000,
  enterprise: 999_999_999,
};
const ACTIVE_SUB_STATUSES = new Set(['active', 'trialing']);
const UPGRADE_URL = 'https://zentricprotocol.com/pricing';

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('X-Powered-By', 'Zentric Protocol v1.0');
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

function extractBearerToken(req) {
  const header = req.headers?.authorization || req.headers?.Authorization;
  if (!header || typeof header !== 'string') return null;
  if (!header.toLowerCase().startsWith('bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

async function readJsonBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') {
      try {
        return JSON.parse(req.body);
      } catch {
        return { __parseError: true };
      }
    }
    return req.body;
  }
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        req.destroy();
        resolve({ __parseError: true });
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({ __parseError: true });
      }
    });
    req.on('error', () => resolve({ __parseError: true }));
  });
}

function signReport(report) {
  const secret = process.env.HMAC_SECRET;
  if (!secret) return;
  const payload = `${report.report_id}.${report.sha256}.${report.timestamp_utc}`;
  report.report_hash = crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

async function lookupFreeKey(supabase, keyHash) {
  const { data, error } = await supabase
    .from('free_api_keys')
    .select('key_hash, email, requests_this_month, month_bucket')
    .eq('key_hash', keyHash)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function lookupPaidKey(supabase, keyHash) {
  const { data, error } = await supabase
    .from('api_keys')
    .select('key_hash, user_id, tier, requests_this_month, revoked_at')
    .eq('key_hash', keyHash)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function lookupSubscription(supabase, userId) {
  const { data, error } = await supabase
    .from('subscriptions')
    .select('user_id, status, plan')
    .eq('user_id', userId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function authenticate(supabase, apiKey) {
  const keyHash = hashApiKey(apiKey);

  const freeRow = await lookupFreeKey(supabase, keyHash);
  if (freeRow) {
    const month = currentMonthKey();
    const sameMonth = freeRow.month_bucket === month;
    const used = sameMonth ? (freeRow.requests_this_month ?? 0) : 0;
    return {
      kind: 'free',
      keyHash,
      email: freeRow.email,
      monthBucket: freeRow.month_bucket,
      currentMonth: month,
      sameMonth,
      used,
      limit: FREE_MONTHLY_LIMIT,
      tier: 'FREE',
      plan: 'free',
    };
  }

  const paidRow = await lookupPaidKey(supabase, keyHash);
  if (!paidRow) return { kind: 'none' };

  if (paidRow.revoked_at) {
    return { kind: 'revoked' };
  }

  const sub = await lookupSubscription(supabase, paidRow.user_id);
  if (!sub || !ACTIVE_SUB_STATUSES.has(sub.status)) {
    return {
      kind: 'inactive_subscription',
      status: sub?.status ?? 'missing',
      plan: sub?.plan ?? paidRow.tier ?? null,
    };
  }

  const plan = (sub.plan || paidRow.tier || '').toLowerCase();
  const limit = PLAN_LIMITS[plan] ?? PLAN_LIMITS.growth;
  return {
    kind: 'paid',
    keyHash,
    userId: paidRow.user_id,
    tier: (paidRow.tier || plan || 'GROWTH').toUpperCase(),
    plan,
    used: paidRow.requests_this_month ?? 0,
    limit,
  };
}

async function incrementFreeKey(supabase, keyHash, sameMonth, currentMonth) {
  if (!sameMonth) {
    const { error } = await supabase
      .from('free_api_keys')
      .update({ requests_this_month: 1, month_bucket: currentMonth })
      .eq('key_hash', keyHash);
    if (error) throw error;
    return;
  }
  const { error } = await supabase.rpc('increment_free_key_usage', { p_key_hash: keyHash });
  if (error) {
    const fallback = await supabase
      .from('free_api_keys')
      .select('requests_this_month')
      .eq('key_hash', keyHash)
      .maybeSingle();
    const next = (fallback.data?.requests_this_month ?? 0) + 1;
    const { error: updErr } = await supabase
      .from('free_api_keys')
      .update({ requests_this_month: next, month_bucket: currentMonth })
      .eq('key_hash', keyHash);
    if (updErr) throw updErr;
  }
}

async function incrementPaidKey(supabase, keyHash, previousCount) {
  const { error } = await supabase.rpc('increment_api_key_usage', { p_key_hash: keyHash });
  if (error) {
    const { error: updErr } = await supabase
      .from('api_keys')
      .update({ requests_this_month: previousCount + 1 })
      .eq('key_hash', keyHash);
    if (updErr) throw updErr;
  }
}

async function logReportRow(supabase, { reportId, userId, verdict, sha256, latencyMs }) {
  const { error } = await supabase.from('reports').insert({
    report_id: reportId,
    user_id: userId,
    verdict,
    sha256,
    latency_ms: latencyMs,
  });
  if (error) throw error;
}

export default async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') {
    return sendJson(res, 405, { error: 'method_not_allowed', message: 'Use POST' });
  }

  const apiKey = extractBearerToken(req);
  if (!apiKey) {
    return sendJson(res, 401, {
      error: 'MISSING_API_KEY',
      message: 'Missing or malformed Authorization header. Use: Authorization: Bearer <api_key>',
    });
  }

  let supabase;
  try {
    supabase = getSupabase();
  } catch (err) {
    console.error('Supabase init failed:', err);
    return sendJson(res, 500, { error: 'SERVER_MISCONFIGURED', message: err.message });
  }

  let auth;
  try {
    auth = await authenticate(supabase, apiKey);
  } catch (err) {
    console.error('Auth lookup failed:', err);
    return sendJson(res, 500, { error: 'AUTH_LOOKUP_FAILED', message: 'Internal auth error' });
  }

  if (auth.kind === 'none') {
    return sendJson(res, 401, { error: 'INVALID_API_KEY', message: 'Invalid API key' });
  }
  if (auth.kind === 'revoked') {
    return sendJson(res, 401, { error: 'REVOKED_API_KEY', message: 'This API key has been revoked' });
  }
  if (auth.kind === 'inactive_subscription') {
    return sendJson(res, 402, {
      error: 'SUBSCRIPTION_INACTIVE',
      message: `Subscription status is "${auth.status}". Update your billing to continue using this API key.`,
      subscription_status: auth.status,
      plan: auth.plan,
      upgrade_url: UPGRADE_URL,
    });
  }

  const month = currentMonthKey();
  if (auth.used >= auth.limit) {
    res.setHeader('X-RateLimit-Limit', String(auth.limit));
    res.setHeader('X-RateLimit-Remaining', '0');
    res.setHeader('X-RateLimit-Reset-Month', month);
    return sendJson(res, 429, {
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Monthly quota of ${auth.limit} requests reached for ${auth.tier} tier`,
      tier: auth.tier,
      plan: auth.plan,
      limit: auth.limit,
      used: auth.used,
      reset_month: month,
      ...(auth.kind === 'free' ? { upgrade_url: UPGRADE_URL } : {}),
    });
  }

  const body = await readJsonBody(req);
  if (body?.__parseError) {
    return sendJson(res, 400, { error: 'INVALID_BODY', message: 'Invalid JSON body' });
  }
  const { input, modules, options } = body || {};
  if (!input || typeof input !== 'string' || !input.trim()) {
    return sendJson(res, 400, {
      error: 'INVALID_INPUT',
      message: 'input field is required (non-empty string)',
    });
  }

  const selectedModules =
    Array.isArray(modules) && modules.length > 0 ? modules : ['integrity', 'privacy'];

  let result;
  try {
    result = analyze(input, selectedModules);
  } catch (err) {
    console.error('Detection failed:', err);
    return sendJson(res, 500, { error: 'DETECTION_FAILED', message: 'Detection engine error' });
  }

  if (options && typeof options === 'object') {
    result.echo_options = options;
  }
  signReport(result.report);

  res.setHeader('X-RateLimit-Limit', String(auth.limit));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, auth.limit - auth.used - 1)));
  res.setHeader('X-RateLimit-Reset-Month', month);
  res.setHeader('X-Zentric-Tier', auth.tier);
  sendJson(res, 200, result);

  try {
    const tasks = [];
    if (auth.kind === 'paid') {
      tasks.push(
        logReportRow(supabase, {
          reportId: result.report.report_id,
          userId: auth.userId,
          verdict: result.verdict,
          sha256: result.report.sha256,
          latencyMs: result.report.latency_ms,
        }),
        incrementPaidKey(supabase, auth.keyHash, auth.used),
      );
    } else if (auth.kind === 'free') {
      tasks.push(incrementFreeKey(supabase, auth.keyHash, auth.sameMonth, auth.currentMonth));
    }
    await Promise.all(tasks);
  } catch (err) {
    console.error('Post-response logging failed:', err);
  }
}

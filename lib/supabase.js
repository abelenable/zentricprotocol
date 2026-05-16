import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

let cachedClient = null;

export function getSupabase() {
  if (cachedClient) return cachedClient;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variable');
  }
  cachedClient = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { 'X-Client-Info': 'zentric-protocol-api/0.1.0' } },
  });
  return cachedClient;
}

export function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

export function currentMonthKey(now = new Date()) {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

export async function lookupApiKey(supabase, apiKey) {
  const keyHash = hashApiKey(apiKey);
  const { data, error } = await supabase
    .from('api_keys')
    .select('id, user_id, tier, is_active')
    .eq('key_hash', keyHash)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function getMonthlyUsage(supabase, userId, month) {
  const { data, error } = await supabase
    .from('api_usage')
    .select('request_count')
    .eq('user_id', userId)
    .eq('month', month)
    .maybeSingle();
  if (error) throw error;
  return data?.request_count ?? 0;
}

export async function incrementUsage(supabase, userId, month, previousCount) {
  if (previousCount === 0) {
    const { error } = await supabase
      .from('api_usage')
      .insert({ user_id: userId, month, request_count: 1 });
    if (error && error.code !== '23505') throw error;
    return;
  }
  const { error } = await supabase
    .from('api_usage')
    .update({ request_count: previousCount + 1 })
    .eq('user_id', userId)
    .eq('month', month);
  if (error) throw error;
}

export async function logReport(supabase, { reportId, userId, verdict, sha256, latencyMs }) {
  const { error } = await supabase.from('reports').insert({
    report_id: reportId,
    user_id: userId,
    verdict,
    sha256,
    latency_ms: latencyMs,
  });
  if (error) throw error;
}

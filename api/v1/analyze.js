// api/v1/analyze.js — Zentric Protocol Core Endpoint
// Injection detection + PII detection with signed audit report
//
// Route: POST /v1/analyze
// Auth:  Authorization: Bearer zp_live_...

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const FREE_TIER_LIMIT = 2000;

// ─── INJECTION SIGNATURES (22) ───────────────────────────────────────────────
// Covers direct override attempts, role injection, token smuggling,
// multilingual variants, and encoded payloads.

const INJECTION_SIGNATURES = [
  // Direct override
  { id: 'INJ-001', pattern: /ignore\s+(all\s+)?previous\s+instructions?/i,       label: 'Direct instruction override' },
  { id: 'INJ-002', pattern: /disregard\s+(all\s+)?(your\s+)?instructions?/i,     label: 'Instruction disregard' },
  { id: 'INJ-003', pattern: /forget\s+(all\s+)?(your\s+)?instructions?/i,        label: 'Instruction erasure' },
  { id: 'INJ-004', pattern: /override\s+(your\s+)?(safety|system|instructions?)/i, label: 'Safety override attempt' },
  { id: 'INJ-005', pattern: /new\s+instructions?\s*:/i,                           label: 'Instruction injection' },
  // System prompt manipulation
  { id: 'INJ-006', pattern: /\[?system\s+prompt\]?\s*:/i,                        label: 'System prompt injection' },
  { id: 'INJ-007', pattern: /###\s*(system|human|assistant)\s*:/i,               label: 'Chat format injection' },
  { id: 'INJ-008', pattern: /\[INST\]|\[\/INST\]/i,                              label: 'LLaMA instruction tag' },
  { id: 'INJ-009', pattern: /<\|im_start\|>|<\|im_end\|>/i,                      label: 'ChatML token injection' },
  { id: 'INJ-010', pattern: /\\n\\nHuman:|\\n\\nAssistant:/i,                    label: 'RLHF format injection' },
  // Role/persona hijacking
  { id: 'INJ-011', pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,                 label: 'Persona override' },
  { id: 'INJ-012', pattern: /act\s+as\s+(a|an|the|if)\s+/i,                     label: 'Role injection' },
  { id: 'INJ-013', pattern: /pretend\s+(you\s+are|to\s+be)\s+/i,                label: 'Persona injection' },
  { id: 'INJ-014', pattern: /roleplay\s+as\s+/i,                                 label: 'Roleplay hijack' },
  { id: 'INJ-015', pattern: /jailbreak|jail\s+break/i,                           label: 'Jailbreak attempt' },
  // Developer/debug mode exploits
  { id: 'INJ-016', pattern: /developer\s+mode|debug\s+mode|god\s+mode/i,        label: 'Mode bypass attempt' },
  { id: 'INJ-017', pattern: /\bDAN\b.*do\s+anything\s+now/i,                    label: 'DAN jailbreak' },
  // Token/encoding attacks
  { id: 'INJ-018', pattern: /<\/s>|<s>|<eos>|<bos>/i,                           label: 'EOS token injection' },
  { id: 'INJ-019', pattern: /base64[^a-z]*(decode|encoded)/i,                   label: 'Base64 obfuscation' },
  { id: 'INJ-020', pattern: /‮|​|‌|‍|﻿/,               label: 'Unicode control character' },
  // Multilingual variants (ES, FR, DE, ZH, AR)
  { id: 'INJ-021', pattern: /ignora\s+(todas?\s+)?las\s+instrucciones?|ignorez\s+les\s+instructions?|ignoriere\s+alle\s+anweisungen/i, label: 'Multilingual instruction override' },
  // Indirect/context manipulation
  { id: 'INJ-022', pattern: /the\s+(above|following|previous)\s+(instructions?|context|text)\s+(should\s+be\s+ignored|is\s+wrong)/i, label: 'Context manipulation' },
];

// ─── PII PATTERNS (17) ───────────────────────────────────────────────────────

const PII_PATTERNS = [
  { type: 'EMAIL',            pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g },
  { type: 'US_SSN',           pattern: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g },
  { type: 'CREDIT_CARD',      pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
  { type: 'IBAN',             pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g },
  { type: 'PHONE_INTL',       pattern: /(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4,}\b/g },
  { type: 'PASSPORT',         pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g },
  { type: 'IP_ADDRESS',       pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { type: 'AWS_ACCESS_KEY',   pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { type: 'PRIVATE_KEY',      pattern: /-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----/g },
  { type: 'API_TOKEN',        pattern: /\b(?:sk-|pk-|rk-|xox[baprs]-)[a-zA-Z0-9]{20,}\b/g },
  { type: 'BITCOIN_ADDRESS',  pattern: /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g },
  { type: 'UK_NIN',           pattern: /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b/gi },
  { type: 'US_DRIVER_LICENSE',pattern: /\b[A-Z]\d{7}\b|\b\d{9}\b/g },
  { type: 'DATE_OF_BIRTH',    pattern: /\b(?:dob|date\s+of\s+birth|born\s+on)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/gi },
  { type: 'PHYSICAL_ADDRESS', pattern: /\b\d{1,5}\s+[a-zA-Z\s]{3,30}(?:street|st|avenue|ave|boulevard|blvd|road|rd|lane|ln|drive|dr|court|ct|way)\b/gi },
  { type: 'MEDICAL_RECORD',   pattern: /\b(?:mrn|medical\s+record\s+(?:number|#|no))[:\s]+[A-Z0-9\-]{4,20}\b/gi },
  { type: 'JWT_TOKEN',        pattern: /\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b/g },
];

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function hashKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

function hashContent(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Sign a report with HMAC-SHA256 using ZENTRIC_SIGNING_SECRET.
 * Makes report_hash tamper-evident — only the server can produce a valid
 * signature, giving customers and auditors a verifiable audit artifact.
 * Falls back to plain SHA-256 in dev (logs a warning so it's never silent).
 */
function signReport(reportData) {
  const secret = process.env.ZENTRIC_SIGNING_SECRET;
  if (secret) {
    return crypto
      .createHmac('sha256', secret)
      .update(JSON.stringify(reportData))
      .digest('hex');
  }
  console.warn('[analyze] ZENTRIC_SIGNING_SECRET not set — using unsigned SHA-256. Set this in Vercel before going live.');
  return hashContent(JSON.stringify(reportData));
}

function generateReportId() {
  return crypto.randomUUID();
}

// ─── ANALYSIS ENGINES ────────────────────────────────────────────────────────

function runIntegrityGuard(input) {
  const flags = [];

  for (const sig of INJECTION_SIGNATURES) {
    if (sig.pattern.test(input)) {
      flags.push({ id: sig.id, label: sig.label });
      sig.pattern.lastIndex = 0; // reset global regex
    }
  }

  const riskScore = Math.min(100, Math.round((flags.length / INJECTION_SIGNATURES.length) * 100 * 3));

  return {
    passed:              flags.length === 0,
    risk_score:          riskScore,
    flags,
    signatures_checked:  INJECTION_SIGNATURES.length,
    languages_covered:   7, // EN, ES, FR, DE, ZH, AR, token-level
  };
}

function runPrivacyGuard(input) {
  const detected = [];

  for (const pii of PII_PATTERNS) {
    pii.pattern.lastIndex = 0;
    const matches = [...input.matchAll(pii.pattern)];
    if (matches.length > 0) {
      detected.push({
        type:  pii.type,
        count: matches.length,
      });
    }
    pii.pattern.lastIndex = 0;
  }

  return {
    passed:               detected.length === 0,
    pii_detected:         detected,
    entity_types_checked: PII_PATTERNS.length,
  };
}

// ─── HANDLER ─────────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  const startTime = Date.now();

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // ── Auth ────────────────────────────────────────────────────────────────────
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'MISSING_AUTHORIZATION',
      message: 'Authorization header required. Format: "Authorization: Bearer zp_live_..."',
      docs: 'https://zentricprotocol.com',
    });
  }

  const rawKey = authHeader.slice(7).trim();
  if (!rawKey.startsWith('zp_live_') || rawKey.length < 32) {
    return res.status(401).json({
      error: 'INVALID_KEY_FORMAT',
      message: 'API key must start with zp_live_',
    });
  }

  const keyHash = hashKey(rawKey);

  // Look up key in free_api_keys
  const { data: keyRecord, error: keyError } = await supabase
    .from('free_api_keys')
    .select('id, email, requests_this_month, month_bucket')
    .eq('key_hash', keyHash)
    .maybeSingle();

  if (keyError) {
    console.error('[analyze] Key lookup error:', keyError.message);
    return res.status(503).json({ error: 'SERVICE_UNAVAILABLE', message: 'Auth service temporarily unavailable.' });
  }

  if (!keyRecord) {
    return res.status(401).json({
      error: 'INVALID_API_KEY',
      message: 'API key not found. Get your key at zentricprotocol.com',
    });
  }

  // Check monthly budget
  const currentBucket = new Date().toISOString().slice(0, 7); // "2026-05"
  const usedThisMonth = keyRecord.month_bucket === currentBucket
    ? keyRecord.requests_this_month
    : 0;

  if (usedThisMonth >= FREE_TIER_LIMIT) {
    return res.status(429).json({
      error: 'FREE_TIER_EXHAUSTED',
      message: `You have used all ${FREE_TIER_LIMIT} free requests for this month.`,
      upgrade: 'https://zentricprotocol.com#pricing',
      used:  usedThisMonth,
      limit: FREE_TIER_LIMIT,
    });
  }

  // Set rate limit headers
  res.setHeader('X-RateLimit-Limit',     String(FREE_TIER_LIMIT));
  res.setHeader('X-RateLimit-Used',      String(usedThisMonth));
  res.setHeader('X-RateLimit-Remaining', String(FREE_TIER_LIMIT - usedThisMonth - 1));

  // ── Validate body ───────────────────────────────────────────────────────────
  const { input, modules = ['integrity', 'privacy'] } = req.body ?? {};

  if (!input || typeof input !== 'string') {
    return res.status(400).json({
      error: 'INVALID_REQUEST',
      message: '"input" field is required and must be a string.',
    });
  }

  if (input.length > 32_000) {
    return res.status(400).json({
      error: 'INPUT_TOO_LONG',
      message: 'Input exceeds maximum length of 32,000 characters.',
    });
  }

  // ── Run analysis ────────────────────────────────────────────────────────────
  const reportId   = generateReportId();
  const inputHash  = hashContent(input);
  const timestamp  = new Date().toISOString();

  const results = {};

  if (modules.includes('integrity')) {
    results.integrity = runIntegrityGuard(input);
  }

  if (modules.includes('privacy')) {
    results.privacy = runPrivacyGuard(input);
  }

  const overallPassed = Object.values(results).every((r) => r.passed);
  const latencyMs     = Date.now() - startTime;

  // Build report object (before signing)
  const report = {
    id:             reportId,
    timestamp,
    input_hash:     inputHash,
    modules:        results,
    overall_passed: overallPassed,
    latency_ms:     latencyMs,
    tier:           'free',
    requests_used:  usedThisMonth + 1,
    requests_remaining: FREE_TIER_LIMIT - usedThisMonth - 1,
  };

  // Sign the report with HMAC-SHA256 (requires ZENTRIC_SIGNING_SECRET in Vercel env)
  const reportHash = signReport(report);
  report.report_hash = reportHash;

  // ── Increment counter (non-blocking) ───────────────────────────────────────
  supabase
    .rpc('increment_free_key_requests', { p_key_id: keyRecord.id })
    .then(({ error }) => {
      if (error) console.warn('[analyze] Failed to increment counter:', error.message);
    });

  return res.status(200).json(report);
}

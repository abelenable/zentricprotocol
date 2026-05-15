/**
 * Zentric Protocol — Rate Limiter Middleware
 *
 * Enforces per-tier request limits using Supabase as the counter store.
 * Runs after requireValidLicense, so req.zentric is guaranteed to be set.
 *
 * Tier limits (per calendar month):
 *   free        → 500 requests  (no subscription required)
 *   growth      → 100,000 requests
 *   enterprise  → unlimited
 *
 * Rate limiting is also applied per-minute to prevent burst abuse:
 *   free        → 10 req/min
 *   growth      → 60 req/min
 *   enterprise  → 300 req/min
 *
 * Environment variables required:
 *   SUPABASE_URL              — Your Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY — Service role key
 */

'use strict';

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ---------------------------------------------------------------------------
// Tier configuration
// ---------------------------------------------------------------------------
const TIER_LIMITS = {
  free: {
    monthly:    2000, // matches FREE_TIER_LIMIT in /api/v1/analyze.js and landing copy
    perMinute:  10,
    label:      'Free Tier',
  },
  growth: {
    monthly:    100_000,
    perMinute:  60,
    label:      'Growth',
  },
  enterprise: {
    monthly:    Infinity,
    perMinute:  300,
    label:      'Enterprise',
  },
};

// In-memory per-minute window (resets on cold start — acceptable for burst control)
// For distributed deployments, replace with Redis or Supabase-based counters.
const minuteWindows = new Map(); // keyId → { count, windowStart }

// ---------------------------------------------------------------------------
// Per-minute rate check (in-memory, lightweight)
// ---------------------------------------------------------------------------
function checkMinuteLimit(keyId, perMinuteLimit) {
  const now = Date.now();
  const windowDuration = 60 * 1000; // 1 minute

  const window = minuteWindows.get(keyId) ?? { count: 0, windowStart: now };

  if (now - window.windowStart > windowDuration) {
    // New window
    minuteWindows.set(keyId, { count: 1, windowStart: now });
    return { allowed: true, remaining: perMinuteLimit - 1 };
  }

  if (window.count >= perMinuteLimit) {
    const resetIn = Math.ceil((windowDuration - (now - window.windowStart)) / 1000);
    return { allowed: false, remaining: 0, resetIn };
  }

  window.count += 1;
  minuteWindows.set(keyId, window);
  return { allowed: true, remaining: perMinuteLimit - window.count };
}

// ---------------------------------------------------------------------------
// Core middleware
// ---------------------------------------------------------------------------

/**
 * enforceRateLimit
 *
 * Must run after requireValidLicense. Checks monthly and per-minute limits,
 * then increments the monthly counter in Supabase on success.
 *
 * Sets response headers:
 *   X-RateLimit-Tier      — Current plan tier
 *   X-RateLimit-Limit     — Monthly request limit
 *   X-RateLimit-Used      — Requests used this month
 *   X-RateLimit-Remaining — Requests remaining this month
 */
async function enforceRateLimit(req, res, next) {
  try {
    const { keyId, tier, requestsThisMonth } = req.zentric;
    const limits = TIER_LIMITS[tier] ?? TIER_LIMITS.free;

    // ------------------------------------------------------------------
    // Monthly limit check (enterprise = unlimited, skip check)
    // ------------------------------------------------------------------
    if (limits.monthly !== Infinity && requestsThisMonth >= limits.monthly) {
      res.set({
        'X-RateLimit-Tier':      tier,
        'X-RateLimit-Limit':     String(limits.monthly),
        'X-RateLimit-Used':      String(requestsThisMonth),
        'X-RateLimit-Remaining': '0',
      });

      return res.status(429).json({
        error: 'MONTHLY_LIMIT_EXCEEDED',
        message:
          `You have used all ${limits.monthly.toLocaleString()} requests included in your ` +
          `${limits.label} plan for this month. ` +
          (tier === 'free'
            ? 'Upgrade to Growth for 100,000 requests/month.'
            : 'Contact core@zentricprotocol.com to discuss Enterprise.'),
        upgrade: 'https://zentricprotocol.com#pricing',
        used:    requestsThisMonth,
        limit:   limits.monthly,
      });
    }

    // ------------------------------------------------------------------
    // Per-minute burst check
    // ------------------------------------------------------------------
    const { allowed, remaining: minuteRemaining, resetIn } = checkMinuteLimit(
      keyId,
      limits.perMinute
    );

    if (!allowed) {
      res.set('Retry-After', String(resetIn));
      return res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        message:
          `Too many requests. ${limits.label} tier allows ${limits.perMinute} requests/minute.`,
        retryAfterSeconds: resetIn,
      });
    }

    // ------------------------------------------------------------------
    // Set informational headers
    // ------------------------------------------------------------------
    const monthlyRemaining =
      limits.monthly === Infinity ? 'unlimited' : String(limits.monthly - requestsThisMonth - 1);

    res.set({
      'X-RateLimit-Tier':          tier,
      'X-RateLimit-Limit':         limits.monthly === Infinity ? 'unlimited' : String(limits.monthly),
      'X-RateLimit-Used':          String(requestsThisMonth),
      'X-RateLimit-Remaining':     monthlyRemaining,
      'X-RateLimit-Minute-Remaining': String(minuteRemaining),
    });

    // ------------------------------------------------------------------
    // Increment monthly counter in Supabase (non-blocking)
    // ------------------------------------------------------------------
    supabase.rpc('increment_api_key_requests', { key_id: keyId }).then(({ error }) => {
      if (error) console.warn('[rateLimiter] Failed to increment counter:', error.message);
    });

    return next();
  } catch (err) {
    console.error('[rateLimiter] Unexpected error:', err);
    // Fail open on rate limiter errors — don't block legitimate requests
    // due to a counter service outage. Log and continue.
    return next();
  }
}

module.exports = { enforceRateLimit, TIER_LIMITS };

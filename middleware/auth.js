/**
 * Zentric Protocol — Authentication Middleware
 *
 * Validates every inbound API request against:
 *   1. API key format and existence (Supabase api_keys table)
 *   2. Active subscription status (Supabase subscriptions table, synced from Stripe)
 *   3. Free-tier request budget (500 requests before subscription required)
 *
 * The detection engine (IntegrityGuard, PrivacyGuard) is proprietary and not
 * included in this repository. This middleware is the enforcement boundary
 * between the public network and that engine.
 *
 * Environment variables required:
 *   SUPABASE_URL              — Your Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY — Service role key (server-side only, never expose)
 */

'use strict';

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Supabase client (service role — bypasses RLS for server-side auth checks)
// ---------------------------------------------------------------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const FREE_TIER_REQUEST_LIMIT = 500;
const VALID_KEY_PREFIXES = ['zp_live_', 'zp_test_'];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Hash an API key with SHA-256 before comparing against the database.
 * Raw keys are never stored — only their hashes.
 */
function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

/**
 * Return a consistent 401 response without leaking whether the key exists.
 */
function unauthorized(res, code, message) {
  return res.status(401).json({
    error: code,
    message,
    docs: 'https://zentricprotocol.com#api',
  });
}

/**
 * Return a 402 Payment Required response with upgrade information.
 */
function paymentRequired(res, code, message) {
  return res.status(402).json({
    error: code,
    message,
    upgrade: 'https://zentricprotocol.com#pricing',
    contact: 'core@zentricprotocol.com',
  });
}

// ---------------------------------------------------------------------------
// Core middleware
// ---------------------------------------------------------------------------

/**
 * requireValidLicense
 *
 * Express-compatible middleware. Attach to any route that calls the
 * Zentric detection engine. On success, populates req.zentric with:
 *
 *   req.zentric.userId            — Supabase user ID
 *   req.zentric.tier              — 'free' | 'growth' | 'enterprise'
 *   req.zentric.requestsThisMonth — integer, current month usage
 *   req.zentric.subscriptionStatus — Stripe status string
 *   req.zentric.keyId             — api_keys row UUID (for usage tracking)
 */
async function requireValidLicense(req, res, next) {
  try {
    // ------------------------------------------------------------------
    // Step 1 — Extract and validate API key format
    // ------------------------------------------------------------------
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized(
        res,
        'MISSING_AUTHORIZATION',
        'Authorization header is required. Format: "Authorization: Bearer zp_live_..."'
      );
    }

    const rawKey = authHeader.slice(7).trim();
    const hasValidPrefix = VALID_KEY_PREFIXES.some((p) => rawKey.startsWith(p));

    if (!hasValidPrefix || rawKey.length < 32) {
      return unauthorized(
        res,
        'INVALID_KEY_FORMAT',
        `API key must start with one of: ${VALID_KEY_PREFIXES.join(', ')}`
      );
    }

    // ------------------------------------------------------------------
    // Step 2 — Look up the hashed key in Supabase
    // ------------------------------------------------------------------
    const keyHash = hashApiKey(rawKey);

    const { data: keyRecord, error: keyError } = await supabase
      .from('api_keys')
      .select('id, user_id, tier, requests_this_month, revoked_at, last_used_at')
      .eq('key_hash', keyHash)
      .maybeSingle();

    if (keyError) {
      console.error('[auth] Supabase key lookup error:', keyError.message);
      return res.status(503).json({
        error: 'AUTH_SERVICE_UNAVAILABLE',
        message: 'Authentication service temporarily unavailable. Please retry.',
      });
    }

    if (!keyRecord) {
      return unauthorized(
        res,
        'INVALID_API_KEY',
        'API key not found. Generate your key at zentricprotocol.com'
      );
    }

    if (keyRecord.revoked_at) {
      return unauthorized(
        res,
        'REVOKED_API_KEY',
        'This API key has been revoked. Generate a new key at zentricprotocol.com/dashboard'
      );
    }

    // ------------------------------------------------------------------
    // Step 3 — Check subscription status
    //
    // Logic:
    //   a) If under FREE_TIER_REQUEST_LIMIT → allow (free trial)
    //   b) Otherwise → require active Stripe subscription
    // ------------------------------------------------------------------
    const underFreeTier =
      !keyRecord.tier || keyRecord.tier === 'free'
        ? keyRecord.requests_this_month < FREE_TIER_REQUEST_LIMIT
        : false;

    let subscription = null;

    if (!underFreeTier) {
      const { data: sub, error: subError } = await supabase
        .from('subscriptions')
        .select('status, plan, current_period_end, stripe_subscription_id')
        .eq('user_id', keyRecord.user_id)
        .maybeSingle();

      if (subError) {
        console.error('[auth] Supabase subscription lookup error:', subError.message);
        return res.status(503).json({
          error: 'AUTH_SERVICE_UNAVAILABLE',
          message: 'Subscription verification temporarily unavailable. Please retry.',
        });
      }

      if (!sub) {
        return paymentRequired(
          res,
          'NO_ACTIVE_SUBSCRIPTION',
          `Your free trial (${FREE_TIER_REQUEST_LIMIT} requests) has been used. ` +
            'A Growth or Enterprise subscription is required to continue.'
        );
      }

      if (!['active', 'trialing'].includes(sub.status)) {
        const statusMessages = {
          past_due:  'Your subscription payment has failed. Please update your payment method.',
          canceled:  'Your subscription has been canceled. Reactivate at zentricprotocol.com.',
          unpaid:    'Your subscription is unpaid. Please update your payment method.',
          paused:    'Your subscription is paused. Resume it at zentricprotocol.com.',
        };
        return paymentRequired(
          res,
          'SUBSCRIPTION_INACTIVE',
          statusMessages[sub.status] ||
            `Subscription status: "${sub.status}". Contact core@zentricprotocol.com for help.`
        );
      }

      subscription = sub;
    }

    // ------------------------------------------------------------------
    // Step 4 — Attach context to request object
    // ------------------------------------------------------------------
    req.zentric = {
      keyId:                keyRecord.id,
      userId:               keyRecord.user_id,
      tier:                 subscription?.plan ?? 'free',
      requestsThisMonth:    keyRecord.requests_this_month,
      subscriptionStatus:   subscription?.status ?? 'free_trial',
      isFreeTier:           underFreeTier,
    };

    // ------------------------------------------------------------------
    // Step 5 — Update last_used_at asynchronously (non-blocking)
    // ------------------------------------------------------------------
    supabase
      .from('api_keys')
      .update({ last_used_at: new Date().toISOString() })
      .eq('id', keyRecord.id)
      .then(({ error }) => {
        if (error) console.warn('[auth] Failed to update last_used_at:', error.message);
      });

    return next();
  } catch (err) {
    console.error('[auth] Unexpected middleware error:', err);
    return res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred during authentication.',
    });
  }
}

module.exports = { requireValidLicense, hashApiKey };

-- =============================================================================
-- Zentric Protocol — Supabase Database Schema
-- Migration: 001_schema.sql
--
-- Tables:
--   api_keys       → issued API keys per user (hashed, never plaintext)
--   subscriptions  → Stripe subscription state (synced via webhook)
--
-- Run via Supabase CLI:
--   supabase db push
--
-- Or apply manually in the Supabase SQL editor.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Extensions
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- -----------------------------------------------------------------------------
-- subscriptions
--
-- One row per Stripe subscription. Synced in real time by the Stripe webhook
-- handler (/api/webhooks/stripe.js). The auth middleware reads this table to
-- verify that a user has a paid, active subscription before allowing API access.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscriptions (
  id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 UUID        REFERENCES auth.users(id) ON DELETE CASCADE,
  stripe_customer_id      TEXT        UNIQUE,
  stripe_subscription_id  TEXT        UNIQUE NOT NULL,
  status                  TEXT        NOT NULL DEFAULT 'incomplete',
  -- status values mirror Stripe: active | trialing | past_due | canceled | unpaid | paused
  plan                    TEXT        NOT NULL DEFAULT 'growth',
  -- plan: free | growth | enterprise
  current_period_end      TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for the auth middleware's subscription lookup (hot path)
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id
  ON public.subscriptions (user_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer_id
  ON public.subscriptions (stripe_customer_id);

-- RLS: users can read their own subscription; service role bypasses RLS
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own subscription"
  ON public.subscriptions
  FOR SELECT
  USING (auth.uid() = user_id);

-- Service role (used by webhook and auth middleware) bypasses RLS automatically.


-- -----------------------------------------------------------------------------
-- api_keys
--
-- One or more API keys per user. The raw key is never stored — only its
-- SHA-256 hash. When a user presents a key, we hash it and look up the record.
--
-- Key format: zp_live_<32+ random chars> or zp_test_<32+ random chars>
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  key_hash             TEXT        NOT NULL UNIQUE,  -- SHA-256 of the raw key
  key_prefix           TEXT        NOT NULL,         -- first 12 chars for display (e.g. "zp_live_xkQ3")
  tier                 TEXT        NOT NULL DEFAULT 'free',
  label                TEXT        DEFAULT 'Default',
  requests_this_month  INTEGER     NOT NULL DEFAULT 0,
  month_bucket         TEXT        NOT NULL DEFAULT TO_CHAR(NOW(), 'YYYY-MM'),
  -- month_bucket resets counter logic: '2026-05', '2026-06', etc.
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at         TIMESTAMPTZ,
  revoked_at           TIMESTAMPTZ
);

-- Index for the auth middleware's key lookup (hot path)
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
  ON public.api_keys (key_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id
  ON public.api_keys (user_id);

-- RLS: users can read and manage their own keys
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own keys"
  ON public.api_keys
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own keys"
  ON public.api_keys
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own keys"
  ON public.api_keys
  FOR UPDATE
  USING (auth.uid() = user_id);


-- -----------------------------------------------------------------------------
-- Function: increment_api_key_requests
--
-- Called by the rate limiter middleware after every successful API request.
-- Resets the counter automatically when the month_bucket changes.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.increment_api_key_requests(key_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER  -- runs as postgres, bypasses RLS
AS $$
DECLARE
  current_bucket TEXT := TO_CHAR(NOW(), 'YYYY-MM');
  stored_bucket  TEXT;
BEGIN
  SELECT month_bucket INTO stored_bucket
  FROM public.api_keys
  WHERE id = key_id;

  IF stored_bucket IS DISTINCT FROM current_bucket THEN
    -- New month — reset counter
    UPDATE public.api_keys
    SET requests_this_month = 1,
        month_bucket        = current_bucket,
        last_used_at        = NOW()
    WHERE id = key_id;
  ELSE
    -- Same month — increment
    UPDATE public.api_keys
    SET requests_this_month = requests_this_month + 1,
        last_used_at        = NOW()
    WHERE id = key_id;
  END IF;
END;
$$;


-- -----------------------------------------------------------------------------
-- Function: generate_api_key_prefix
--
-- Helper to store only the display prefix (first 12 chars) of each key,
-- so users can identify their keys in the dashboard without exposing the secret.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.generate_api_key_prefix(raw_key TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT SUBSTRING(raw_key FROM 1 FOR 12) || '...';
$$;


-- -----------------------------------------------------------------------------
-- Trigger: auto-reset month bucket on api_keys insert
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_api_key_month_bucket()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.month_bucket := TO_CHAR(NOW(), 'YYYY-MM');
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_api_keys_set_month_bucket
  BEFORE INSERT ON public.api_keys
  FOR EACH ROW
  EXECUTE FUNCTION public.set_api_key_month_bucket();

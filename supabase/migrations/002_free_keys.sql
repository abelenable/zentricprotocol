-- Migration 002: Free tier API keys (email-based, no Supabase Auth required)
-- Supports the PLG waitlist → instant API key flow

CREATE TABLE IF NOT EXISTS free_api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  key_hash      TEXT NOT NULL UNIQUE,   -- SHA-256 of the raw key
  key_prefix    TEXT NOT NULL,          -- e.g. "zp_live_a1b2c3" (display only)
  requests_this_month INT NOT NULL DEFAULT 0,
  month_bucket  TEXT NOT NULL,          -- e.g. "2026-05"
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ
);

-- Auto-reset monthly counter when month changes
CREATE OR REPLACE FUNCTION increment_free_key_requests(p_key_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  current_bucket TEXT := to_char(now(), 'YYYY-MM');
BEGIN
  UPDATE free_api_keys
  SET
    requests_this_month = CASE
      WHEN month_bucket = current_bucket THEN requests_this_month + 1
      ELSE 1
    END,
    month_bucket = current_bucket,
    last_used_at = now()
  WHERE id = p_key_id;
END;
$$;

-- RLS: service role only (API key lookup happens server-side)
ALTER TABLE free_api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access"
  ON free_api_keys
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

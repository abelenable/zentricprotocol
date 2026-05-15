// api/waitlist.js — Vercel Serverless Function
// PLG flow: email submitted → API key generated → welcome email sent instantly

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const FREE_TIER_LIMIT = 500;

function generateApiKey() {
  const random = crypto.randomBytes(24).toString('hex');
  return `zp_live_${random}`;
}

function hashKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

function getMonthBucket() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

async function sendWelcomeEmail(email, apiKey) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Zentric Protocol <core@zentricprotocol.com>',
      to: email,
      subject: 'Your Zentric Protocol API key — 500 free requests',
      html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0A0A0A;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0A0A0A;padding:48px 24px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

          <!-- Logo -->
          <tr>
            <td style="padding-bottom:32px;">
              <span style="font-family:monospace;font-size:11px;letter-spacing:0.2em;color:#00FFC2;text-transform:uppercase;">ZENTRIC PROTOCOL</span>
            </td>
          </tr>

          <!-- Headline -->
          <tr>
            <td style="padding-bottom:24px;border-bottom:1px solid rgba(245,245,245,0.08);">
              <h1 style="margin:0;font-size:28px;font-weight:700;color:#F5F5F5;letter-spacing:-0.04em;line-height:1.2;">
                Your API key is ready.
              </h1>
              <p style="margin:12px 0 0;font-size:15px;color:rgba(245,245,245,0.6);line-height:1.6;">
                500 free requests. No credit card required. Save this key — it won't be shown again.
              </p>
            </td>
          </tr>

          <!-- API Key -->
          <tr>
            <td style="padding:24px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 8px;font-family:monospace;font-size:10px;letter-spacing:0.18em;color:rgba(245,245,245,0.4);text-transform:uppercase;">Your API Key</p>
              <div style="background:rgba(245,245,245,0.04);border:1px solid rgba(245,245,245,0.1);border-radius:6px;padding:14px 16px;">
                <code style="font-family:monospace;font-size:13px;color:#00FFC2;word-break:break-all;">${apiKey}</code>
              </div>
            </td>
          </tr>

          <!-- First call -->
          <tr>
            <td style="padding:24px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 12px;font-size:14px;font-weight:600;color:#F5F5F5;">Make your first call</p>
              <div style="background:rgba(245,245,245,0.04);border:1px solid rgba(245,245,245,0.1);border-radius:6px;padding:16px;">
                <pre style="margin:0;font-family:monospace;font-size:12px;color:rgba(245,245,245,0.8);white-space:pre-wrap;word-break:break-all;">curl -X POST https://api.zentricprotocol.com/v1/analyze \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "input": "your user input here",
    "modules": ["integrity", "privacy"]
  }'</pre>
              </div>
            </td>
          </tr>

          <!-- What you get -->
          <tr>
            <td style="padding:24px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 16px;font-size:14px;font-weight:600;color:#F5F5F5;">What each request returns</p>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:6px 0;">
                    <span style="display:inline-block;width:6px;height:6px;background:#00FFC2;border-radius:50%;margin-right:10px;vertical-align:middle;"></span>
                    <span style="font-size:13px;color:rgba(245,245,245,0.7);">Injection detection across 22 signatures, 7 languages</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:6px 0;">
                    <span style="display:inline-block;width:6px;height:6px;background:#00FFC2;border-radius:50%;margin-right:10px;vertical-align:middle;"></span>
                    <span style="font-size:13px;color:rgba(245,245,245,0.7);">PII detection — 17 entity types (SSN, IBAN, email, passport...)</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:6px 0;">
                    <span style="display:inline-block;width:6px;height:6px;background:#00FFC2;border-radius:50%;margin-right:10px;vertical-align:middle;"></span>
                    <span style="font-size:13px;color:rgba(245,245,245,0.7);">SHA-256 signed audit report — UUID + timestamp UTC</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:6px 0;">
                    <span style="display:inline-block;width:6px;height:6px;background:#00FFC2;border-radius:50%;margin-right:10px;vertical-align:middle;"></span>
                    <span style="font-size:13px;color:rgba(245,245,245,0.7);">Mean latency: 23.4ms</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td style="padding:32px 0 0;">
              <p style="margin:0 0 16px;font-size:13px;color:rgba(245,245,245,0.5);line-height:1.6;">
                Questions? Reply to this email or reach us at
                <a href="mailto:core@zentricprotocol.com" style="color:#00FFC2;text-decoration:none;">core@zentricprotocol.com</a>
              </p>
              <p style="margin:0;font-size:11px;color:rgba(245,245,245,0.3);font-family:monospace;letter-spacing:0.1em;">
                ZENTRIC PROTOCOL · zentricprotocol.com · © ZP MMXXVI
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
      `,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Resend error: ${error}`);
  }

  return response.json();
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', 'https://zentricprotocol.com');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email } = req.body;

  // Validate email
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Check if email already registered
    const { data: existing } = await supabase
      .from('free_api_keys')
      .select('key_prefix')
      .eq('email', normalizedEmail)
      .single();

    if (existing) {
      return res.status(200).json({
        success: true,
        message: 'already_registered',
        hint: 'Check your inbox — your API key was already sent.',
      });
    }

    // Generate API key
    const rawKey = generateApiKey();
    const keyHash = hashKey(rawKey);
    const keyPrefix = rawKey.substring(0, 16); // "zp_live_a1b2c3xx"

    // Store in Supabase
    const { error: insertError } = await supabase
      .from('free_api_keys')
      .insert({
        email: normalizedEmail,
        key_hash: keyHash,
        key_prefix: keyPrefix,
        requests_this_month: 0,
        month_bucket: getMonthBucket(),
      });

    if (insertError) throw insertError;

    // Send welcome email
    await sendWelcomeEmail(normalizedEmail, rawKey);

    return res.status(200).json({
      success: true,
      message: 'api_key_sent',
      hint: 'Check your inbox (and spam folder) for your API key.',
    });

  } catch (error) {
    console.error('Waitlist error:', error);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
}

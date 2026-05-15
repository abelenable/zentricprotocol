/**
 * Zentric Protocol — Stripe Webhook Handler
 *
 * Keeps the Supabase `subscriptions` table in sync with Stripe in real time.
 * This is the single source of truth for subscription status.
 *
 * Handles:
 *   customer.subscription.created/updated/deleted
 *   invoice.paid / invoice.payment_failed
 *
 * IMPORTANT: bodyParser is disabled (export const config below) so Vercel
 * passes the raw request stream through. stripe.webhooks.constructEvent()
 * requires the raw Buffer — a parsed JS object always fails HMAC verification.
 *
 * Environment variables required:
 *   STRIPE_SECRET_KEY       — sk_live_...
 *   STRIPE_WEBHOOK_SECRET   — whsec_... (from Stripe Dashboard → Webhooks)
 *   STRIPE_PRICE_GROWTH     — Stripe Price ID for the Growth plan
 *   STRIPE_PRICE_ENTERPRISE — Stripe Price ID for the Enterprise plan
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 */

import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';

// Disable Vercel's automatic body parsing — required for Stripe signature verification
export const config = {
  api: {
    bodyParser: false,
  },
};

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ---------------------------------------------------------------------------
// Raw body collector — reads the Node.js IncomingMessage stream into a Buffer
// ---------------------------------------------------------------------------
async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// Map Stripe Price IDs → internal plan names
// ---------------------------------------------------------------------------
function getPlanFromPriceId(priceId) {
  const map = {
    [process.env.STRIPE_PRICE_GROWTH]:     'growth',
    [process.env.STRIPE_PRICE_ENTERPRISE]: 'enterprise',
  };
  return map[priceId] ?? 'growth';
}

// ---------------------------------------------------------------------------
// Supabase helpers
// ---------------------------------------------------------------------------

async function upsertSubscription(payload) {
  const { error } = await supabase
    .from('subscriptions')
    .upsert(payload, { onConflict: 'stripe_subscription_id' });
  if (error) {
    console.error('[stripe-webhook] upsertSubscription error:', error.message);
    throw error;
  }
}

async function updateSubscriptionByStripeId(stripeSubscriptionId, updates) {
  const { error } = await supabase
    .from('subscriptions')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('stripe_subscription_id', stripeSubscriptionId);
  if (error) {
    console.error('[stripe-webhook] updateSubscription error:', error.message);
    throw error;
  }
}

async function resolveUserId(stripeCustomerId) {
  try {
    const customer = await stripe.customers.retrieve(stripeCustomerId);
    if (customer.metadata?.supabase_user_id) return customer.metadata.supabase_user_id;
  } catch (err) {
    console.warn('[stripe-webhook] Could not retrieve Stripe customer:', err.message);
  }
  const { data } = await supabase
    .from('subscriptions')
    .select('user_id')
    .eq('stripe_customer_id', stripeCustomerId)
    .maybeSingle();
  return data?.user_id ?? null;
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

async function handleSubscriptionCreated(subscription) {
  const priceId = subscription.items.data[0]?.price?.id;
  const plan    = getPlanFromPriceId(priceId);
  const userId  = await resolveUserId(subscription.customer);

  await upsertSubscription({
    stripe_customer_id:     subscription.customer,
    stripe_subscription_id: subscription.id,
    user_id:                userId,
    status:                 subscription.status,
    plan,
    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
    updated_at:         new Date().toISOString(),
  });
  console.log(`[stripe-webhook] created: ${subscription.id} → ${plan} (${subscription.status})`);
}

async function handleSubscriptionUpdated(subscription) {
  const priceId = subscription.items.data[0]?.price?.id;
  const plan    = getPlanFromPriceId(priceId);

  await updateSubscriptionByStripeId(subscription.id, {
    status: subscription.status,
    plan,
    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
  });
  console.log(`[stripe-webhook] updated: ${subscription.id} → ${plan} (${subscription.status})`);
}

async function handleSubscriptionDeleted(subscription) {
  await updateSubscriptionByStripeId(subscription.id, { status: 'canceled' });
  console.log(`[stripe-webhook] canceled: ${subscription.id}`);
}

async function handleInvoicePaid(invoice) {
  if (!invoice.subscription) return;
  await updateSubscriptionByStripeId(invoice.subscription, { status: 'active' });
  console.log(`[stripe-webhook] invoice paid → active: ${invoice.subscription}`);
}

async function handleInvoicePaymentFailed(invoice) {
  if (!invoice.subscription) return;
  await updateSubscriptionByStripeId(invoice.subscription, { status: 'past_due' });
  console.log(`[stripe-webhook] payment failed → past_due: ${invoice.subscription}`);
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).json({ error: 'Missing stripe-signature header' });

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (err) {
    console.error('[stripe-webhook] Failed to read body:', err.message);
    return res.status(400).json({ error: 'Could not read request body' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[stripe-webhook] Signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook signature error: ${err.message}` });
  }

  console.log(`[stripe-webhook] Event received: ${event.type}`);

  try {
    switch (event.type) {
      case 'customer.subscription.created':  await handleSubscriptionCreated(event.data.object); break;
      case 'customer.subscription.updated':  await handleSubscriptionUpdated(event.data.object); break;
      case 'customer.subscription.deleted':  await handleSubscriptionDeleted(event.data.object); break;
      case 'invoice.paid':                   await handleInvoicePaid(event.data.object);          break;
      case 'invoice.payment_failed':         await handleInvoicePaymentFailed(event.data.object); break;
      default: console.log(`[stripe-webhook] Unhandled event: ${event.type}`);
    }
    return res.status(200).json({ received: true, event: event.type });
  } catch (err) {
    console.error(`[stripe-webhook] Handler error for ${event.type}:`, err);
    return res.status(500).json({ error: 'Webhook handler failed' });
  }
}

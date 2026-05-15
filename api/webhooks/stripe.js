/**
 * Zentric Protocol — Stripe Webhook Handler
 *
 * Keeps the Supabase `subscriptions` table in sync with Stripe in real time.
 * This is the single source of truth for subscription status — the auth
 * middleware reads from this table to gate API access.
 *
 * Handles the following Stripe events:
 *   customer.subscription.created   → upsert subscription as active/trialing
 *   customer.subscription.updated   → sync status and plan changes
 *   customer.subscription.deleted   → mark as canceled
 *   invoice.paid                    → mark as active (after renewal)
 *   invoice.payment_failed          → mark as past_due
 *   customer.created                → link Stripe customer to Supabase user
 *
 * Deploy this as a Vercel Serverless Function:
 *   Vercel route:  /api/webhooks/stripe
 *   Stripe config: Dashboard → Webhooks → Add endpoint
 *
 * IMPORTANT: Vercel must receive the raw body for signature verification.
 * Disable body parsing in vercel.json for this route (see vercel.json).
 *
 * Environment variables required:
 *   STRIPE_SECRET_KEY       — sk_live_... (never expose client-side)
 *   STRIPE_WEBHOOK_SECRET   — whsec_... (from Stripe webhook settings)
 *   STRIPE_PRICE_GROWTH     — Stripe price ID for the Growth plan
 *   STRIPE_PRICE_ENTERPRISE — Stripe price ID for the Enterprise plan
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 */

'use strict';

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ---------------------------------------------------------------------------
// Map Stripe Price IDs → internal plan names
// ---------------------------------------------------------------------------
function getPlanFromPriceId(priceId) {
  const map = {
    [process.env.STRIPE_PRICE_GROWTH]:      'growth',
    [process.env.STRIPE_PRICE_ENTERPRISE]:  'enterprise',
  };
  return map[priceId] ?? 'growth'; // default to growth if price ID unknown
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

async function updateSubscriptionByCustomerId(stripeCustomerId, updates) {
  const { error } = await supabase
    .from('subscriptions')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('stripe_customer_id', stripeCustomerId);

  if (error) {
    console.error('[stripe-webhook] updateByCustomer error:', error.message);
    throw error;
  }
}

/**
 * Resolve Supabase user_id from Stripe customer metadata.
 * When creating a Stripe customer, set metadata.supabase_user_id.
 */
async function resolveUserId(stripeCustomerId) {
  // First try customer metadata
  try {
    const customer = await stripe.customers.retrieve(stripeCustomerId);
    if (customer.metadata?.supabase_user_id) {
      return customer.metadata.supabase_user_id;
    }
  } catch (err) {
    console.warn('[stripe-webhook] Could not retrieve Stripe customer:', err.message);
  }

  // Fallback: look up by stripe_customer_id in existing subscription row
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
  const plan = getPlanFromPriceId(priceId);
  const userId = await resolveUserId(subscription.customer);

  await upsertSubscription({
    stripe_customer_id:      subscription.customer,
    stripe_subscription_id:  subscription.id,
    user_id:                 userId,
    status:                  subscription.status,
    plan,
    current_period_end:      new Date(subscription.current_period_end * 1000).toISOString(),
    updated_at:              new Date().toISOString(),
  });

  console.log(`[stripe-webhook] Subscription created: ${subscription.id} → ${plan} (${subscription.status})`);
}

async function handleSubscriptionUpdated(subscription) {
  const priceId = subscription.items.data[0]?.price?.id;
  const plan = getPlanFromPriceId(priceId);

  await updateSubscriptionByStripeId(subscription.id, {
    status:             subscription.status,
    plan,
    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
  });

  console.log(`[stripe-webhook] Subscription updated: ${subscription.id} → ${plan} (${subscription.status})`);
}

async function handleSubscriptionDeleted(subscription) {
  await updateSubscriptionByStripeId(subscription.id, {
    status: 'canceled',
  });

  console.log(`[stripe-webhook] Subscription canceled: ${subscription.id}`);
}

async function handleInvoicePaid(invoice) {
  if (!invoice.subscription) return;
  await updateSubscriptionByStripeId(invoice.subscription, {
    status: 'active',
  });

  console.log(`[stripe-webhook] Invoice paid → subscription active: ${invoice.subscription}`);
}

async function handleInvoicePaymentFailed(invoice) {
  if (!invoice.subscription) return;
  await updateSubscriptionByStripeId(invoice.subscription, {
    status: 'past_due',
  });

  console.log(`[stripe-webhook] Invoice payment failed → past_due: ${invoice.subscription}`);
}

// ---------------------------------------------------------------------------
// Vercel Serverless Function entry point
// ---------------------------------------------------------------------------
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const sig = req.headers['stripe-signature'];

  if (!sig) {
    return res.status(400).json({ error: 'Missing stripe-signature header' });
  }

  let event;

  try {
    // req.body must be the raw Buffer — configure Vercel to skip body parsing
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[stripe-webhook] Signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook signature error: ${err.message}` });
  }

  console.log(`[stripe-webhook] Received event: ${event.type}`);

  try {
    switch (event.type) {
      case 'customer.subscription.created':
        await handleSubscriptionCreated(event.data.object);
        break;

      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(event.data.object);
        break;

      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(event.data.object);
        break;

      case 'invoice.paid':
        await handleInvoicePaid(event.data.object);
        break;

      case 'invoice.payment_failed':
        await handleInvoicePaymentFailed(event.data.object);
        break;

      default:
        // Acknowledge but don't process unhandled events
        console.log(`[stripe-webhook] Unhandled event type: ${event.type}`);
    }

    return res.status(200).json({ received: true, event: event.type });
  } catch (err) {
    console.error(`[stripe-webhook] Handler error for ${event.type}:`, err);
    // Return 500 so Stripe retries the event
    return res.status(500).json({ error: 'Webhook handler failed' });
  }
};

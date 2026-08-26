const express = require('express');
const db      = require('../db/database');
const { requireAuth, requireAdmin, requireSuperAdmin } = require('../middleware/auth');

const router = express.Router();

const PLANS = {
  Starter: { price: process.env.STRIPE_PRICE_STARTER || null, amount: 5500,  name: 'Starter Plan' },
  Growth:  { price: process.env.STRIPE_PRICE_GROWTH  || null, amount: 9900,  name: 'Growth Plan'  },
  Pro:     { price: process.env.STRIPE_PRICE_PRO     || null, amount: 17900, name: 'Pro Plan'     },
};

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// The organization owns the subscription (one plan per company).
function callerOrg(req) {
  return db.prepare('SELECT * FROM organizations WHERE id = ?').get(req.user.org_id) || {};
}

// GET /api/stripe/status
router.get('/status', requireAuth, (req, res) => {
  const org = callerOrg(req);
  const onTrial = org.subscription_status === 'trialing' && org.trial_ends_at;
  const trialDaysLeft = onTrial
    ? Math.max(0, Math.ceil((new Date(org.trial_ends_at) - Date.now()) / 86400000))
    : null;
  res.json({
    plan:               org.plan,
    status:             org.subscription_status,
    hasStripe:          !!process.env.STRIPE_SECRET_KEY,
    customerId:         org.stripe_customer_id ? '***' : null,
    subscriptionActive: org.subscription_status === 'active',
    onTrial:            !!onTrial,
    trialEndsAt:        onTrial ? org.trial_ends_at : null,
    trialDaysLeft,
  });
});

// POST /api/stripe/checkout  — create a Stripe Checkout session (org admin only)
router.post('/checkout', requireAdmin, express.json(), async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Payment processing not configured. Contact us to upgrade your plan.' });

  const { plan } = req.body;
  if (!PLANS[plan]) return res.status(400).json({ error: 'Invalid plan' });

  const user    = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const planCfg = PLANS[plan];

  if (!planCfg.price) return res.status(503).json({ error: 'This plan is not yet available for purchase online. Please contact us.' });

  const siteUrl = process.env.SITE_URL || 'https://localhost:3443';

  try {
    const session = await stripe.checkout.sessions.create({
      mode:               'subscription',
      payment_method_types: ['card'],
      customer_email:     user.email,
      metadata:           { orgId: String(req.user.org_id), plan },
      line_items: [{ price: planCfg.price, quantity: 1 }],
      success_url: `${siteUrl}/pages/dashboard/billing.html?success=1`,
      cancel_url:  `${siteUrl}/pages/dashboard/billing.html?cancelled=1`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe] Checkout error:', err.message);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

// POST /api/stripe/portal  — customer portal (manage billing)
router.post('/portal', requireAdmin, express.json(), async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Payment processing not configured' });

  const org = callerOrg(req);
  if (!org.stripe_customer_id) return res.status(400).json({ error: 'No billing account found. Please subscribe first.' });

  const siteUrl = process.env.SITE_URL || 'https://localhost:3443';
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer:   org.stripe_customer_id,
      return_url: `${siteUrl}/pages/dashboard/billing.html`,
    });
    res.json({ url: session.url });
  } catch {
    res.status(500).json({ error: 'Could not open billing portal' });
  }
});

// POST /api/stripe/webhook  — handle Stripe events
router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.sendStatus(200);

  const sig     = req.headers['stripe-signature'];
  const secret  = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret)  return res.sendStatus(200);

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    return res.status(400).send(`Webhook error: ${err.message}`);
  }

  const { type, data } = event;

  if (type === 'checkout.session.completed') {
    const session    = data.object;
    const orgId      = parseInt(session.metadata?.orgId, 10);
    const plan       = session.metadata?.plan;
    const customerId = session.customer;
    const subId      = session.subscription;
    if (orgId && plan) {
      db.prepare('UPDATE organizations SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ?, subscription_status = ? WHERE id = ?')
        .run(plan, customerId, subId, 'active', orgId);
      // Keep members' (vestigial) plan column roughly in sync for display.
      db.prepare('UPDATE users SET plan = ? WHERE org_id = ?').run(plan, orgId);
    }
  }

  if (type === 'customer.subscription.deleted' || type === 'customer.subscription.paused') {
    const sub = data.object;
    db.prepare('UPDATE organizations SET subscription_status = ? WHERE stripe_subscription_id = ?').run('inactive', sub.id);
  }

  if (type === 'customer.subscription.updated') {
    const sub    = data.object;
    const status = sub.status === 'active' ? 'active' : 'inactive';
    db.prepare('UPDATE organizations SET subscription_status = ? WHERE stripe_subscription_id = ?').run(status, sub.id);
  }

  res.sendStatus(200);
});

// GET /api/stripe/subscribers  — platform owner overview (paying organizations)
router.get('/subscribers', requireSuperAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, name, plan, subscription_status, created_at FROM organizations WHERE stripe_customer_id IS NOT NULL ORDER BY created_at DESC`).all();
  res.json(rows);
});

module.exports = router;

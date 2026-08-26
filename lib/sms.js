// ─────────────────────────────────────────────────────────────
// SMS sending — framework / scaffold.
//
// Real delivery requires an SMS provider account (Twilio by default):
//   1. Sign up at twilio.com and buy a phone number (~$1/mo + per-text cost).
//   2. `npm i twilio`
//   3. Set these env vars:
//        SMS_PROVIDER=twilio
//        TWILIO_ACCOUNT_SID=ACxxxxxxxx
//        TWILIO_AUTH_TOKEN=xxxxxxxx
//        TWILIO_FROM=+1XXXXXXXXXX
//
// Until that's done, sendSms() is a safe no-op that just logs the message, so the
// rest of the app can call it unconditionally without crashing or sending anything.
// Per-user delivery also requires the user to have a `phone` set and `sms_alerts`
// enabled (both added to the users table in migration #4).
// ─────────────────────────────────────────────────────────────

const logger = require('./logger');

// Is a real provider fully configured?
function smsConfigured() {
  return (
    process.env.SMS_PROVIDER === 'twilio' &&
    !!process.env.TWILIO_ACCOUNT_SID &&
    !!process.env.TWILIO_AUTH_TOKEN &&
    !!process.env.TWILIO_FROM
  );
}

// Lazily build the provider client so `twilio` stays an optional dependency.
let _client;
function getClient() {
  if (_client) return _client;
  const twilio = require('twilio'); // only reached when smsConfigured() is true
  _client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  return _client;
}

// Basic E.164-ish sanity check. Not a full validator — just stops obvious junk.
function isValidPhone(phone) {
  return /^\+?[1-9]\d{7,14}$/.test(String(phone || '').replace(/[\s()-]/g, ''));
}

// Send one SMS. Returns true only if it was handed to the provider.
// When SMS isn't configured the message is logged (not sent) and false is returned.
async function sendSms({ to, body }) {
  if (!to || !isValidPhone(to)) {
    logger.warn(`[sms] invalid/missing recipient — skipped`);
    return false;
  }
  if (!smsConfigured()) {
    logger.info(`[sms] (provider not configured) would send to ${to}: ${body}`);
    return false;
  }
  try {
    await getClient().messages.create({ to, from: process.env.TWILIO_FROM, body });
    logger.info(`[sms] sent to ${to}`);
    return true;
  } catch (err) {
    logger.error({ err }, '[sms] send failed');
    return false;
  }
}

// Convenience: SMS a user only if they've opted in and have a number on file.
async function smsUser(user, body) {
  if (!user || !user.sms_alerts || !user.phone) return false;
  return sendSms({ to: user.phone, body });
}

module.exports = { sendSms, smsUser, smsConfigured, isValidPhone };

// Resolves a plan's limits, applying any account-wide overrides an admin has set
// (stored in app_settings). Overrides win when present; otherwise the plan default
// from lib/plans.js applies. Used by storage quota, dashboard stats, and seat checks.

const plans = require('./plans');
const { getInt } = require('./appSettings');

function effectiveStorageGB(plan) {
  return getInt('storage_override_gb') ?? plans.limitGB(plan);
}

function effectiveStorageBytes(plan) {
  return effectiveStorageGB(plan) * 1024 ** 3;
}

function effectiveSeatLimit(plan) {
  return getInt('seat_override') ?? plans.seatLimit(plan);
}

function effectiveMailboxLimit(plan) {
  return getInt('mailbox_override') ?? plans.mailboxLimit(plan);
}

module.exports = { effectiveStorageGB, effectiveStorageBytes, effectiveSeatLimit, effectiveMailboxLimit };

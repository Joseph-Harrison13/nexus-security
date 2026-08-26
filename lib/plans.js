// Single source of truth for per-plan storage limits AND the storage-warning
// thresholds. Tune `warnPct` / `criticalPct` per plan here — bigger plans have
// far more absolute headroom at the same percentage, so they warn later.
//
//   warnPct     → amber "storage is filling up" banner
//   criticalPct → red "almost out of storage" banner

const PLANS = {
  Starter: { storageGB: 10,  seats: 3,  mailboxes: 3,  warnPct: 80, criticalPct: 95 },
  Growth:  { storageGB: 50,  seats: 10, mailboxes: 10, warnPct: 85, criticalPct: 95 },
  Pro:     { storageGB: 200, seats: 50, mailboxes: 50, warnPct: 90, criticalPct: 97 },
};
const DEFAULT = { storageGB: 10, seats: 3, mailboxes: 3, warnPct: 80, criticalPct: 95 };

function planCfg(plan) {
  return PLANS[plan] || DEFAULT;
}

// Back-compat: other modules import STORAGE_LIMITS_GB / limitGB / limitBytes.
const STORAGE_LIMITS_GB = Object.fromEntries(
  Object.entries(PLANS).map(([name, cfg]) => [name, cfg.storageGB])
);
const DEFAULT_GB = DEFAULT.storageGB;

function limitGB(plan) {
  return planCfg(plan).storageGB;
}

function limitBytes(plan) {
  return limitGB(plan) * 1024 ** 3;
}

// { warn, critical } percentages for the given plan.
function thresholds(plan) {
  const cfg = planCfg(plan);
  return { warn: cfg.warnPct, critical: cfg.criticalPct };
}

// Maximum number of user accounts allowed on a plan.
function seatLimit(plan) {
  return planCfg(plan).seats;
}

// Maximum number of email mailboxes scanned on a plan (provisioned in Proofpoint).
function mailboxLimit(plan) {
  return planCfg(plan).mailboxes;
}

module.exports = { PLANS, STORAGE_LIMITS_GB, DEFAULT_GB, limitGB, limitBytes, thresholds, seatLimit, mailboxLimit };

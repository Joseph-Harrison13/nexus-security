// ─────────────────────────────────────────────────────────────
// Password breach check via Have I Been Pwned's range API, using
// k-anonymity: we hash the password (SHA-1), send only the first 5 hex
// characters of the hash, and match the rest locally. The full password
// and full hash never leave this server. No API key required.
//
// Fails OPEN: if the API is unreachable, we return null and callers let the
// password through rather than blocking a legitimate signup on a network blip.
// ─────────────────────────────────────────────────────────────

const crypto = require('crypto');
const logger = require('./logger');

// Returns how many times the password appears in known breaches (0 = clean),
// or null if the check could not be completed.
async function breachCount(password) {
  try {
    const sha1   = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;

    const body = await res.text();
    for (const line of body.split('\n')) {
      const [suf, count] = line.trim().split(':');
      if (suf === suffix) return parseInt(count, 10) || 0;
    }
    return 0;
  } catch (err) {
    logger.warn(`[breach-check] skipped: ${err.message}`);
    return null; // fail open
  }
}

// Convenience: returns the breach count if the password is compromised, else false.
async function isBreached(password) {
  const n = await breachCount(password);
  return n != null && n > 0 ? n : false;
}

module.exports = { breachCount, isBreached };

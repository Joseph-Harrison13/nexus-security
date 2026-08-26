// Build a list of CSP sha256 source hashes for every inline <script> block we
// ship, computed once at startup by scanning the static HTML. This lets us keep
// the app's own inline scripts working while a modern browser will REJECT any
// inline <script> it wasn't told about — i.e. an injected <script> payload from
// a stored-XSS bug is blocked at the browser, even if it slipped past escaping.
//
// Per the CSP spec, when a hash (or nonce) is present in script-src, conforming
// browsers IGNORE 'unsafe-inline'. So we can keep 'unsafe-inline' in the policy
// purely as a fallback for ancient (pre-CSP2) browsers without weakening the
// hash enforcement that every current browser applies.
//
// Hashes are derived from the files themselves, so editing an inline script just
// requires a server restart — there is no hardcoded list to keep in sync. Note
// this only covers inline <script> BLOCKS; inline event-handler attributes
// (onclick=...) are governed separately by script-src-attr and still rely on
// 'unsafe-inline' (an injected handler can only fire if unescaped data reaches
// the DOM, which the escapeHtml render layer prevents).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Matches <script ...>...</script> blocks that do NOT have a src attribute
// (i.e. inline scripts only — external <script src> is covered by 'self').
const INLINE_SCRIPT = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;

function walkHtml(dir) {
  let out = [];
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) out = out.concat(walkHtml(full));
    else if (entry.endsWith('.html')) out.push(full);
  }
  return out;
}

function computeScriptHashes(publicDir) {
  const hashes = new Set();
  let files;
  try {
    files = walkHtml(publicDir);
  } catch {
    return []; // no public dir (e.g. some test setups) — nothing to hash
  }
  for (const file of files) {
    const html = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = INLINE_SCRIPT.exec(html)) !== null) {
      const body = m[1]; // exact bytes the browser will hash
      const digest = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
      hashes.add(`'sha256-${digest}'`);
    }
  }
  return [...hashes];
}

module.exports = { computeScriptHashes };

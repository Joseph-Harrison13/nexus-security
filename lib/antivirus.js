// ─────────────────────────────────────────────────────────────
// Malware scanning for uploaded files via ClamAV (clamd).
//
// Disabled by default. To turn it on in production:
//   1. Install ClamAV + the daemon:   apt-get install clamav clamav-daemon
//   2. Keep signatures fresh:          freshclam  (runs on a timer automatically)
//   3. Make sure clamd is listening on TCP 3310 (or a unix socket)
//   4. Set env:  AV_ENABLED=true   (optionally CLAMD_HOST / CLAMD_PORT / CLAMD_SOCKET)
//
// `clamscan` is lazy-required so the dependency only loads when scanning is on.
// Security posture: when enabled but the scanner can't be reached, we FAIL CLOSED
// (reject the upload) unless AV_FAIL_OPEN=true is explicitly set.
// ─────────────────────────────────────────────────────────────

const logger = require('./logger');

function avEnabled() {
  return process.env.AV_ENABLED === 'true' || process.env.AV_ENABLED === '1';
}

let _clam = null;
async function getScanner() {
  if (_clam) return _clam;
  const NodeClam = require('clamscan'); // lazy — only when AV is enabled
  _clam = await new NodeClam().init({
    clamdscan: {
      host:    process.env.CLAMD_HOST || '127.0.0.1',
      port:    parseInt(process.env.CLAMD_PORT || '3310', 10),
      socket:  process.env.CLAMD_SOCKET || null,
      timeout: parseInt(process.env.CLAMD_TIMEOUT_MS || '30000', 10),
      localFallback: false,
    },
    preference: 'clamdscan',
  });
  return _clam;
}

// Scan a file on disk.
// Returns { skipped, clean, virus, error } — `skipped` means scanning was off.
async function scanFile(filePath) {
  if (!avEnabled()) return { skipped: true, clean: true, virus: null };
  try {
    const clam = await getScanner();
    const { isInfected, viruses } = await clam.isInfected(filePath);
    return { skipped: false, clean: !isInfected, virus: isInfected ? (viruses[0] || 'unknown') : null };
  } catch (err) {
    _clam = null; // drop the cached client so the next upload can retry
    logger.error({ err }, '[antivirus] scan failed');
    if (process.env.AV_FAIL_OPEN === 'true') return { skipped: true, clean: true, virus: null, error: true };
    return { skipped: false, clean: false, virus: null, error: true };
  }
}

module.exports = { scanFile, avEnabled };

const express = require('express');
const bcrypt  = require('bcrypt');
const db      = require('../db/database');
const { E } = require('../lib/errors');
const { driver: storage } = require('../lib/storage');

const router = express.Router();

// Look up a share by token and decide whether it can still be used. Returns
// { share, file, status } where status is 'ok' or a reason it's unavailable.
function resolveShare(token) {
  const share = db.prepare('SELECT * FROM file_shares WHERE token = ?').get(token);
  if (!share) return { status: 'not_found' };
  if (share.revoked) return { status: 'revoked', share };
  if (share.expires_at && new Date(share.expires_at) < new Date()) return { status: 'expired', share };
  if (share.max_downloads && share.downloads >= share.max_downloads) return { status: 'used_up', share };
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(share.file_id);
  if (!file || file.deleted_at) return { status: 'gone', share };
  return { status: 'ok', share, file };
}

function statusMessage(status) {
  switch (status) {
    case 'revoked':  return 'This share link has been turned off by its owner.';
    case 'expired':  return 'This share link has expired.';
    case 'used_up':  return 'This share link has reached its download limit.';
    case 'gone':     return 'The shared file is no longer available.';
    default:         return 'This share link is invalid.';
  }
}

// GET /api/share/:token  — public metadata about a share (no file contents)
router.get('/:token', (req, res) => {
  const { status, share, file } = resolveShare(req.params.token);
  if (status !== 'ok') {
    return res.status(status === 'not_found' ? 404 : 410).json({ available: false, reason: status, message: statusMessage(status) });
  }
  res.json({
    available:       true,
    fileName:        file.name,
    size:            file.size,
    requiresPassword: !!share.password_hash,
    expiresAt:       share.expires_at,
    downloadsLeft:   share.max_downloads ? Math.max(0, share.max_downloads - share.downloads) : null,
  });
});

// POST /api/share/:token/download  — validate (optional password) and stream the file
router.post('/:token/download', express.json(), async (req, res) => {
  const { status, share, file } = resolveShare(req.params.token);
  if (status !== 'ok') {
    return res.status(status === 'not_found' ? 404 : 410).json({ error: statusMessage(status), reason: status });
  }

  if (share.password_hash) {
    const ok = req.body.password && await bcrypt.compare(String(req.body.password), share.password_hash);
    if (!ok) return E.unauthorized(res, 'Incorrect password for this link.');
  }

  if (!file.disk_path) return E.notFound(res, 'File content not available');

  // Count the download up front so a concurrent burst can't exceed the cap.
  db.prepare('UPDATE file_shares SET downloads = downloads + 1 WHERE id = ?').run(share.id);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(share.user_id, 'share_downloaded', `Shared file "${file.name}" was downloaded`, req.ip);

  const sent = await storage.sendFile(res, file.disk_path, {
    contentType: 'application/octet-stream',
    disposition: 'attachment',
    filename:    file.name,
  });
  if (!sent) return E.notFound(res, 'File data not found in storage');
});

module.exports = router;

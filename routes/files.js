const express  = require('express');
const multer   = require('multer');
const fs       = require('fs');
const crypto   = require('crypto');
const bcrypt   = require('bcrypt');
const db       = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { canAccessRow, listScope } = require('../lib/scope');
const { E, sendError } = require('../lib/errors');
const { alertSuspiciousActivity } = require('../lib/alerts');
const { driver: storage, UPLOADS_DIR } = require('../lib/storage');
const limits = require('../lib/limits');
const { scanFile } = require('../lib/antivirus');

const router = express.Router();

const ALLOWED_EXTENSIONS = new Set([
  'pdf','doc','docx','xls','xlsx','csv','txt',
  'png','jpg','jpeg','gif','webp',
  'zip','mp4','mov',
]);

// What each allowed extension must actually contain, checked against the file's
// real magic bytes (via file-type). This is deliberately strict:
//   • binary formats MUST present recognizable magic that matches the extension
//     — a file with no/other magic renamed to .png/.pdf/.zip is rejected;
//   • text formats (txt/csv) have no magic, so we allow "undetected" but reject
//     anything that IS a recognizable binary masquerading as text.
const CONTENT_RULES = {
  pdf:  { mimes: ['application/pdf'] },
  png:  { mimes: ['image/png'] },
  jpg:  { mimes: ['image/jpeg'] },
  jpeg: { mimes: ['image/jpeg'] },
  gif:  { mimes: ['image/gif'] },
  webp: { mimes: ['image/webp'] },
  zip:  { mimes: ['application/zip'] },
  mp4:  { prefix: 'video/' },
  mov:  { prefix: 'video/' },
  doc:  { mimes: ['application/x-cfb'] }, // legacy OLE compound file
  xls:  { mimes: ['application/x-cfb'] },
  docx: { mimes: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'] },
  xlsx: { mimes: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'] },
  txt:  { text: true },
  csv:  { text: true },
};

// Sanitize the user-supplied filename before we store it as the display name.
// Rendering already escapes it, but sanitizing on the way in strips control
// characters, path components and header/filesystem-hostile characters so the
// value is safe everywhere it's later used (DB, logs, Content-Disposition).
function sanitizeDisplayName(name) {
  let n = String(name || '').split(/[\\/]/).pop();      // basename only — no dirs
  // Matching control characters is the entire point here — they are what we are
  // stripping out — so the no-control-regex rule is disabled deliberately.
  // eslint-disable-next-line no-control-regex
  n = n.replace(/[\x00-\x1f\x7f]/g, '');                // drop control chars / NUL
  n = n.replace(/[<>:"|?*]/g, '_');                     // filesystem/header-hostile
  n = n.replace(/\s+/g, ' ').trim();
  if (!n || /^\.+$/.test(n)) n = 'file';                // reject empty / "."/".."
  if (n.length > 200) {                                 // cap, preserving extension
    const dot = n.lastIndexOf('.');
    const ext = dot > 0 ? n.slice(dot) : '';
    n = n.slice(0, 200 - ext.length) + ext;
  }
  return n;
}

// Content types we trust to render inline in the browser. Everything else is
// forced to download as a generic binary so a file whose stored mime_type was
// spoofed (it comes from the uploader) can't be served as inline HTML/SVG/etc.
const SAFE_INLINE_TYPES = {
  pdf:  'application/pdf',
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  gif:  'image/gif',
  webp: 'image/webp',
};

// multer always writes the upload to the local uploads/ dir first; the storage
// driver then either leaves it there (disk) or ships it to S3 (see lib/storage.js).
const multerStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename:    (_req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${safe}`);
  },
});

const upload = multer({
  storage: multerStorage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = file.originalname.split('.').pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new Error(`File type .${ext} is not allowed`));
    }
    cb(null, true);
  },
});

// file-type v22 is ESM-only; load it lazily via a cached dynamic import so this
// CommonJS module can still use it (v22 also fixes a DoS in the parser).
let _fileTypePromise;
function loadFileType() {
  return (_fileTypePromise ||= import('file-type'));
}

async function verifyContent(filePath, originalName) {
  const ext  = (originalName.split('.').pop() || '').toLowerCase();
  const rule = CONTENT_RULES[ext];
  if (!rule) return false; // extension isn't allowed (fileFilter should catch this first)

  let detected = null;
  try {
    const { fileTypeFromFile } = await loadFileType();
    detected = await fileTypeFromFile(filePath);
  } catch { /* treat as undetected below */ }

  if (rule.text) {
    // Real text has no magic bytes; anything file-type recognizes here is a
    // binary pretending to be .txt/.csv, so reject it.
    return !detected;
  }
  // Binary formats must present recognizable magic that matches the extension.
  if (!detected) return false;
  if (rule.prefix) return detected.mime.startsWith(rule.prefix);
  return rule.mimes.includes(detected.mime);
}

function parsePage(query) {
  const page  = Math.max(1,   parseInt(query.page  || '1',  10));
  const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10)));
  return { page, limit, offset: (page - 1) * limit };
}

// GET /api/files  — active (non-trashed) files, optionally filtered by folder
router.get('/', requireAuth, (req, res) => {
  const { page, limit, offset } = parsePage(req.query);
  const elevated = req.user.role === 'Admin' || req.user.role === 'SuperAdmin';

  const where  = ['f.deleted_at IS NULL'];
  const params = [];
  const scope  = listScope(req, { userCol: 'f.user_id', orgCol: 'f.org_id' });
  where.push(scope.sql); params.push(...scope.params);
  if (req.query.folder === 'root') {
    where.push('f.folder_id IS NULL');
  } else if (req.query.folder && /^\d+$/.test(req.query.folder)) {
    where.push('f.folder_id = ?'); params.push(parseInt(req.query.folder, 10));
  }
  const whereSql = 'WHERE ' + where.join(' AND ');
  const fromSql  = elevated ? 'files f JOIN users u ON f.user_id = u.id' : 'files f';
  const cols     = elevated ? 'f.*, u.email AS owner_email' : 'f.*';

  const data  = db.prepare(`SELECT ${cols} FROM ${fromSql} ${whereSql} ORDER BY f.uploaded_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  const total = db.prepare(`SELECT COUNT(*) AS n FROM ${fromSql} ${whereSql}`).get(...params).n;

  const totalPages = Math.ceil(total / limit);
  res.json({ data, pagination: { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 } });
});

// GET /api/files/trash  — soft-deleted files still within the 30-day window
router.get('/trash', requireAuth, (req, res) => {
  const elevated = req.user.role === 'Admin' || req.user.role === 'SuperAdmin';
  const scope    = listScope(req, { userCol: 'f.user_id', orgCol: 'f.org_id' });
  const from     = elevated ? 'files f JOIN users u ON f.user_id = u.id' : 'files f';
  const cols     = elevated ? 'f.*, u.email AS owner_email' : 'f.*';
  const rows = db.prepare(
    `SELECT ${cols} FROM ${from} WHERE ${scope.sql} AND f.deleted_at IS NOT NULL ORDER BY f.deleted_at DESC`
  ).all(...scope.params);
  res.json({ data: rows });
});

// POST /api/files/upload
router.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return E.badRequest(res, 'No file provided');

  // Enforce the ORG-wide storage quota: the whole organization shares one plan's
  // storage. Usage is summed across the org's members.
  const org  = db.prepare(
    `SELECT o.plan, (SELECT COALESCE(SUM(storage_used), 0) FROM users WHERE org_id = o.id) AS used
     FROM organizations o WHERE o.id = ?`
  ).get(req.user.org_id) || { plan: 'Starter', used: 0 };
  const limit = limits.effectiveStorageBytes(org.plan);
  if (org.used + req.file.size > limit) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return sendError(res, 413,
      `This upload would exceed your organization's storage limit of ${limits.effectiveStorageGB(org.plan)} GB. Delete some files or upgrade your plan.`,
      'QUOTA_EXCEEDED');
  }

  const displayName = sanitizeDisplayName(req.file.originalname);

  const safe = await verifyContent(req.file.path, req.file.originalname);
  if (!safe) {
    fs.unlinkSync(req.file.path);
    alertSuspiciousActivity({ email: req.user.email }, 'suspicious_upload',
      `${displayName} content doesn't match its extension`, req.ip).catch(() => {});
    return E.badRequest(res, 'File content does not match its extension — rejected for security.');
  }

  // Malware scan (no-op unless AV is enabled). Blocks infected files; fails closed
  // if the scanner is enabled but unreachable.
  const scan = await scanFile(req.file.path);
  if (!scan.clean) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    if (scan.virus) {
      db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
        .run(req.user.sub, 'malware_blocked', `Blocked ${displayName} — ${scan.virus}`, req.ip);
      alertSuspiciousActivity({ email: req.user.email }, 'malware_blocked',
        `${displayName}: ${scan.virus}`, req.ip).catch(() => {});
      return E.badRequest(res, `This file was blocked — our scanner detected a threat (${scan.virus}).`);
    }
    return sendError(res, 503, 'We could not virus-scan this file right now. Please try again shortly.', 'SCAN_UNAVAILABLE');
  }

  // Hand the validated file to the storage driver (local disk or S3) and record
  // the returned key. disk_path holds the storage key for whichever backend is active.
  let storageKey;
  try {
    storageKey = await storage.finalizeUpload(req.file);
  } catch (err) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error('[upload] storage error:', err.message);
    return E.server(res, 'Could not store the uploaded file. Please try again.');
  }

  // Optional folder placement — only honor a folder the user actually owns.
  let folderId = null;
  if (req.body.folderId && /^\d+$/.test(req.body.folderId)) {
    const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(req.body.folderId, req.user.sub);
    if (folder) folderId = folder.id;
  }

  const result = db.prepare(
    'INSERT INTO files (user_id, org_id, name, size, mime_type, disk_path, folder_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.sub, req.user.org_id, displayName, req.file.size, req.file.mimetype, storageKey, folderId);

  db.prepare('UPDATE users SET storage_used = storage_used + ? WHERE id = ?').run(req.file.size, req.user.sub);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_upload', `Uploaded ${displayName}`, req.ip);

  res.status(201).json(db.prepare('SELECT * FROM files WHERE id = ?').get(result.lastInsertRowid));
});

// DELETE /api/files/:id  — soft delete: move to Trash (recoverable for 30 days)
router.delete('/:id', requireAuth, async (req, res) => {
  const fileId = parseInt(req.params.id, 10);
  const file   = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);

  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');
  if (file.deleted_at) return res.json({ message: `${file.name} is already in the Trash` });

  // Keep the bytes in storage so the file can be restored; it still counts toward
  // the quota until it's permanently deleted or purged after 30 days.
  db.prepare("UPDATE files SET deleted_at = datetime('now') WHERE id = ?").run(fileId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_trashed', `Moved ${file.name} to Trash`, req.ip);

  res.json({ message: `${file.name} moved to Trash`, recoverableDays: 30 });
});

// POST /api/files/:id/restore  — bring a file back from the Trash
router.post('/:id/restore', requireAuth, (req, res) => {
  const fileId = parseInt(req.params.id, 10);
  const file   = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);

  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');

  db.prepare('UPDATE files SET deleted_at = NULL WHERE id = ?').run(fileId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_restored', `Restored ${file.name}`, req.ip);

  res.json({ message: `${file.name} restored` });
});

// DELETE /api/files/:id/permanent  — delete for good (from Trash), free the storage
router.delete('/:id/permanent', requireAuth, async (req, res) => {
  const fileId = parseInt(req.params.id, 10);
  const file   = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);

  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');

  if (file.disk_path) {
    try { await storage.remove(file.disk_path); }
    catch (err) { console.error('[delete] storage error:', err.message); }
  }
  db.prepare('DELETE FROM files WHERE id = ?').run(fileId);
  db.prepare('UPDATE users SET storage_used = MAX(0, storage_used - ?) WHERE id = ?').run(file.size, file.user_id);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_deleted', `Permanently deleted ${file.name}`, req.ip);

  res.json({ message: `${file.name} permanently deleted` });
});

// PUT /api/files/:id/move  — move a file into a folder (or to root with folderId null)
router.put('/:id/move', requireAuth, express.json(), (req, res) => {
  const fileId = parseInt(req.params.id, 10);
  const file   = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);

  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');

  let folderId = null;
  if (req.body.folderId !== null && req.body.folderId !== undefined && `${req.body.folderId}` !== '') {
    if (!/^\d+$/.test(`${req.body.folderId}`)) return E.badRequest(res, 'Invalid folder');
    const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(req.body.folderId, file.user_id);
    if (!folder) return E.notFound(res, 'Folder not found');
    folderId = folder.id;
  }
  db.prepare('UPDATE files SET folder_id = ? WHERE id = ?').run(folderId, fileId);
  res.json({ message: 'File moved', folderId });
});

// GET /api/files/:id/download  — serve file for download or preview
router.get('/:id/download', requireAuth, async (req, res) => {
  const fileId = parseInt(req.params.id, 10);
  const file   = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);
  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');

  if (file.disk_path) {
    // Derive the content type from the (server-controlled) extension, not the
    // stored mime_type which originated from the uploader. Only render inline for
    // a small set of safe types; anything else downloads as a generic binary.
    const ext      = (file.name.split('.').pop() || '').toLowerCase();
    const safeType = SAFE_INLINE_TYPES[ext];
    const isPreview = req.query.preview === '1' && !!safeType;

    db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
      .run(req.user.sub, isPreview ? 'file_preview' : 'file_download',
           `${isPreview ? 'Opened' : 'Downloaded'} ${file.name}`, req.ip);

    const sent = await storage.sendFile(res, file.disk_path, {
      contentType: safeType || 'application/octet-stream',
      disposition: isPreview ? 'inline' : 'attachment',
      filename:    file.name,
    });
    if (!sent) return E.notFound(res, 'File data not found in storage');
    return;
  }
  // Demo files have no disk_path — return a placeholder response
  res.status(404).json({ error: 'File content not available for demo files' });
});

// GET /api/files/export/zip  — download all user files as ZIP
router.get('/export/zip', requireAuth, async (req, res) => {
  const archiver = require('archiver');
  const scope = listScope(req, { userCol: 'user_id', orgCol: 'org_id' });
  const files = db.prepare(
    `SELECT * FROM files WHERE ${scope.sql} AND disk_path IS NOT NULL AND deleted_at IS NULL`
  ).all(...scope.params);

  if (!files.length) return res.status(404).json({ error: 'No files to export' });

  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_export', `Exported ${files.length} file(s) as ZIP`, req.ip);

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="nexus-files.zip"');

  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', err => { console.error('[zip]', err.message); });
  archive.pipe(res);

  // Guard against duplicate entry names (different users/uploads, same filename).
  const usedNames = new Map();
  for (const f of files) {
    const stream = await storage.openReadStream(f.disk_path);
    if (!stream) continue; // skip objects missing from storage

    let entryName = f.name;
    if (usedNames.has(entryName)) {
      const n   = usedNames.get(entryName) + 1;
      usedNames.set(entryName, n);
      const dot = f.name.lastIndexOf('.');
      entryName = dot > 0 ? `${f.name.slice(0, dot)} (${n})${f.name.slice(dot)}` : `${f.name} (${n})`;
    } else {
      usedNames.set(entryName, 0);
    }
    archive.append(stream, { name: entryName });
  }

  await archive.finalize();
});

// ── Secure share links ───────────────────────────────────────

// POST /api/files/:id/share  — create an expiring (optionally password-protected) link
router.post('/:id/share', requireAuth, express.json(), async (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(parseInt(req.params.id, 10));
  if (!file) return E.notFound(res, 'File not found');
  if (!canAccessRow(req, file)) return E.forbidden(res, 'Forbidden');
  if (file.deleted_at) return E.badRequest(res, 'Cannot share a file that is in the Trash');

  // Expiry: default 7 days. 0 / null means "no expiry". Cap at 90 days.
  let expiresAt = null;
  const hours = req.body.expiresInHours;
  if (hours === undefined || hours === null || hours === '') {
    expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  } else if (Number(hours) > 0) {
    const capped = Math.min(Number(hours), 90 * 24);
    expiresAt = new Date(Date.now() + capped * 3600 * 1000).toISOString();
  }

  const maxDownloads = Number(req.body.maxDownloads) > 0 ? Math.min(Number(req.body.maxDownloads), 10000) : null;
  const passwordHash = req.body.password ? await bcrypt.hash(String(req.body.password), 10) : null;
  const token        = crypto.randomBytes(20).toString('hex');

  db.prepare(
    'INSERT INTO file_shares (file_id, user_id, org_id, token, password_hash, expires_at, max_downloads) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(file.id, req.user.sub, req.user.org_id, token, passwordHash, expiresAt, maxDownloads);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'file_shared', `Created a share link for ${file.name}`, req.ip);

  res.status(201).json({ token, path: `/share.html?t=${token}`, expiresAt, hasPassword: !!passwordHash, maxDownloads });
});

// GET /api/files/shares  — list the user's active/expired share links
router.get('/shares', requireAuth, (req, res) => {
  const scope = listScope(req, { userCol: 's.user_id', orgCol: 's.org_id' });
  const rows = db.prepare(`
    SELECT s.id, s.token, s.expires_at, s.max_downloads, s.downloads, s.revoked, s.created_at,
           (s.password_hash IS NOT NULL) AS has_password,
           f.name AS file_name
    FROM file_shares s JOIN files f ON s.file_id = f.id
    WHERE ${scope.sql}
    ORDER BY s.created_at DESC
  `).all(...scope.params);
  res.json({ data: rows });
});

// DELETE /api/files/shares/:shareId  — revoke a share link
router.delete('/shares/:shareId', requireAuth, (req, res) => {
  const share = db.prepare('SELECT * FROM file_shares WHERE id = ?').get(req.params.shareId);
  if (!canAccessRow(req, share)) return E.notFound(res, 'Share link not found');
  db.prepare('UPDATE file_shares SET revoked = 1 WHERE id = ?').run(share.id);
  res.json({ message: 'Share link revoked' });
});

module.exports = router;

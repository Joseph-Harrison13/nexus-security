const express = require('express');
const db      = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { E } = require('../lib/errors');

const router = express.Router();

const MAX_NAME = 60;

function cleanName(raw) {
  return String(raw || '').trim().replace(/[\r\n\t]/g, '').slice(0, MAX_NAME);
}

// GET /api/folders  — the user's folders, each with a live (non-trashed) file count
router.get('/', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT f.id, f.name, f.created_at,
           (SELECT COUNT(*) FROM files fi WHERE fi.folder_id = f.id AND fi.deleted_at IS NULL) AS file_count
    FROM folders f
    WHERE f.user_id = ?
    ORDER BY f.name COLLATE NOCASE ASC
  `).all(req.user.sub);
  res.json({ data: rows });
});

// POST /api/folders  — create a folder
router.post('/', requireAuth, express.json(), (req, res) => {
  const name = cleanName(req.body.name);
  if (!name) return E.badRequest(res, 'Folder name is required');

  const dupe = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ? COLLATE NOCASE').get(req.user.sub, name);
  if (dupe) return E.conflict(res, 'You already have a folder with that name');

  const result = db.prepare('INSERT INTO folders (user_id, org_id, name) VALUES (?, ?, ?)').run(req.user.sub, req.user.org_id, name);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'folder_created', `Created folder "${name}"`, req.ip);
  res.status(201).json(db.prepare('SELECT id, name, created_at FROM folders WHERE id = ?').get(result.lastInsertRowid));
});

// PUT /api/folders/:id  — rename a folder
router.put('/:id', requireAuth, express.json(), (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!folder) return E.notFound(res, 'Folder not found');

  const name = cleanName(req.body.name);
  if (!name) return E.badRequest(res, 'Folder name is required');

  const dupe = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ? COLLATE NOCASE AND id != ?').get(req.user.sub, name, folder.id);
  if (dupe) return E.conflict(res, 'You already have a folder with that name');

  db.prepare('UPDATE folders SET name = ? WHERE id = ?').run(name, folder.id);
  res.json({ message: 'Folder renamed', id: folder.id, name });
});

// DELETE /api/folders/:id  — delete a folder; its files fall back to "no folder" (not deleted)
router.delete('/:id', requireAuth, (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!folder) return E.notFound(res, 'Folder not found');

  db.prepare('UPDATE files SET folder_id = NULL WHERE folder_id = ?').run(folder.id);
  db.prepare('DELETE FROM folders WHERE id = ?').run(folder.id);
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'folder_deleted', `Deleted folder "${folder.name}"`, req.ip);
  res.json({ message: `Folder "${folder.name}" deleted. Its files were kept and moved out of the folder.` });
});

module.exports = router;

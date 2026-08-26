const fs   = require('fs');
const path = require('path');
const cron = require('node-cron');
const db   = require('../db/database');
const logger = require('./logger');

const BACKUPS_DIR  = path.join(__dirname, '..', 'backups');
const MAX_BACKUPS  = 7;

async function runBackup() {
  if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const destPath  = path.join(BACKUPS_DIR, `app-${timestamp}.db`);

  try {
    // Use SQLite's online backup API. A plain fs.copyFileSync of a WAL-mode
    // database can miss committed-but-uncheckpointed data sitting in the -wal
    // file, producing a stale or inconsistent backup. db.backup() takes a
    // consistent snapshot even while the database is being written to.
    await db.backup(destPath);
    logger.info(`[backup] created ${path.basename(destPath)}`);
    pruneOldBackups();
  } catch (err) {
    logger.error({ err }, '[backup] failed');
  }
}

function pruneOldBackups() {
  const files = fs.readdirSync(BACKUPS_DIR)
    .filter(f => f.endsWith('.db'))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(BACKUPS_DIR, f)).mtime }))
    .sort((a, b) => b.mtime - a.mtime);

  files.slice(MAX_BACKUPS).forEach(f => {
    fs.unlinkSync(path.join(BACKUPS_DIR, f.name));
    logger.info(`[backup] pruned old backup ${f.name}`);
  });
}

function scheduleBackups() {
  // Run once immediately on startup, then daily at 2am
  runBackup();
  cron.schedule('0 2 * * *', runBackup);
  logger.info('[backup] daily backup scheduled for 2:00 AM');
}

module.exports = { scheduleBackups, runBackup };

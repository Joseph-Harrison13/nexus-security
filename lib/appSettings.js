// Tiny key/value store for account-wide settings (e.g. "require 2FA").
const db = require('../db/database');

function getSetting(key, fallback = null) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}

function setSetting(key, value) {
  db.prepare(
    'INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(key, String(value));
}

function getBool(key) {
  return getSetting(key) === '1';
}

// Returns a positive integer setting, or null if unset/invalid.
function getInt(key) {
  const n = parseInt(getSetting(key), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

module.exports = { getSetting, setSetting, getBool, getInt };

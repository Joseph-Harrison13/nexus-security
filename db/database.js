const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const { runMigrations } = require('./migrations');

// DB_PATH lets tests (and alternate deployments) point at a different file or
// an in-memory database; defaults to the bundled app.db.
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Apply schema migrations (idempotent; tracked in schema_migrations).
runMigrations(db);

// Seed demo data if fresh database (skipped under test — tests seed their own data)
const existing = process.env.NODE_ENV === 'test'
  ? { id: 0 }
  : db.prepare('SELECT id FROM users WHERE email = ?').get('demo@testwebsite.com');
if (!existing) {
  const passwordHash = bcrypt.hashSync('password123', 12);
  db.prepare(`INSERT INTO users (email, password_hash, name, role, plan, storage_used) VALUES (?, ?, ?, ?, ?, ?)`)
    .run('demo@testwebsite.com', passwordHash, 'Demo Admin', 'Admin', 'Pro', 48318382);

  const demoUser = db.prepare('SELECT id FROM users WHERE email = ?').get('demo@testwebsite.com');

  const hash2 = bcrypt.hashSync('password456', 12);
  db.prepare(`INSERT INTO users (email, password_hash, name, role, plan, storage_used) VALUES (?, ?, ?, ?, ?, ?)`)
    .run('sarah@company.com', hash2, 'Sarah Johnson', 'User', 'Growth', 8445000);

  const insertFile = db.prepare(`INSERT INTO files (user_id, name, size, mime_type) VALUES (?, ?, ?, ?)`);
  insertFile.run(demoUser.id, 'Q3_Financial_Report.pdf',    2457600,  'application/pdf');
  insertFile.run(demoUser.id, 'Client_Contracts_2024.zip', 15728640, 'application/zip');
  insertFile.run(demoUser.id, 'Employee_Records.xlsx',       524288,  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  insertFile.run(demoUser.id, 'Marketing_Assets.zip',      31457280, 'application/zip');

  const log = db.prepare(`INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)`);
  log.run(demoUser.id, 'login',        'Successful login');
  log.run(demoUser.id, 'file_upload',  'Uploaded Q3_Financial_Report.pdf');
  log.run(demoUser.id, 'file_upload',  'Uploaded Client_Contracts_2024.zip');
  log.run(demoUser.id, 'user_created', 'Added sarah@company.com');
}

module.exports = db;

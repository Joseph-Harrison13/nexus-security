// Versioned, idempotent schema migrations.
//
// Each migration has a numeric version and an up(db) function. Applied versions
// are tracked in schema_migrations, and each migration runs once, in order,
// inside a transaction. Migrations are written to be safe to run against both a
// brand-new database and the existing app.db (which already has every table and
// column from the original inline setup) — that's why the baseline uses
// CREATE TABLE IF NOT EXISTS and the column step checks before ALTER.

const MIGRATIONS = [
  {
    version: 1,
    name: 'baseline schema',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id               INTEGER PRIMARY KEY AUTOINCREMENT,
          email            TEXT    UNIQUE NOT NULL,
          password_hash    TEXT    NOT NULL,
          name             TEXT    NOT NULL,
          role             TEXT    NOT NULL DEFAULT 'User',
          plan             TEXT    NOT NULL DEFAULT 'Starter',
          storage_used     INTEGER NOT NULL DEFAULT 0,
          totp_secret      TEXT,
          totp_enabled     INTEGER NOT NULL DEFAULT 0,
          failed_attempts  INTEGER NOT NULL DEFAULT 0,
          locked_until     DATETIME,
          known_ips        TEXT    NOT NULL DEFAULT '[]',
          created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login       DATETIME
        );

        CREATE TABLE IF NOT EXISTS files (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id      INTEGER NOT NULL,
          name         TEXT    NOT NULL,
          size         INTEGER NOT NULL DEFAULT 0,
          mime_type    TEXT,
          disk_path    TEXT,
          uploaded_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contact_submissions (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          first_name    TEXT,
          last_name     TEXT,
          email         TEXT    NOT NULL,
          business_name TEXT,
          interested_in TEXT,
          message       TEXT,
          submitted_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS activity_log (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER,
          action     TEXT    NOT NULL,
          detail     TEXT,
          ip         TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
          jti        TEXT PRIMARY KEY,
          revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
          id          TEXT PRIMARY KEY,
          user_id     INTEGER NOT NULL,
          jti         TEXT    UNIQUE NOT NULL,
          ip          TEXT,
          user_agent  TEXT,
          created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_used   DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at  DATETIME NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id     INTEGER NOT NULL,
          token_hash  TEXT    UNIQUE NOT NULL,
          expires_at  DATETIME NOT NULL,
          used        INTEGER NOT NULL DEFAULT 0,
          created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id     INTEGER NOT NULL,
          token_hash  TEXT    UNIQUE NOT NULL,
          session_id  TEXT,
          expires_at  DATETIME NOT NULL,
          revoked     INTEGER NOT NULL DEFAULT 0,
          created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS backup_codes (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          code_hash  TEXT    NOT NULL,
          used       INTEGER NOT NULL DEFAULT 0,
          used_at    DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          type       TEXT    NOT NULL,
          icon       TEXT    NOT NULL DEFAULT '🔔',
          message    TEXT    NOT NULL,
          read_at    DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          email         TEXT    UNIQUE NOT NULL,
          subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          unsubscribed  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS email_verifications (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          token_hash TEXT    UNIQUE NOT NULL,
          expires_at DATETIME NOT NULL,
          used       INTEGER NOT NULL DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS push_subscriptions (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          endpoint   TEXT    NOT NULL,
          keys       TEXT    NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, endpoint),
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
      `);
    },
  },
  {
    version: 2,
    name: 'add user 2FA/stripe + contact read_at columns',
    up(db) {
      const userCols = db.pragma('table_info(users)').map((c) => c.name);
      [
        ['totp_secret', 'TEXT'],
        ['totp_enabled', 'INTEGER NOT NULL DEFAULT 0'],
        ['failed_attempts', 'INTEGER NOT NULL DEFAULT 0'],
        ['locked_until', 'DATETIME'],
        ['known_ips', "TEXT NOT NULL DEFAULT '[]'"],
        ['email_verified', 'INTEGER NOT NULL DEFAULT 0'],
        ['stripe_customer_id', 'TEXT'],
        ['stripe_subscription_id', 'TEXT'],
        ['subscription_status', "TEXT NOT NULL DEFAULT 'inactive'"],
      ].forEach(([col, def]) => {
        if (!userCols.includes(col)) db.exec(`ALTER TABLE users ADD COLUMN ${col} ${def}`);
      });

      const contactCols = db.pragma('table_info(contact_submissions)').map((c) => c.name);
      if (!contactCols.includes('read_at')) {
        db.exec('ALTER TABLE contact_submissions ADD COLUMN read_at DATETIME');
      }
    },
  },
  {
    version: 3,
    name: 'index user_id foreign keys',
    up(db) {
      // These columns are filtered by user_id constantly (file lists, activity,
      // notifications, session/token lookups) — without indexes they're table scans.
      db.exec(`
        CREATE INDEX IF NOT EXISTS idx_files_user_id                 ON files(user_id);
        CREATE INDEX IF NOT EXISTS idx_activity_log_user_id          ON activity_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_id          ON notifications(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id              ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id        ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id   ON email_verifications(user_id);
        CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id          ON backup_codes(user_id);
      `);
    },
  },
  {
    version: 4,
    name: 'add file trash (soft delete) + folders + new-location login codes',
    up(db) {
      const fileCols = db.pragma('table_info(files)').map((c) => c.name);
      if (!fileCols.includes('deleted_at')) db.exec('ALTER TABLE files ADD COLUMN deleted_at DATETIME');
      if (!fileCols.includes('folder_id'))  db.exec('ALTER TABLE files ADD COLUMN folder_id INTEGER');

      // Optional mobile number for SMS alerts (see lib/sms.js — needs a Twilio account).
      const userCols = db.pragma('table_info(users)').map((c) => c.name);
      if (!userCols.includes('phone'))         db.exec('ALTER TABLE users ADD COLUMN phone TEXT');
      if (!userCols.includes('sms_alerts'))    db.exec('ALTER TABLE users ADD COLUMN sms_alerts INTEGER NOT NULL DEFAULT 0');

      db.exec(`
        CREATE TABLE IF NOT EXISTS folders (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          name       TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_folders_user_id   ON folders(user_id);
        CREATE INDEX IF NOT EXISTS idx_files_folder_id    ON files(folder_id);
        CREATE INDEX IF NOT EXISTS idx_files_deleted_at   ON files(deleted_at);

        CREATE TABLE IF NOT EXISTS login_codes (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id    INTEGER NOT NULL,
          code_hash  TEXT NOT NULL,
          ip         TEXT,
          expires_at DATETIME NOT NULL,
          used       INTEGER NOT NULL DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_login_codes_user_id ON login_codes(user_id);
      `);
    },
  },
  {
    version: 5,
    name: 'email two-factor authentication enabled by default',
    up(db) {
      const userCols = db.pragma('table_info(users)').map((c) => c.name);
      // ON by default for every account (new and existing).
      if (!userCols.includes('email_2fa')) db.exec('ALTER TABLE users ADD COLUMN email_2fa INTEGER NOT NULL DEFAULT 1');
    },
  },
  {
    version: 6,
    name: 'secure file sharing — expiring links',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS file_shares (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          file_id       INTEGER NOT NULL,
          user_id       INTEGER NOT NULL,
          token         TEXT NOT NULL UNIQUE,
          password_hash TEXT,
          expires_at    DATETIME,
          max_downloads INTEGER,
          downloads     INTEGER NOT NULL DEFAULT 0,
          revoked       INTEGER NOT NULL DEFAULT 0,
          created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_file_shares_token   ON file_shares(token);
        CREATE INDEX IF NOT EXISTS idx_file_shares_user_id ON file_shares(user_id);
        CREATE INDEX IF NOT EXISTS idx_file_shares_file_id ON file_shares(file_id);
      `);
    },
  },
  {
    version: 7,
    name: 'app settings key-value store',
    up(db) {
      db.exec(`CREATE TABLE IF NOT EXISTS app_settings (
        key   TEXT PRIMARY KEY,
        value TEXT
      )`);
    },
  },
  {
    version: 8,
    name: 'add user suspended flag (admin account suspension)',
    up(db) {
      const userCols = db.pragma('table_info(users)').map((c) => c.name);
      // A suspended account cannot log in and its live sessions are cut off,
      // without destroying the account/data (unlike DELETE).
      if (!userCols.includes('suspended')) {
        db.exec('ALTER TABLE users ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0');
      }
    },
  },
  {
    version: 9,
    name: 'add force_password_reset flag',
    up(db) {
      const userCols = db.pragma('table_info(users)').map((c) => c.name);
      // When set, the account can authenticate its password but must set a new
      // one before it can be used — for when credentials may be compromised.
      if (!userCols.includes('force_password_reset')) {
        db.exec('ALTER TABLE users ADD COLUMN force_password_reset INTEGER NOT NULL DEFAULT 0');
      }
    },
  },
  {
    version: 10,
    name: 'multi-tenancy: organizations + org_id scoping',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS organizations (
          id                     INTEGER PRIMARY KEY AUTOINCREMENT,
          name                   TEXT    NOT NULL,
          plan                   TEXT    NOT NULL DEFAULT 'Starter',
          stripe_customer_id     TEXT,
          stripe_subscription_id TEXT,
          subscription_status    TEXT    NOT NULL DEFAULT 'inactive',
          created_at             DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);

      const addCol = (table, col, def) => {
        const cols = db.pragma(`table_info(${table})`).map((c) => c.name);
        if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
      };
      addCol('users',       'org_id', 'INTEGER');
      addCol('files',       'org_id', 'INTEGER');
      addCol('folders',     'org_id', 'INTEGER');
      addCol('file_shares', 'org_id', 'INTEGER');

      // Backfill: give every existing (pre-tenancy) user their own organization,
      // carry over their plan + Stripe billing, and tag their data with that org.
      // On a fresh production DB there are no rows, so this is a no-op there.
      const orphans = db.prepare('SELECT * FROM users WHERE org_id IS NULL').all();
      const insertOrg = db.prepare(
        `INSERT INTO organizations (name, plan, stripe_customer_id, stripe_subscription_id, subscription_status)
         VALUES (?, ?, ?, ?, ?)`
      );
      for (const u of orphans) {
        const orgName = (u.name ? `${u.name.split(' ')[0]}'s` : 'My') + ' Organization';
        const orgId = insertOrg.run(
          orgName, u.plan || 'Starter',
          u.stripe_customer_id || null, u.stripe_subscription_id || null, u.subscription_status || 'inactive'
        ).lastInsertRowid;
        db.prepare('UPDATE users SET org_id = ? WHERE id = ?').run(orgId, u.id);
        db.prepare('UPDATE files SET org_id = ? WHERE user_id = ?').run(orgId, u.id);
        db.prepare('UPDATE folders SET org_id = ? WHERE user_id = ?').run(orgId, u.id);
        db.prepare('UPDATE file_shares SET org_id = ? WHERE user_id = ?').run(orgId, u.id);
      }

      db.exec(`
        CREATE INDEX IF NOT EXISTS idx_users_org_id       ON users(org_id);
        CREATE INDEX IF NOT EXISTS idx_files_org_id       ON files(org_id);
        CREATE INDEX IF NOT EXISTS idx_folders_org_id     ON folders(org_id);
        CREATE INDEX IF NOT EXISTS idx_file_shares_org_id ON file_shares(org_id);
      `);
    },
  },
  {
    version: 11,
    name: 'add organization free-trial period',
    up(db) {
      const cols = db.pragma('table_info(organizations)').map((c) => c.name);
      if (!cols.includes('trial_ends_at')) {
        db.exec('ALTER TABLE organizations ADD COLUMN trial_ends_at DATETIME');
      }
    },
  },
];

const logger = require('../lib/logger');

function runMigrations(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const current = db.prepare('SELECT MAX(version) AS v FROM schema_migrations').get().v || 0;

  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    db.transaction(() => {
      m.up(db);
      db.prepare('INSERT INTO schema_migrations (version, name) VALUES (?, ?)').run(m.version, m.name);
    })();
    logger.info(`[migrate] applied #${m.version} — ${m.name}`);
  }
}

module.exports = { runMigrations, MIGRATIONS };

const { db } = require('./helpers');
const { MIGRATIONS } = require('../db/migrations');

describe('migrations', () => {
  it('applies every migration on a fresh database', () => {
    const applied = db.prepare('SELECT version FROM schema_migrations ORDER BY version').all().map((r) => r.version);
    const expected = MIGRATIONS.map((m) => m.version);
    expect(applied).toEqual(expected);
  });

  it('creates the user_id indexes (migration #3)', () => {
    const idx = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all().map((r) => r.name);
    expect(idx).toContain('idx_files_user_id');
    expect(idx).toContain('idx_activity_log_user_id');
    expect(idx).toContain('idx_notifications_user_id');
    expect(idx).toContain('idx_sessions_user_id');
  });
});

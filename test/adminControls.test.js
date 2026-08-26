const { app, db, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

describe('force password reset', () => {
  it('revokes sessions, blocks login with the right code, and lifts after reset', async () => {
    const admin = await registerAndLogin({ email: 'fpr-admin@test.com', role: 'Admin' });
    const user  = await registerAndLogin({ email: 'fpr-user@test.com', orgId: admin.orgId });

    expect((await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`)).status).toBe(200);

    const r = await request(app).post(`/api/users/${user.user.id}/force-password-reset`).set('Authorization', `Bearer ${admin.token}`);
    expect(r.status).toBe(200);

    // Live token revoked.
    expect((await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`)).status).toBe(401);

    // Login blocked with a clear code.
    const login = await request(app).post('/api/auth/login').send({ email: 'fpr-user@test.com', password: STRONG });
    expect(login.status).toBe(403);
    expect(login.body.code).toBe('PASSWORD_RESET_REQUIRED');

    // Simulate the completed reset (the reset endpoint clears the flag).
    db.prepare('UPDATE users SET force_password_reset = 0 WHERE id = ?').run(user.user.id);
    const login2 = await request(app).post('/api/auth/login').send({ email: 'fpr-user@test.com', password: STRONG });
    expect(login2.status).toBe(200);
  });

  it('force-reset-all excludes the acting admin', async () => {
    const admin = await registerAndLogin({ email: 'fpra-admin@test.com', role: 'Admin' });
    // A second member of the org must exist for the reset to have anyone to hit.
    await registerAndLogin({ email: 'fpra-user@test.com', orgId: admin.orgId });

    const r = await request(app).post('/api/users/force-password-reset-all').set('Authorization', `Bearer ${admin.token}`);
    expect(r.status).toBe(200);

    const ul = await request(app).post('/api/auth/login').send({ email: 'fpra-user@test.com', password: STRONG });
    expect(ul.body.code).toBe('PASSWORD_RESET_REQUIRED');

    const al = await request(app).post('/api/auth/login').send({ email: 'fpra-admin@test.com', password: STRONG });
    expect(al.status).toBe(200); // acting admin not forced
  });
});

describe('maintenance mode', () => {
  it('walls off non-admins but lets admins and login through', async () => {
    const admin = await registerAndLogin({ email: 'mnt-admin@test.com', role: 'SuperAdmin' }); // maintenance is platform-wide
    const user  = await registerAndLogin({ email: 'mnt-user@test.com' });

    const on = await request(app).post('/api/users/maintenance').set('Authorization', `Bearer ${admin.token}`).send({ enabled: true });
    expect(on.body.enabled).toBe(true);

    const blocked = await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`);
    expect(blocked.status).toBe(503);
    expect(blocked.body.code).toBe('MAINTENANCE');

    // Admin bypasses.
    expect((await request(app).get('/api/files').set('Authorization', `Bearer ${admin.token}`)).status).toBe(200);
    // Login endpoint stays reachable so an admin can sign in.
    expect((await request(app).post('/api/auth/login').send({ email: 'mnt-user@test.com', password: STRONG })).status).toBe(200);

    await request(app).post('/api/users/maintenance').set('Authorization', `Bearer ${admin.token}`).send({ enabled: false });
    expect((await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`)).status).toBe(200);
  });
});

describe('email verification before login', () => {
  it('is enforced only when email delivery is configured', async () => {
    const OLD_U = process.env.EMAIL_USER, OLD_P = process.env.EMAIL_PASS;
    try {
      process.env.EMAIL_USER = 'ops@nexus.test';
      process.env.EMAIL_PASS = 'app-password';
      await request(app).post('/api/auth/register')
        .send({ firstName: 'V', lastName: 'U', businessName: 'B', email: 'unverified@test.com', password: STRONG });
      const login = await request(app).post('/api/auth/login').send({ email: 'unverified@test.com', password: STRONG });
      expect(login.status).toBe(403);
      expect(login.body.error).toMatch(/verify your email/i);
    } finally {
      process.env.EMAIL_USER = OLD_U; process.env.EMAIL_PASS = OLD_P;
    }
  });
});

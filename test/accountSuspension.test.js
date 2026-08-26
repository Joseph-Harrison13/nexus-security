const { app, db, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

describe('account suspension', () => {
  it('suspends a user: live token cut off and login blocked', async () => {
    const admin  = await registerAndLogin({ email: 'ir-admin@test.com', role: 'Admin' });
    const victim = await registerAndLogin({ email: 'victim@test.com', orgId: admin.orgId });

    // Works before suspension.
    let r = await request(app).get('/api/files').set('Authorization', `Bearer ${victim.token}`);
    expect(r.status).toBe(200);

    const susp = await request(app).post(`/api/users/${victim.user.id}/suspend`).set('Authorization', `Bearer ${admin.token}`);
    expect(susp.status).toBe(200);

    // Live token no longer works (revoked jti -> 401, or suspended -> 403).
    r = await request(app).get('/api/files').set('Authorization', `Bearer ${victim.token}`);
    expect([401, 403]).toContain(r.status);

    // Password login is refused outright.
    const login = await request(app).post('/api/auth/login').send({ email: 'victim@test.com', password: STRONG });
    expect(login.status).toBe(403);
  });

  it('middleware rejects a live token the moment the account is flagged suspended', async () => {
    const victim = await registerAndLogin({ email: 'v2@test.com' });
    // Flag suspended WITHOUT revoking tokens, to exercise the middleware guard.
    db.prepare('UPDATE users SET suspended = 1 WHERE id = ?').run(victim.user.id);
    const r = await request(app).get('/api/files').set('Authorization', `Bearer ${victim.token}`);
    expect(r.status).toBe(403);
    expect(r.body.code).toBe('ACCOUNT_SUSPENDED');
  });

  it('unsuspend restores the ability to log in', async () => {
    const admin  = await registerAndLogin({ email: 'ir-admin2@test.com', role: 'Admin' });
    const victim = await registerAndLogin({ email: 'v3@test.com', orgId: admin.orgId });

    await request(app).post(`/api/users/${victim.user.id}/suspend`).set('Authorization', `Bearer ${admin.token}`);
    await request(app).post(`/api/users/${victim.user.id}/unsuspend`).set('Authorization', `Bearer ${admin.token}`);

    const login = await request(app).post('/api/auth/login').send({ email: 'v3@test.com', password: STRONG });
    expect(login.status).toBe(200);
    expect(login.body.needsTwoFactor).toBe(true);
  });

  it('non-admins cannot suspend, and admins cannot suspend themselves', async () => {
    const admin = await registerAndLogin({ email: 'ir-admin3@test.com', role: 'Admin' });
    const user  = await registerAndLogin({ email: 'plainuser@test.com' });

    const byUser = await request(app).post(`/api/users/${admin.user.id}/suspend`).set('Authorization', `Bearer ${user.token}`);
    expect(byUser.status).toBe(403);

    const self = await request(app).post(`/api/users/${admin.user.id}/suspend`).set('Authorization', `Bearer ${admin.token}`);
    expect(self.status).toBe(400);
  });
});

describe('global session revocation (panic button)', () => {
  it('revokes every session so existing tokens stop working', async () => {
    const admin = await registerAndLogin({ email: 'panic-admin@test.com', role: 'Admin' });
    const user  = await registerAndLogin({ email: 'panic-user@test.com', orgId: admin.orgId });

    // Both tokens work first.
    expect((await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`)).status).toBe(200);

    const res = await request(app).post('/api/users/revoke-all-sessions').set('Authorization', `Bearer ${admin.token}`);
    expect(res.status).toBe(200);
    expect(res.body.sessionsRevoked).toBeGreaterThanOrEqual(2);

    // The user's previously-valid token is now revoked.
    const after = await request(app).get('/api/files').set('Authorization', `Bearer ${user.token}`);
    expect(after.status).toBe(401);
  });

  it('non-admins cannot trigger the panic button', async () => {
    const user = await registerAndLogin({ email: 'nopanic@test.com' });
    const res = await request(app).post('/api/users/revoke-all-sessions').set('Authorization', `Bearer ${user.token}`);
    expect(res.status).toBe(403);
  });
});

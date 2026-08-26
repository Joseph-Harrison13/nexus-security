const { app, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

describe('email 2FA setting', () => {
  it('is on by default and can be toggled off', async () => {
    const { token } = await registerAndLogin({ email: 'e2fa@test.com' });

    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(me.body.email_2fa).toBe(1);

    const off = await request(app).post('/api/auth/email-2fa').set('Authorization', `Bearer ${token}`).send({ enabled: false });
    expect(off.body.email_2fa).toBe(0);
  });
});

describe('account-wide require 2FA', () => {
  it('blocks a user from disabling 2FA when an admin requires it', async () => {
    const admin = await registerAndLogin({ email: 'r2fa-admin@test.com', role: 'Admin' });

    const req = await request(app).post('/api/dashboard/require-2fa').set('Authorization', `Bearer ${admin.token}`).send({ enabled: true });
    expect(req.status).toBe(200);

    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${admin.token}`);
    expect(me.body.require_2fa).toBe(true);

    const off = await request(app).post('/api/auth/email-2fa').set('Authorization', `Bearer ${admin.token}`).send({ enabled: false });
    expect(off.status).toBe(403);
  });

  it('only admins can change the requirement', async () => {
    const { token } = await registerAndLogin({ email: 'r2fa-user@test.com' });
    const res = await request(app).post('/api/dashboard/require-2fa').set('Authorization', `Bearer ${token}`).send({ enabled: true });
    expect(res.status).toBe(403);
  });
});

describe('devices & sessions', () => {
  it('lists the current session and flags it', async () => {
    const { token } = await registerAndLogin({ email: 'sess@test.com' });
    const res = await request(app).get('/api/sessions').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body.some((s) => s.is_current)).toBe(true);
  });

  it('revokes all other sessions', async () => {
    const { token } = await registerAndLogin({ email: 'sess2@test.com' });
    const res = await request(app).delete('/api/sessions').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});

describe('account data export & deletion', () => {
  it('exports account data as JSON', async () => {
    const { token } = await registerAndLogin({ email: 'exp@test.com' });
    const res = await request(app).get('/api/auth/export').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    const data = JSON.parse(res.text);
    expect(data.account.email).toBe('exp@test.com');
    expect(Array.isArray(data.activity)).toBe(true);
    expect(Array.isArray(data.files)).toBe(true);
  });

  it('requires the correct password to delete the account', async () => {
    const { token } = await registerAndLogin({ email: 'del@test.com' });

    const wrong = await request(app).delete('/api/auth/me').set('Authorization', `Bearer ${token}`).send({ password: 'WrongPass9!' });
    expect(wrong.status).toBe(401);

    const right = await request(app).delete('/api/auth/me').set('Authorization', `Bearer ${token}`).send({ password: STRONG });
    expect(right.status).toBe(200);

    // The account is gone — login now fails.
    const login = await request(app).post('/api/auth/login').send({ email: 'del@test.com', password: STRONG });
    expect(login.status).toBe(401);
  });
});

const speakeasy = require('speakeasy');
const { app, db, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

describe('authenticator app (TOTP) setup', () => {
  it('sets up, verifies, returns backup codes, and disables', async () => {
    const { token, user } = await registerAndLogin({ email: 'totp@test.com', noTotp: true });

    // 1. Start setup → get a secret + QR.
    const setup = await request(app).get('/api/auth/setup-2fa').set('Authorization', `Bearer ${token}`);
    expect(setup.status).toBe(200);
    expect(setup.body.qrDataUrl).toMatch(/^data:image\/png/);
    const secret = setup.body.secret;

    // 2. A wrong code is rejected.
    const bad = await request(app).post('/api/auth/confirm-2fa').set('Authorization', `Bearer ${token}`).send({ code: '000000' });
    expect(bad.status).toBe(401);

    // 3. A real code from the secret activates 2FA and returns backup codes.
    const code = speakeasy.totp({ secret, encoding: 'base32' });
    const confirm = await request(app).post('/api/auth/confirm-2fa').set('Authorization', `Bearer ${token}`).send({ code });
    expect(confirm.status).toBe(200);
    expect(Array.isArray(confirm.body.backupCodes)).toBe(true);
    expect(confirm.body.backupCodes.length).toBe(8);

    // 4. /me now reports it enabled.
    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(me.body.totp_enabled).toBe(1);

    // 5. Disabling requires the correct password.
    const wrong = await request(app).post('/api/auth/disable-2fa').set('Authorization', `Bearer ${token}`).send({ password: 'WrongPass9!' });
    expect(wrong.status).toBe(401);

    const off = await request(app).post('/api/auth/disable-2fa').set('Authorization', `Bearer ${token}`).send({ password: STRONG });
    expect(off.status).toBe(200);

    expect(db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(user.id).totp_enabled).toBe(0);
  });

  it("won't start setup when 2FA is already enabled", async () => {
    const { token } = await registerAndLogin({ email: 'totp2@test.com', noTotp: true });
    const secret = (await request(app).get('/api/auth/setup-2fa').set('Authorization', `Bearer ${token}`)).body.secret;
    const code = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app).post('/api/auth/confirm-2fa').set('Authorization', `Bearer ${token}`).send({ code });

    const again = await request(app).get('/api/auth/setup-2fa').set('Authorization', `Bearer ${token}`);
    expect(again.status).toBe(409);
  });

  it('lets a TOTP user log in with an authenticator code', async () => {
    const { token } = await registerAndLogin({ email: 'totp3@test.com', noTotp: true });
    const secret = (await request(app).get('/api/auth/setup-2fa').set('Authorization', `Bearer ${token}`)).body.secret;
    await request(app).post('/api/auth/confirm-2fa').set('Authorization', `Bearer ${token}`)
      .send({ code: speakeasy.totp({ secret, encoding: 'base32' }) });

    const login = await request(app).post('/api/auth/login').send({ email: 'totp3@test.com', password: STRONG });
    expect(login.body.needsTwoFactor).toBe(true);
    expect(login.body.totpEnabled).toBe(true);

    const verify = await request(app).post('/api/auth/verify-2fa')
      .send({ tempToken: login.body.tempToken, code: speakeasy.totp({ secret, encoding: 'base32' }) });
    expect(verify.status).toBe(200);
    expect(verify.body.token).toBeTruthy();
  });
});

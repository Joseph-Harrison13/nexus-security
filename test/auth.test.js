const { app, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

describe('POST /api/auth/register', () => {
  it('rejects a weak password', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ firstName: 'A', lastName: 'B', businessName: 'C', email: 'weak@test.com', password: 'weak' });
    expect(res.status).toBe(400);
  });

  it('does not reveal whether an account already exists', async () => {
    const body = { firstName: 'A', lastName: 'B', businessName: 'C', email: 'dup@test.com', password: STRONG };
    const first = await request(app).post('/api/auth/register').send(body);
    const second = await request(app).post('/api/auth/register').send(body);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201); // generic 201, never 409
  });
});

describe('login + 2FA', () => {
  it('rejects a wrong password', async () => {
    await request(app).post('/api/auth/register')
      .send({ firstName: 'A', lastName: 'B', businessName: 'C', email: 'x@test.com', password: STRONG });
    const res = await request(app).post('/api/auth/login').send({ email: 'x@test.com', password: 'Wrong1!aa' });
    expect(res.status).toBe(401);
  });

  it('returns needsTwoFactor then a token after verification', async () => {
    await request(app).post('/api/auth/register')
      .send({ firstName: 'A', lastName: 'B', businessName: 'C', email: 'flow@test.com', password: STRONG });
    const login = await request(app).post('/api/auth/login').send({ email: 'flow@test.com', password: STRONG });
    expect(login.body.needsTwoFactor).toBe(true);
    expect(login.body.tempToken).toBeTruthy();

    const verify = await request(app).post('/api/auth/verify-2fa')
      .send({ tempToken: login.body.tempToken, code: process.env.DEMO_2FA_CODE || '482719' });
    expect(verify.status).toBe(200);
    expect(verify.body.token).toBeTruthy();
  });

  it('rejects an incorrect 2FA code', async () => {
    await request(app).post('/api/auth/register')
      .send({ firstName: 'A', lastName: 'B', businessName: 'C', email: 'bad2fa@test.com', password: STRONG });
    const login = await request(app).post('/api/auth/login').send({ email: 'bad2fa@test.com', password: STRONG });
    const verify = await request(app).post('/api/auth/verify-2fa')
      .send({ tempToken: login.body.tempToken, code: '000000' });
    expect(verify.status).toBe(401);
  });
});

describe('protected routes', () => {
  it('rejects requests without a token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('returns the current user with a valid token', async () => {
    const { token, email } = await registerAndLogin({ email: 'me@test.com' });
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.email).toBe(email);
  });
});

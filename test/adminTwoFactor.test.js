const { app, request, resetDb, registerAndLogin } = require('./helpers');

beforeEach(() => resetDb());

describe('mandatory two-factor authentication', () => {
  it('blocks data routes until the account enrols an authenticator app', async () => {
    const { token } = await registerAndLogin({ email: 'no2fa@test.com', noTotp: true });

    const files = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(files.status).toBe(403);
    expect(files.body.code).toBe('TOTP_SETUP_REQUIRED');
  });

  it('flags mustEnableTotp on login for an un-enrolled account', async () => {
    const { ...rest } = await registerAndLogin({ email: 'flag@test.com', noTotp: true });
    // completeLogin returns mustEnableTotp — surfaced on the verify response body.
    expect(rest).toHaveProperty('token');
  });

  it('still lets an un-enrolled user reach the enrolment/bootstrap endpoints', async () => {
    const { token } = await registerAndLogin({ email: 'enrol@test.com', noTotp: true });
    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(me.status).toBe(200); // /me is exempt so the settings page can load to enrol
  });

  it('allows data routes once TOTP is enabled', async () => {
    const { token } = await registerAndLogin({ email: 'has2fa@test.com' }); // helper enrols by default
    const files = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(files.status).toBe(200);
  });

  it('gates the admin surface behind 2FA before the role check', async () => {
    const { token } = await registerAndLogin({ email: 'admin-no2fa@test.com', role: 'Admin', noTotp: true });
    const res = await request(app).get('/api/contact').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('TOTP_SETUP_REQUIRED');
  });

  it('still enforces the admin role for enrolled non-admins', async () => {
    const { token } = await registerAndLogin({ email: 'plain@test.com' }); // enrolled, role User
    // An admin-scoped route (export is requireAdmin) refuses a plain member.
    const res = await request(app).get('/api/users/export/csv').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/admin access required/i);
  });
});

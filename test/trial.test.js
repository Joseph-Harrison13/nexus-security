const { app, db, request, resetDb, registerAndLogin } = require('./helpers');

beforeEach(() => resetDb());
const auth = t => ({ Authorization: `Bearer ${t}` });

function expireTrial(orgId) {
  db.prepare("UPDATE organizations SET subscription_status = 'trialing', trial_ends_at = ? WHERE id = ?")
    .run(new Date(Date.now() - 86400000).toISOString(), orgId);
}

describe('free-trial lifecycle', () => {
  it('an active trial can use the app', async () => {
    const u = await registerAndLogin({ email: 't1@test.com' });
    expect((await request(app).get('/api/files').set(auth(u.token))).status).toBe(200);
  });

  it('locks the account with TRIAL_EXPIRED once the trial passes', async () => {
    const u = await registerAndLogin({ email: 't2@test.com' });
    expireTrial(u.orgId);

    const r = await request(app).get('/api/files').set(auth(u.token));
    expect(r.status).toBe(402);
    expect(r.body.code).toBe('TRIAL_EXPIRED');

    // Account + billing endpoints stay reachable so the user can upgrade.
    expect((await request(app).get('/api/auth/me').set(auth(u.token))).status).toBe(200);
    expect((await request(app).get('/api/stripe/status').set(auth(u.token))).status).toBe(200);
  });

  it('unlocks once upgraded to an active (paid) plan', async () => {
    const u = await registerAndLogin({ email: 't3@test.com' });
    expireTrial(u.orgId);
    db.prepare("UPDATE organizations SET subscription_status = 'active' WHERE id = ?").run(u.orgId);
    expect((await request(app).get('/api/files').set(auth(u.token))).status).toBe(200);
  });

  it('never locks out the platform SuperAdmin', async () => {
    const s = await registerAndLogin({ email: 'owner@test.com', role: 'SuperAdmin' });
    expireTrial(s.orgId);
    expect((await request(app).get('/api/files').set(auth(s.token))).status).toBe(200);
  });

  it('reports trial status + days remaining', async () => {
    const u = await registerAndLogin({ email: 't4@test.com' });
    const st = await request(app).get('/api/stripe/status').set(auth(u.token));
    expect(st.body.onTrial).toBe(true);
    expect(st.body.trialDaysLeft).toBeGreaterThan(0);
    expect(st.body.trialDaysLeft).toBeLessThanOrEqual(21);
  });
});

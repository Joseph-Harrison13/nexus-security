const { app, request, resetDb, registerAndLogin, STRONG } = require('./helpers');

beforeEach(() => resetDb());

function newUserPayload(email, plan = 'Starter') {
  return { email, password: STRONG, name: 'Member', role: 'User', plan };
}

describe('seat limits & per-account overrides', () => {
  it('enforces the plan seat limit on user creation', async () => {
    // Admin on Starter (3 seats). registerAndLogin creates user #1 (the admin).
    const { token } = await registerAndLogin({ email: 'admin@seat.com', role: 'Admin' });

    const u2 = await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('u2@seat.com'));
    expect(u2.status).toBe(201); // total now 2
    const u3 = await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('u3@seat.com'));
    expect(u3.status).toBe(201); // total now 3 (at the Starter cap)

    const u4 = await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('u4@seat.com'));
    expect(u4.status).toBe(403); // over the 3-seat cap
  });

  it('lets an admin override the seat limit', async () => {
    const { token } = await registerAndLogin({ email: 'admin2@seat.com', role: 'Admin' });
    // Fill the Starter cap (admin + 2 = 3).
    await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('a@seat.com'));
    await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('b@seat.com'));

    // Raise the cap via override, then the next create should succeed.
    const set = await request(app).post('/api/dashboard/account-limits').set('Authorization', `Bearer ${token}`).send({ seatOverride: 10 });
    expect(set.status).toBe(200);
    expect(set.body.seatOverride).toBe(10);

    const c = await request(app).post('/api/users').set('Authorization', `Bearer ${token}`).send(newUserPayload('c@seat.com'));
    expect(c.status).toBe(201);
  });

  it('applies a storage override to the dashboard limit', async () => {
    const { token } = await registerAndLogin({ email: 'admin3@seat.com', role: 'Admin' });

    const before = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${token}`);
    expect(before.body.storage.limitGB).toBe(10); // Starter default

    await request(app).post('/api/dashboard/account-limits').set('Authorization', `Bearer ${token}`).send({ storageOverrideGb: 1000 });

    const after = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${token}`);
    expect(after.body.storage.limitGB).toBe(1000);
  });

  it('clears an override when set to empty', async () => {
    const { token } = await registerAndLogin({ email: 'admin4@seat.com', role: 'Admin' });
    await request(app).post('/api/dashboard/account-limits').set('Authorization', `Bearer ${token}`).send({ storageOverrideGb: 500 });
    await request(app).post('/api/dashboard/account-limits').set('Authorization', `Bearer ${token}`).send({ storageOverrideGb: '' });

    const stats = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${token}`);
    expect(stats.body.storage.limitGB).toBe(10); // back to plan default
  });

  it('blocks non-admins from changing account limits', async () => {
    const { token } = await registerAndLogin({ email: 'plainuser@seat.com' }); // role: User
    const res = await request(app).post('/api/dashboard/account-limits').set('Authorization', `Bearer ${token}`).send({ seatOverride: 99 });
    expect(res.status).toBe(403);
  });

  it('exposes per-plan storage thresholds in stats', async () => {
    const { token } = await registerAndLogin({ email: 'thr@seat.com' });
    const stats = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${token}`);
    expect(stats.body.storage.thresholds).toEqual({ warn: 80, critical: 95 }); // Starter
  });
});

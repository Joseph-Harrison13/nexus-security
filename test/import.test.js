const { app, db, request, resetDb, registerAndLogin } = require('./helpers');

beforeEach(() => resetDb());

describe('bulk user import', () => {
  it('creates users from CSV and returns invite links (email not configured in test)', async () => {
    const { token } = await registerAndLogin({ email: 'imp-admin@test.com', role: 'Admin' });
    const csv = 'name,email,role,plan\nAlice Imp,alice@imp.test,User,Growth\nBob Imp,bob@imp.test';

    const res = await request(app).post('/api/users/import').set('Authorization', `Bearer ${token}`).send({ csv });
    expect(res.status).toBe(200);
    expect(res.body.createdCount).toBe(2);
    expect(res.body.invitesEmailed).toBe(false);            // no SMTP in test env
    expect(res.body.created[0].inviteLink).toMatch(/reset-password\.html\?token=/);
    // Never returns a plaintext password.
    expect(res.body.created[0].tempPassword).toBeUndefined();

    // The accounts actually exist.
    expect(db.prepare('SELECT COUNT(*) AS n FROM users').get().n).toBe(3); // admin + 2
  });

  it('skips duplicates and reports invalid rows', async () => {
    const { token } = await registerAndLogin({ email: 'imp-admin2@test.com', role: 'Admin' });
    // Pre-create one of the emails.
    await request(app).post('/api/users').set('Authorization', `Bearer ${token}`)
      .send({ email: 'existing@imp.test', password: 'Str0ng!Pass1', name: 'Exist', role: 'User', plan: 'Starter' });

    const csv = 'name,email\nExisting User,existing@imp.test\nNo Email,not-an-email\nGood One,good@imp.test';
    const res = await request(app).post('/api/users/import').set('Authorization', `Bearer ${token}`).send({ csv });

    expect(res.body.createdCount).toBe(1);
    expect(res.body.skippedCount).toBe(1); // duplicate
    expect(res.body.errorCount).toBe(1);   // invalid email
  });

  it('respects the seat limit during import', async () => {
    const { token } = await registerAndLogin({ email: 'imp-admin3@test.com', role: 'Admin' });
    // Starter = 3 seats; admin is #1, so only 2 more can be created.
    const csv = 'name,email\nA,a@imp.test\nB,b@imp.test\nC,c@imp.test\nD,d@imp.test';
    const res = await request(app).post('/api/users/import').set('Authorization', `Bearer ${token}`).send({ csv });

    expect(res.body.createdCount).toBe(2);
    expect(res.body.errors.some((e) => /Seat limit/.test(e.reason))).toBe(true);
  });

  it('lets the invited user set their password and sign in', async () => {
    const { token } = await registerAndLogin({ email: 'imp-admin4@test.com', role: 'Admin' });
    const res = await request(app).post('/api/users/import').set('Authorization', `Bearer ${token}`)
      .send({ csv: 'name,email\nCarol,carol@imp.test' });
    const link = res.body.created[0].inviteLink;
    const rawToken = link.split('token=')[1];

    const set = await request(app).post('/api/auth/reset-password').send({ token: rawToken, password: 'Br4nd!New9' });
    expect(set.status).toBe(200);

    const login = await request(app).post('/api/auth/login').send({ email: 'carol@imp.test', password: 'Br4nd!New9' });
    // Reaches the 2FA step → password was accepted.
    expect(login.body.needsTwoFactor || login.body.needsLocationVerification || login.body.token).toBeTruthy();
  });

  it('blocks non-admins from importing', async () => {
    const { token } = await registerAndLogin({ email: 'imp-plain@test.com' });
    const res = await request(app).post('/api/users/import').set('Authorization', `Bearer ${token}`).send({ csv: 'name,email\nX,x@imp.test' });
    expect(res.status).toBe(403);
  });
});

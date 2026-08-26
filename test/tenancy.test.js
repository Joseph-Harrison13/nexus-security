const { app, request, resetDb, registerAndLogin, uploadFile } = require('./helpers');

beforeEach(() => resetDb());

// Two separate customer organizations, plus the platform owner.
async function twoOrgs() {
  const adminA = await registerAndLogin({ email: 'a-admin@test.com', role: 'Admin' });
  const userA  = await registerAndLogin({ email: 'a-user@test.com',  orgId: adminA.orgId });
  const adminB = await registerAndLogin({ email: 'b-admin@test.com', role: 'Admin' });
  const userB  = await registerAndLogin({ email: 'b-user@test.com',  orgId: adminB.orgId });
  const superA = await registerAndLogin({ email: 'owner@test.com',   role: 'SuperAdmin' });
  return { adminA, userA, adminB, userB, superA };
}
const auth = t => ({ Authorization: `Bearer ${t}` });

describe('cross-tenant isolation', () => {
  it("keeps one org's files invisible and untouchable to another org", async () => {
    const { adminA, userA, adminB, userB, superA } = await twoOrgs();
    const fileId = (await uploadFile(userA.token, 'secret.txt', 'org A confidential')).body.id;
    expect(fileId).toBeTruthy();

    // Org B (member AND admin) cannot read it.
    expect((await request(app).get(`/api/files/${fileId}/download`).set(auth(userB.token))).status).toBe(403);
    expect((await request(app).get(`/api/files/${fileId}/download`).set(auth(adminB.token))).status).toBe(403);
    // Org B cannot delete or share it either.
    expect((await request(app).delete(`/api/files/${fileId}`).set(auth(adminB.token))).status).toBe(403);
    expect((await request(app).post(`/api/files/${fileId}/share`).set(auth(adminB.token)).send({})).status).toBe(403);

    // Same-org admin and the platform owner CAN.
    expect((await request(app).get(`/api/files/${fileId}/download`).set(auth(adminA.token))).status).toBe(200);
    expect((await request(app).get(`/api/files/${fileId}/download`).set(auth(superA.token))).status).toBe(200);

    // Org B's file listing does not include org A's file.
    const bList = await request(app).get('/api/files').set(auth(adminB.token));
    expect((bList.body.data || []).some(f => f.id === fileId)).toBe(false);
  });

  it('scopes the admin user list to the admin’s own organization', async () => {
    // twoOrgs() creates the members either way; this test only reads the list.
    const { adminA, superA } = await twoOrgs();
    const listA = await request(app).get('/api/users?limit=100').set(auth(adminA.token));
    const emails = (listA.body.data || []).map(u => u.email);
    expect(emails).toContain('a-admin@test.com');
    expect(emails).toContain('a-user@test.com');
    expect(emails).not.toContain('b-user@test.com');   // <- the isolation guarantee
    expect(emails).not.toContain('b-admin@test.com');

    // The platform owner sees everyone.
    const listSuper = await request(app).get('/api/users?limit=100').set(auth(superA.token));
    const all = (listSuper.body.data || []).map(u => u.email);
    expect(all).toContain('a-user@test.com');
    expect(all).toContain('b-user@test.com');
  });

  it('blocks an admin from managing users in another org', async () => {
    const { adminA, userB } = await twoOrgs();
    // 404 (not 403) so we don't even confirm the foreign user exists.
    expect((await request(app).post(`/api/users/${userB.id}/suspend`).set(auth(adminA.token))).status).toBe(404);
    expect((await request(app).post(`/api/users/${userB.id}/force-password-reset`).set(auth(adminA.token))).status).toBe(404);
    expect((await request(app).delete(`/api/users/${userB.id}`).set(auth(adminA.token))).status).toBe(404);
    expect((await request(app).put(`/api/users/${userB.id}`).set(auth(adminA.token)).send({ name: 'Hacked' })).status).toBe(403);
  });

  it('scopes the panic button + force-reset-all to the admin’s org only', async () => {
    const { adminA, userA, userB } = await twoOrgs();
    // adminA revokes all sessions in org A.
    const r = await request(app).post('/api/users/revoke-all-sessions').set(auth(adminA.token));
    expect(r.status).toBe(200);
    // org A member is signed out...
    expect((await request(app).get('/api/files').set(auth(userA.token))).status).toBe(401);
    // ...but org B member is untouched.
    expect((await request(app).get('/api/files').set(auth(userB.token))).status).toBe(200);
  });

  it('reserves platform maintenance mode for the SuperAdmin', async () => {
    const { adminA, superA } = await twoOrgs();
    expect((await request(app).post('/api/users/maintenance').set(auth(adminA.token)).send({ enabled: true })).status).toBe(403);
    expect((await request(app).post('/api/users/maintenance').set(auth(superA.token)).send({ enabled: true })).status).toBe(200);
    await request(app).post('/api/users/maintenance').set(auth(superA.token)).send({ enabled: false });
  });

  it('counts dashboard stats per-organization', async () => {
    const { adminA, userA } = await twoOrgs();
    await uploadFile(userA.token, 'a1.txt', 'x');
    const stats = await request(app).get('/api/dashboard/stats').set(auth(adminA.token));
    expect(stats.body.counts.users).toBe(2);   // a-admin + a-user, NOT org B
    expect(stats.body.counts.files).toBe(1);    // only org A's file
  });
});

const { app, db, request, resetDb, registerAndLogin, uploadFile } = require('./helpers');

beforeEach(() => resetDb());

async function createShare(token, fileId, body = {}) {
  return request(app).post(`/api/files/${fileId}/share`).set('Authorization', `Bearer ${token}`).send(body);
}

describe('secure file sharing', () => {
  it('creates a public share link that anyone can download (no auth)', async () => {
    const { token } = await registerAndLogin({ email: 'sh1@test.com' });
    const id = (await uploadFile(token, 'doc.txt', 'shared content')).body.id;

    const share = await createShare(token, id, { expiresInHours: 24 });
    expect(share.status).toBe(201);
    const t = share.body.token;

    const info = await request(app).get(`/api/share/${t}`);
    expect(info.body.available).toBe(true);
    expect(info.body.requiresPassword).toBe(false);

    const dl = await request(app).post(`/api/share/${t}/download`).send({});
    expect(dl.status).toBe(200);
    expect(dl.headers['content-disposition']).toContain('doc.txt');
  });

  it('enforces a share password', async () => {
    const { token } = await registerAndLogin({ email: 'sh2@test.com' });
    const id = (await uploadFile(token)).body.id;
    const t = (await createShare(token, id, { password: 'letmein' })).body.token;

    const info = await request(app).get(`/api/share/${t}`);
    expect(info.body.requiresPassword).toBe(true);

    const wrong = await request(app).post(`/api/share/${t}/download`).send({ password: 'nope' });
    expect(wrong.status).toBe(401);

    const right = await request(app).post(`/api/share/${t}/download`).send({ password: 'letmein' });
    expect(right.status).toBe(200);
  });

  it('revokes a share link', async () => {
    const { token } = await registerAndLogin({ email: 'sh3@test.com' });
    const id = (await uploadFile(token)).body.id;
    const share = (await createShare(token, id, {})).body;

    const list = await request(app).get('/api/files/shares').set('Authorization', `Bearer ${token}`);
    const shareId = list.body.data[0].id;

    const revoke = await request(app).delete(`/api/files/shares/${shareId}`).set('Authorization', `Bearer ${token}`);
    expect(revoke.status).toBe(200);

    const info = await request(app).get(`/api/share/${share.token}`);
    expect(info.body.available).toBe(false);
    expect(info.body.reason).toBe('revoked');
  });

  it('treats an expired link as unavailable', async () => {
    const { token } = await registerAndLogin({ email: 'sh4@test.com' });
    const id = (await uploadFile(token)).body.id;
    const t = (await createShare(token, id, { expiresInHours: 1 })).body.token;

    db.prepare('UPDATE file_shares SET expires_at = ? WHERE token = ?').run(new Date(Date.now() - 3600000).toISOString(), t);

    const info = await request(app).get(`/api/share/${t}`);
    expect(info.status).toBe(410);
    expect(info.body.reason).toBe('expired');
  });

  it('respects a download cap', async () => {
    const { token } = await registerAndLogin({ email: 'sh5@test.com' });
    const id = (await uploadFile(token)).body.id;
    const t = (await createShare(token, id, { maxDownloads: 1 })).body.token;

    const first = await request(app).post(`/api/share/${t}/download`).send({});
    expect(first.status).toBe(200);
    const second = await request(app).get(`/api/share/${t}`);
    expect(second.body.available).toBe(false);
    expect(second.body.reason).toBe('used_up');
  });

  it("won't let a user share someone else's file", async () => {
    const a = await registerAndLogin({ email: 'sh-a@test.com' });
    const b = await registerAndLogin({ email: 'sh-b@test.com' });
    const aFile = (await uploadFile(a.token)).body.id;

    const share = await createShare(b.token, aFile, {});
    expect(share.status).toBe(403);
  });

  it('returns 404 for an unknown share token', async () => {
    const info = await request(app).get('/api/share/deadbeefdeadbeef');
    expect(info.status).toBe(404);
  });
});

const { app, db, request, resetDb, registerAndLogin, uploadFile } = require('./helpers');

beforeEach(() => resetDb());

describe('file trash (soft delete)', () => {
  it('moves a deleted file to the trash, out of the active list', async () => {
    const { token } = await registerAndLogin({ email: 'trash1@test.com' });
    const id = (await uploadFile(token)).body.id;

    const del = await request(app).delete(`/api/files/${id}`).set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(200);
    expect(del.body.recoverableDays).toBe(30);

    const active = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(active.body.data.some((f) => f.id === id)).toBe(false);

    const trash = await request(app).get('/api/files/trash').set('Authorization', `Bearer ${token}`);
    expect(trash.body.data.some((f) => f.id === id)).toBe(true);
  });

  it('restores a file from the trash', async () => {
    const { token } = await registerAndLogin({ email: 'trash2@test.com' });
    const id = (await uploadFile(token)).body.id;
    await request(app).delete(`/api/files/${id}`).set('Authorization', `Bearer ${token}`);

    const restore = await request(app).post(`/api/files/${id}/restore`).set('Authorization', `Bearer ${token}`);
    expect(restore.status).toBe(200);

    const active = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(active.body.data.some((f) => f.id === id)).toBe(true);
  });

  it('permanently deletes from the trash and frees storage', async () => {
    const { token, user } = await registerAndLogin({ email: 'trash3@test.com' });
    const id = (await uploadFile(token, 'note.txt', 'some bytes here')).body.id;
    const usedAfterUpload = db.prepare('SELECT storage_used FROM users WHERE id = ?').get(user.id).storage_used;
    expect(usedAfterUpload).toBeGreaterThan(0);

    await request(app).delete(`/api/files/${id}`).set('Authorization', `Bearer ${token}`);
    const perm = await request(app).delete(`/api/files/${id}/permanent`).set('Authorization', `Bearer ${token}`);
    expect(perm.status).toBe(200);

    const trash = await request(app).get('/api/files/trash').set('Authorization', `Bearer ${token}`);
    expect(trash.body.data.some((f) => f.id === id)).toBe(false);

    const usedAfterPurge = db.prepare('SELECT storage_used FROM users WHERE id = ?').get(user.id).storage_used;
    expect(usedAfterPurge).toBe(0);
  });

  it('keeps trashed files out of the ZIP export', async () => {
    const { token } = await registerAndLogin({ email: 'trash4@test.com' });
    const id = (await uploadFile(token)).body.id;
    await request(app).delete(`/api/files/${id}`).set('Authorization', `Bearer ${token}`);
    const zip = await request(app).get('/api/files/export/zip').set('Authorization', `Bearer ${token}`);
    expect(zip.status).toBe(404); // only file was trashed → nothing to export
  });
});

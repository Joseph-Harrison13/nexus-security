const { app, db, request, resetDb, registerAndLogin } = require('./helpers');

beforeEach(() => resetDb());

describe('files', () => {
  it('requires auth to list', async () => {
    const res = await request(app).get('/api/files');
    expect(res.status).toBe(401);
  });

  it('uploads, lists, and deletes a file', async () => {
    const { token } = await registerAndLogin({ email: 'f@test.com' });

    const up = await request(app).post('/api/files/upload')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('hello world'), 'note.txt');
    expect(up.status).toBe(201);
    const id = up.body.id;

    const list = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(list.body.data.some((f) => f.id === id)).toBe(true);

    const del = await request(app).delete(`/api/files/${id}`).set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(200);

    const after = await request(app).get('/api/files').set('Authorization', `Bearer ${token}`);
    expect(after.body.data.some((f) => f.id === id)).toBe(false);
  });

  it('rejects a disallowed file type', async () => {
    const { token } = await registerAndLogin({ email: 'ext@test.com' });
    const up = await request(app).post('/api/files/upload')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('#!/bin/sh\necho hi'), 'evil.sh');
    expect(up.status).toBe(400);
  });

  it('enforces the per-plan storage quota', async () => {
    const { token, user } = await registerAndLogin({ email: 'q@test.com' });
    // New users are on Starter (10 GiB) — set usage to the limit.
    db.prepare('UPDATE users SET storage_used = ? WHERE id = ?').run(10 * 1024 ** 3, user.id);

    const up = await request(app).post('/api/files/upload')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('x'), 'tiny.txt');
    expect(up.status).toBe(413);
    expect(up.body.code).toBe('QUOTA_EXCEEDED');
  });

  it("forbids accessing another user's file", async () => {
    const a = await registerAndLogin({ email: 'owner@test.com' });
    const b = await registerAndLogin({ email: 'intruder@test.com' });

    const up = await request(app).post('/api/files/upload')
      .set('Authorization', `Bearer ${a.token}`)
      .attach('file', Buffer.from('secret'), 'secret.txt');
    const id = up.body.id;

    const res = await request(app).get(`/api/files/${id}/download`).set('Authorization', `Bearer ${b.token}`);
    expect(res.status).toBe(403);
  });
});

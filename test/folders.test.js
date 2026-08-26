const { app, request, resetDb, registerAndLogin, uploadFile } = require('./helpers');

beforeEach(() => resetDb());

async function makeFolder(token, name) {
  return request(app).post('/api/folders').set('Authorization', `Bearer ${token}`).send({ name });
}

describe('folders', () => {
  it('creates a folder and lists it with a file count', async () => {
    const { token } = await registerAndLogin({ email: 'fld1@test.com' });
    const create = await makeFolder(token, 'Payroll');
    expect(create.status).toBe(201);

    const list = await request(app).get('/api/folders').set('Authorization', `Bearer ${token}`);
    expect(list.body.data.length).toBe(1);
    expect(list.body.data[0].name).toBe('Payroll');
    expect(list.body.data[0].file_count).toBe(0);
  });

  it('rejects a duplicate folder name', async () => {
    const { token } = await registerAndLogin({ email: 'fld2@test.com' });
    await makeFolder(token, 'HR');
    const dupe = await makeFolder(token, 'hr'); // case-insensitive
    expect(dupe.status).toBe(409);
  });

  it('uploads into a folder and filters by it', async () => {
    const { token } = await registerAndLogin({ email: 'fld3@test.com' });
    const folderId = (await makeFolder(token, 'Contracts')).body.id;

    const up = await uploadFile(token, 'c.txt', 'data', { folderId });
    expect(up.body.folder_id).toBe(folderId);

    const inFolder = await request(app).get(`/api/files?folder=${folderId}`).set('Authorization', `Bearer ${token}`);
    expect(inFolder.body.data.length).toBe(1);

    const root = await request(app).get('/api/files?folder=root').set('Authorization', `Bearer ${token}`);
    expect(root.body.data.length).toBe(0);
  });

  it('moves a file into and out of a folder', async () => {
    const { token } = await registerAndLogin({ email: 'fld4@test.com' });
    const folderId = (await makeFolder(token, 'Media')).body.id;
    const id = (await uploadFile(token)).body.id;

    const move = await request(app).put(`/api/files/${id}/move`).set('Authorization', `Bearer ${token}`).send({ folderId });
    expect(move.status).toBe(200);
    expect(move.body.folderId).toBe(folderId);

    const toRoot = await request(app).put(`/api/files/${id}/move`).set('Authorization', `Bearer ${token}`).send({ folderId: null });
    expect(toRoot.body.folderId).toBe(null);
  });

  it('deletes a folder but keeps its files', async () => {
    const { token } = await registerAndLogin({ email: 'fld5@test.com' });
    const folderId = (await makeFolder(token, 'Temp')).body.id;
    const id = (await uploadFile(token, 'k.txt', 'x', { folderId })).body.id;

    const del = await request(app).delete(`/api/folders/${folderId}`).set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(200);

    // File still exists, now with no folder.
    const root = await request(app).get('/api/files?folder=root').set('Authorization', `Bearer ${token}`);
    expect(root.body.data.some((f) => f.id === id)).toBe(true);
  });

  it("won't move a file into another user's folder", async () => {
    const a = await registerAndLogin({ email: 'fld-a@test.com' });
    const b = await registerAndLogin({ email: 'fld-b@test.com' });
    const bFolder = (await makeFolder(b.token, 'Private')).body.id;
    const aFile = (await uploadFile(a.token)).body.id;

    const move = await request(app).put(`/api/files/${aFile}/move`).set('Authorization', `Bearer ${a.token}`).send({ folderId: bFolder });
    expect(move.status).toBe(404); // not a's folder
  });
});

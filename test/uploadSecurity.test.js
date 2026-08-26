const { app, request, resetDb, registerAndLogin } = require('./helpers');

beforeEach(() => resetDb());

function uploadRaw(token, buffer, filename) {
  return request(app).post('/api/files/upload')
    .set('Authorization', `Bearer ${token}`)
    .attach('file', buffer, filename);
}

describe('upload content validation', () => {
  it('rejects a text file disguised with an image extension', async () => {
    const { token } = await registerAndLogin();
    const res = await uploadRaw(token, Buffer.from('this is not really a png'), 'fake.png');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/does not match its extension/i);
  });

  it('rejects a text file disguised as a PDF', async () => {
    const { token } = await registerAndLogin();
    const res = await uploadRaw(token, Buffer.from('nope'), 'fake.pdf');
    expect(res.status).toBe(400);
  });

  it('accepts a real PDF whose content matches the extension', async () => {
    const { token } = await registerAndLogin();
    const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(64)]);
    const res = await uploadRaw(token, pdf, 'real.pdf');
    expect(res.status).toBe(201);
    expect(res.body.name).toBe('real.pdf');
  });

  it('still accepts genuine text files', async () => {
    const { token } = await registerAndLogin();
    const res = await uploadRaw(token, Buffer.from('hello, world'), 'notes.txt');
    expect(res.status).toBe(201);
  });
});

describe('filename sanitization', () => {
  it('strips filesystem/header-hostile characters from the stored name', async () => {
    const { token } = await registerAndLogin();
    const res = await uploadRaw(token, Buffer.from('ok'), 're<p>ort.txt');
    expect(res.status).toBe(201);
    expect(res.body.name).toBe('re_p_ort.txt');        // < > -> _
    expect(res.body.name).not.toMatch(/[<>"|?*]/);
  });
});

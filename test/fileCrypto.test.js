const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// Must be set before the module reads it (key is parsed lazily and cached).
process.env.FILE_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
const fc = require('../lib/fileCrypto');

function drain(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', c => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

describe('file encryption at rest (AES-256-GCM)', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nxfc-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('encrypts on disk and decrypts back to the exact plaintext', async () => {
    const fp = path.join(dir, 'client.txt');
    const plain = 'SSN 123-45-6789 — confidential. ' + 'x'.repeat(9000);
    fs.writeFileSync(fp, plain);

    await fc.encryptFileInPlace(fp);

    // On disk it is NOT plaintext, and carries our magic header.
    const raw = fs.readFileSync(fp);
    expect(raw.toString('utf8', 0, 4)).toBe('NXE1');
    expect(raw.includes(Buffer.from('123-45-6789'))).toBe(false);
    expect(fc.isEncrypted(fp)).toBe(true);

    const { stream, plainSize } = fc.createDecryptStream(fp);
    const out = await drain(stream);
    expect(plainSize).toBe(Buffer.byteLength(plain));
    expect(out.toString()).toBe(plain);
  });

  it('rejects a tampered file (integrity protection)', async () => {
    const fp = path.join(dir, 'tamper.bin');
    fs.writeFileSync(fp, 'important payroll data');
    await fc.encryptFileInPlace(fp);

    const buf = fs.readFileSync(fp);
    buf[buf.length - 20] ^= 0xff; // flip a ciphertext byte
    fs.writeFileSync(fp, buf);

    const { stream } = fc.createDecryptStream(fp);
    await expect(drain(stream)).rejects.toBeTruthy();
  });

  it('treats a legacy plaintext file as unencrypted', () => {
    const fp = path.join(dir, 'legacy.txt');
    fs.writeFileSync(fp, 'stored before encryption was enabled');
    expect(fc.isEncrypted(fp)).toBe(false);
  });
});

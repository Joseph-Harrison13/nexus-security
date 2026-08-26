// ─────────────────────────────────────────────────────────────
// Encryption at rest for locally-stored files (the 'disk' driver).
//
// Files are encrypted with AES-256-GCM — an authenticated cipher, so it gives
// both confidentiality (an attacker with the disk can't read the file) and
// integrity (a tampered file fails to decrypt instead of returning garbage).
//
// On-disk format:  MAGIC(4) | IV(12) | ciphertext | TAG(16)
//   - MAGIC lets the reader tell an encrypted file from a legacy plaintext one,
//     so pre-existing uploads keep working after this is switched on.
//   - The auth TAG is written at the END so both encryption and decryption can
//     stream (we read the small fixed-size IV/TAG separately, then pipe the rest).
//
// Enabled only when FILE_ENCRYPTION_KEY is set (32-byte key, hex or base64).
// Without it, files are stored as before — mirroring how AV_ENABLED gates the
// virus scanner. Rotating the key makes existing files unreadable, so treat it
// like any other production secret: set once, back it up, never lose it.
// ─────────────────────────────────────────────────────────────
const fs     = require('fs');
const crypto = require('crypto');

const ALGO    = 'aes-256-gcm';
const MAGIC   = Buffer.from('NXE1', 'utf8'); // Nexus Encrypted, v1
const IV_LEN  = 12;
const TAG_LEN = 16;
const HEADER  = MAGIC.length + IV_LEN; // bytes before the ciphertext

let _key; // parsed once, cached

// Parse FILE_ENCRYPTION_KEY into a 32-byte Buffer. Accepts 64 hex chars or
// base64. Throws on a malformed key so a misconfiguration fails loudly at boot
// rather than silently storing unreadable data.
function loadKey() {
  const raw = process.env.FILE_ENCRYPTION_KEY;
  if (!raw) return null;
  let key;
  if (/^[0-9a-f]{64}$/i.test(raw.trim())) {
    key = Buffer.from(raw.trim(), 'hex');
  } else {
    try { key = Buffer.from(raw.trim(), 'base64'); } catch { key = Buffer.alloc(0); }
  }
  if (key.length !== 32) {
    throw new Error('FILE_ENCRYPTION_KEY must decode to 32 bytes (64 hex chars or base64). ' +
      'Generate one with:  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }
  return key;
}

function getKey() {
  if (_key === undefined) _key = loadKey();
  if (!_key) throw new Error('File encryption requested but FILE_ENCRYPTION_KEY is not set');
  return _key;
}

function enabled() {
  if (_key === undefined) _key = loadKey();
  return !!_key;
}

// True if the file on disk is one of ours (encrypted). Cheap 4-byte read.
function isEncrypted(fp) {
  try {
    const fd  = fs.openSync(fp, 'r');
    const buf = Buffer.alloc(MAGIC.length);
    const n   = fs.readSync(fd, buf, 0, MAGIC.length, 0);
    fs.closeSync(fd);
    return n === MAGIC.length && buf.equals(MAGIC);
  } catch {
    return false;
  }
}

// Encrypt the file at `fp` in place (used right after upload). Streams through
// the cipher so a 100 MB upload never sits fully in memory.
function encryptFileInPlace(fp) {
  return new Promise((resolve, reject) => {
    const iv     = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
    const tmp    = `${fp}.enc.tmp`;
    const out    = fs.createWriteStream(tmp);
    const input  = fs.createReadStream(fp);

    const fail = err => { input.destroy(); out.destroy(); fs.unlink(tmp, () => reject(err)); };
    input.on('error', fail);
    cipher.on('error', fail);
    out.on('error', fail);

    out.write(Buffer.concat([MAGIC, iv]));   // header first
    input.pipe(cipher).pipe(out, { end: false });
    cipher.on('end', () => out.end(cipher.getAuthTag())); // append tag, then close
    out.on('finish', () => fs.rename(tmp, fp, err => (err ? reject(err) : resolve())));
  });
}

// Return a Readable that yields the decrypted plaintext, plus the plaintext
// byte length (GCM ciphertext is the same size as plaintext) so callers can set
// Content-Length. A tampered file surfaces as an 'error' on the stream.
function createDecryptStream(fp) {
  const size = fs.statSync(fp).size;
  const fd   = fs.openSync(fp, 'r');
  try {
    const head = Buffer.alloc(HEADER);
    fs.readSync(fd, head, 0, HEADER, 0);
    const tag = Buffer.alloc(TAG_LEN);
    fs.readSync(fd, tag, 0, TAG_LEN, size - TAG_LEN);
    const iv       = head.subarray(MAGIC.length, HEADER);
    const decipher = crypto.createDecipheriv(ALGO, getKey(), iv);
    decipher.setAuthTag(tag);
    const ciphertext = fs.createReadStream(fp, { start: HEADER, end: size - TAG_LEN - 1 });
    ciphertext.on('error', err => decipher.destroy(err));
    return { stream: ciphertext.pipe(decipher), plainSize: size - HEADER - TAG_LEN };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { enabled, isEncrypted, encryptFileInPlace, createDecryptStream, loadKey };

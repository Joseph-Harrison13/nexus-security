// ─────────────────────────────────────────────────────────────
// File storage abstraction.
//
// Two interchangeable drivers, selected by the STORAGE_DRIVER env var:
//   • 'disk' (default) — stores files on the local filesystem (uploads/).
//                        Exactly the original behaviour; nothing new to install.
//   • 's3'             — stores files in an AWS S3 bucket, encrypted at rest.
//                        Requires `npm i @aws-sdk/client-s3` and the S3_* env vars.
//
// Every route talks to `storage.driver.*` and never touches fs / the SDK
// directly, so switching to S3 is a config change, not a code change.
//
// In both drivers multer first writes the upload to the local `uploads/` dir;
// the magic-byte security check reads it there, then finalizeUpload() either
// leaves it in place (disk) or ships it to S3 and removes the local temp copy.
// ─────────────────────────────────────────────────────────────
const fs   = require('fs');
const path = require('path');
const logger = require('./logger');
const fileCrypto = require('./fileCrypto');

// UPLOADS_DIR is the local staging dir (and the store itself for the disk driver).
// Configurable so tests can use an isolated dir instead of the real uploads/.
const UPLOADS_DIR = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const DRIVER = (process.env.STORAGE_DRIVER || 'disk').toLowerCase();

function setHeaders(res, { contentType, disposition, filename }) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `${disposition}; filename="${encodeURIComponent(filename)}"`);
}

// ── Local disk driver ──────────────────────────────────────────
const diskDriver = {
  name: 'disk',

  // multer already wrote the file to UPLOADS_DIR; the stored key is its filename.
  // The AV scan + magic-byte check run on the plaintext BEFORE this, so we can
  // safely encrypt at rest here as the last step of the upload.
  async finalizeUpload(file) {
    if (fileCrypto.enabled()) await fileCrypto.encryptFileInPlace(file.path);
    return file.filename;
  },

  // Returns false if the object is missing so the route can reply 404.
  async sendFile(res, key, opts) {
    const fp = path.join(UPLOADS_DIR, key);
    if (!fs.existsSync(fp)) return false;
    setHeaders(res, opts);
    if (fileCrypto.isEncrypted(fp)) {
      // Decrypt on the fly. (Range requests aren't supported for encrypted
      // objects — GCM must verify the whole file — which is fine for downloads.)
      const { stream, plainSize } = fileCrypto.createDecryptStream(fp);
      res.setHeader('Content-Length', plainSize);
      stream.on('error', err => { logger.error({ err, key }, '[storage] decrypt failed'); res.destroy(err); });
      stream.pipe(res);
    } else {
      res.sendFile(path.resolve(fp)); // legacy plaintext object
    }
    return true;
  },

  async remove(key) {
    const fp = path.join(UPLOADS_DIR, key);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  },

  // Returns a Readable stream (for zip export), or null if missing.
  async openReadStream(key) {
    const fp = path.join(UPLOADS_DIR, key);
    if (!fs.existsSync(fp)) return null;
    return fileCrypto.isEncrypted(fp) ? fileCrypto.createDecryptStream(fp).stream : fs.createReadStream(fp);
  },
};

// ── AWS S3 driver (SDK loaded lazily — only when STORAGE_DRIVER=s3) ──
function makeS3Driver() {
  const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } =
    require('@aws-sdk/client-s3');

  const Bucket = process.env.S3_BUCKET;
  if (!Bucket) throw new Error('STORAGE_DRIVER=s3 but S3_BUCKET is not set');

  const client = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });

  // Prefer KMS (customer-managed key) if provided; otherwise S3-managed AES256.
  const encryption = process.env.S3_KMS_KEY_ID
    ? { ServerSideEncryption: 'aws:kms', SSEKMSKeyId: process.env.S3_KMS_KEY_ID }
    : { ServerSideEncryption: 'AES256' };

  const isMissing = err =>
    err && (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404);

  return {
    name: 's3',

    async finalizeUpload(file) {
      const Key = file.filename;
      await client.send(new PutObjectCommand({
        Bucket,
        Key,
        Body: fs.createReadStream(file.path),
        ContentType: file.mimetype,
        ...encryption,
      }));
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path); // drop local temp copy
      return Key;
    },

    async sendFile(res, key, opts) {
      let out;
      try {
        out = await client.send(new GetObjectCommand({ Bucket, Key: key }));
      } catch (err) {
        if (isMissing(err)) return false;
        throw err;
      }
      setHeaders(res, opts);
      out.Body.pipe(res);
      return true;
    },

    async remove(key) {
      await client.send(new DeleteObjectCommand({ Bucket, Key: key }));
    },

    async openReadStream(key) {
      try {
        const out = await client.send(new GetObjectCommand({ Bucket, Key: key }));
        return out.Body;
      } catch (err) {
        if (isMissing(err)) return null;
        throw err;
      }
    },
  };
}

const driver = DRIVER === 's3' ? makeS3Driver() : diskDriver;
if (driver.name === 'disk') {
  if (fileCrypto.enabled()) {
    logger.info('[storage] driver: disk (AES-256-GCM encryption at rest: ON)');
  } else {
    logger.info('[storage] driver: disk (encryption at rest: OFF — set FILE_ENCRYPTION_KEY to enable)');
    if (process.env.NODE_ENV === 'production') {
      logger.warn('[storage] Files are stored UNENCRYPTED. Set FILE_ENCRYPTION_KEY or use an encrypted volume/S3.');
    }
  }
} else {
  logger.info(`[storage] driver: ${driver.name}`);
}

module.exports = { driver, UPLOADS_DIR, DRIVER };

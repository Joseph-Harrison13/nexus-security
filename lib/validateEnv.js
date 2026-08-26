const DEFAULT_JWT = 'change-this-to-a-long-random-string-before-going-live';

const REQUIRED = [
  { key: 'JWT_SECRET', fatal: true },
];

const OPTIONAL_WARN = [
  { key: 'EMAIL_USER',  message: 'Email alerts and contact form emails will only log to console' },
  { key: 'EMAIL_PASS',  message: 'Email alerts and contact form emails will only log to console' },
];

function validateEnv() {
  const errors   = [];
  const warnings = [];
  const isProd   = process.env.NODE_ENV === 'production';

  // Check required vars
  REQUIRED.forEach(({ key }) => {
    if (!process.env[key]) {
      errors.push(`Missing required env var: ${key}`);
    }
  });

  // Warn about insecure defaults in production, always warn for JWT_SECRET default
  if (process.env.JWT_SECRET === DEFAULT_JWT) {
    if (isProd) {
      errors.push('JWT_SECRET is still using the placeholder default — this is insecure in production');
    } else {
      warnings.push('JWT_SECRET is using the default placeholder — change it before going live');
    }
  }

  // A JWT is only as strong as its signing key: a short secret can be brute-forced
  // offline, letting an attacker forge tokens for any user (including an admin).
  const secret = process.env.JWT_SECRET || '';
  if (secret && secret !== DEFAULT_JWT && secret.length < 32) {
    if (isProd) {
      errors.push('JWT_SECRET is too short — use at least 32 random characters in production');
    } else {
      warnings.push('JWT_SECRET is shorter than 32 characters — use a longer random value before going live');
    }
  }

  if (!process.env.JWT_REFRESH_SECRET) {
    warnings.push('JWT_REFRESH_SECRET not set — set it before going live');
  }

  // Files stored on the local disk are only encrypted at rest when this is set.
  if (isProd && (process.env.STORAGE_DRIVER || 'disk') === 'disk' && !process.env.FILE_ENCRYPTION_KEY) {
    warnings.push('FILE_ENCRYPTION_KEY not set — uploaded files will be stored UNENCRYPTED on disk');
  }

  // Warn about optional but recommended vars
  const missingEmail = OPTIONAL_WARN.filter(({ key }) => !process.env[key] || process.env[key] === 'your@email.com');
  if (missingEmail.length) {
    warnings.push('Email credentials not configured — ' + missingEmail[0].message);
  }

  // Print and handle
  warnings.forEach(w => console.warn(`[startup] WARN  ${w}`));
  errors.forEach(e   => console.error(`[startup] ERROR ${e}`));

  if (errors.length > 0) {
    console.error(`[startup] ${errors.length} fatal error(s) — server cannot start safely`);
    process.exit(1);
  }

  console.log('[startup] Environment validated ✓');
}

module.exports = validateEnv;

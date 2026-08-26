// Validate environment variables before anything else
require('dotenv').config();
const validateEnv = require('./lib/validateEnv');
validateEnv();

// Initialize Sentry as early as possible — no-op unless SENTRY_DSN is set.
const Sentry = require('@sentry/node');
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: 0, // errors only; raise to enable performance tracing
  });
}

const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const helmet       = require('helmet');
const cors         = require('cors');
const compression  = require('compression');
const cookieParser = require('cookie-parser');
const pinoHttp     = require('pino-http');
const rateLimit    = require('express-rate-limit');
const { computeScriptHashes } = require('./lib/cspScriptHashes');

const logger             = require('./lib/logger');

const db                 = require('./db/database');
const authRoutes         = require('./routes/auth');
const usersRoutes        = require('./routes/users');
const filesRoutes        = require('./routes/files');
const foldersRoutes      = require('./routes/folders');
const sharesRoutes       = require('./routes/shares');
const dashboardRoutes    = require('./routes/dashboard');
const contactRoutes      = require('./routes/contact');
const sessionsRoutes     = require('./routes/sessions');
const notificationsRoutes= require('./routes/notifications');
const newsletterRoutes   = require('./routes/newsletter');
const verifyEmailRoutes  = require('./routes/verify-email');
const stripeRoutes       = require('./routes/stripe');
const { scheduleBackups } = require('./lib/backup');
const { scheduleCleanup } = require('./lib/cleanup');

const app    = express();
const PORT   = parseInt(process.env.PORT || '3000', 10);
const isProd = process.env.NODE_ENV === 'production';

// ── Proxy awareness ────────────────────────────────────────
// Behind an AWS load balancer / CloudFront, TLS terminates at the edge and the
// real client IP arrives in X-Forwarded-For. Set TRUST_PROXY (e.g. =1 for a
// single LB hop) so req.ip, secure cookies and rate limiting use the real IP.
// Left off by default so a local/dev server can't be tricked via a spoofed header.
if (process.env.TRUST_PROXY) {
  const tp = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(tp) ? parseInt(tp, 10) : tp);
}

// ── Request logging ────────────────────────────────────────
// Structured per-request logs (with a request id) via pino-http. Silent under test.
if (process.env.NODE_ENV !== 'test') {
  app.use(pinoHttp({ logger }));
}

// ── Security headers ───────────────────────────────────────
// sha256 allowlist for our own inline <script> blocks (computed from the static
// HTML at startup). Present in script-src so modern browsers enforce the hash
// list and reject any inline <script> that isn't ours — even if one slips past
// output escaping. 'unsafe-inline' stays only as a pre-CSP2 fallback (ignored by
// current browsers whenever a hash is present).
const INLINE_SCRIPT_HASHES = computeScriptHashes(path.join(__dirname, 'public'));

app.use(helmet({
  // HSTS only in production (behind TLS); leaving it off in dev avoids pinning
  // http://localhost to HTTPS in your browser.
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      // Inline <script> blocks are pinned by sha256 hash (INLINE_SCRIPT_HASHES),
      // so modern browsers block any injected <script> while our own run. The
      // 'unsafe-inline' token is a legacy fallback that current browsers ignore
      // once a hash is present. Inline onclick handlers (~445 across the static
      // pages) are still allowed via script-src-attr; an injected handler can
      // only fire on unescaped data, which the escapeHtml render layer prevents.
      scriptSrc:   ["'self'", "'unsafe-inline'", ...INLINE_SCRIPT_HASHES],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      objectSrc:      ["'none'"],   // block <object>/<embed> plugin-based XSS
      baseUri:        ["'self'"],   // block <base> tag hijacking
      frameAncestors: ["'none'"],   // clickjacking protection
      formAction:     ["'self'"],   // forms can only submit to same origin
      upgradeInsecureRequests: isProd ? [] : null,
    },
  },
}));

// Permissions-Policy: explicitly deny powerful features the app never uses, so a
// compromised/injected script can't silently reach for the camera, mic, etc.
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), usb=(), interest-cohort=()');
  next();
});

// ── Compression ────────────────────────────────────────────
app.use(compression());

// ── CORS ───────────────────────────────────────────────────
// Allow the configured public origin (prod) plus localhost (dev).
const corsOrigins = [process.env.SITE_URL, `http://localhost:${PORT}`].filter(Boolean);
app.use(cors({
  origin:      corsOrigins,
  credentials: true,
}));

// ── Rate limiting (defined early so it can also guard the Stripe routes) ─
// Disabled under test so a fast-running suite isn't throttled; fully active otherwise.
const skipInTest = () => process.env.NODE_ENV === 'test';
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Too many attempts — try again in 15 minutes', code: 'RATE_LIMITED' },
  standardHeaders: true, legacyHeaders: false, skip: skipInTest,
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 120,
  message: { error: 'Rate limit exceeded', code: 'RATE_LIMITED' },
  standardHeaders: true, legacyHeaders: false, skip: skipInTest,
});

// ── Stripe — mounted before express.json() (webhook needs the raw body) ─
// Rate-limit the interactive endpoints but exempt the webhook: Stripe legitimately
// bursts/retries events and authenticates via its signature, not our limiter.
app.use('/api/stripe', (req, res, next) =>
  req.path.endsWith('/webhook') ? next() : apiLimiter(req, res, next));
app.use('/api/stripe', stripeRoutes);

// ── Body parsing ───────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ── Rate limiting (apply to the remaining API routes) ──────
app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);

// Maintenance mode — when an admin flips it on, the API is walled off (503) for
// everyone but admins + the login endpoints. Runs after cookieParser so it can
// read the admin's token.
app.use('/api', require('./middleware/maintenance'));

// ── API routes ─────────────────────────────────────────────
app.use('/api/auth',          authRoutes);
app.use('/api/auth',          verifyEmailRoutes);
app.use('/api/users',         usersRoutes);
app.use('/api/files',         filesRoutes);
app.use('/api/folders',       foldersRoutes);
app.use('/api/share',         sharesRoutes);
app.use('/api/dashboard',     dashboardRoutes);
app.use('/api/contact',       contactRoutes);
app.use('/api/sessions',      sessionsRoutes);
app.use('/api/notifications', notificationsRoutes);
app.use('/api/newsletter',    newsletterRoutes);

// ── Deep health check ──────────────────────────────────────
app.get('/api/health', (req, res) => {
  const start = Date.now();
  let dbStatus = 'ok';
  let dbLatencyMs = 0;

  try {
    const t = Date.now();
    db.prepare('SELECT 1').get();
    dbLatencyMs = Date.now() - t;
  } catch {
    dbStatus = 'error';
  }

  // Disk space — check uploads and db directories
  let diskOk = true;
  try {
    const stat = fs.statfsSync ? fs.statfsSync(__dirname) : null;
    if (stat) {
      const freeGB = (stat.bfree * stat.bsize) / (1024 ** 3);
      if (freeGB < 0.5) diskOk = false; // warn if under 500 MB free
    }
  } catch { /* statfsSync not available on all platforms */ }

  const status = dbStatus === 'ok' ? 'ok' : 'degraded';

  res.status(dbStatus === 'ok' ? 200 : 503).json({
    status,
    uptime:      `${Math.floor(process.uptime())}s`,
    database:    dbStatus,
    dbLatencyMs,
    disk:        diskOk ? 'ok' : 'low',
    https:       true,
    responseMs:  Date.now() - start,
    timestamp:   new Date().toISOString(),
    version:     process.env.npm_package_version || '1.0.0',
  });
});

// ── Error reporting (Sentry captures errors here, then passes them on) ─
if (process.env.SENTRY_DSN) Sentry.setupExpressErrorHandler(app);

// ── Global error handler ───────────────────────────────────
app.use((err, req, res, _next) => {
  // Client errors (bad upload, malformed/oversized body) — answer cleanly, don't
  // log them as server faults or leak internals.
  if (err.code === 'LIMIT_FILE_SIZE')  return res.status(413).json({ error: 'File too large (max 100 MB)',  code: 'FILE_TOO_LARGE' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large', code: 'PAYLOAD_TOO_LARGE' });
  if (err.type === 'entity.parse.failed' || (err.status === 400 && 'body' in err)) {
    return res.status(400).json({ error: 'Invalid JSON in request body', code: 'INVALID_JSON' });
  }
  if (err.message?.startsWith('File type')) return res.status(400).json({ error: err.message, code: 'INVALID_FILE_TYPE' });
  // Anything else is a genuine server fault — log it, return a generic message.
  (req.log || logger).error({ err }, 'unhandled request error');
  res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
});

// ── Static files (after API routes) ───────────────────────
// Serve /.well-known explicitly — express.static ignores dotfile dirs by default,
// which would 404 security.txt. Scoped so no other dotfiles are ever exposed.
app.use('/.well-known', express.static(path.join(__dirname, 'public', '.well-known'), { dotfiles: 'allow' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((_req, res) => res.status(404).sendFile(path.join(__dirname, 'public', '404.html')));

// ── Start server (HTTP) ────────────────────────────────────
// To enable HTTPS once you have a real cert, replace this block with:
//
//   const httpsServer = https.createServer(
//     { cert: fs.readFileSync(path.join(__dirname,'certs','cert.pem')),
//       key:  fs.readFileSync(path.join(__dirname,'certs','key.pem')) },
//     app
//   );
//   httpsServer.listen(HTTPS_PORT, () => console.log(`HTTPS  https://yourdomain.com`));
//   http.createServer((_req, res) => {
//     res.writeHead(301, { Location: `https://yourdomain.com${_req.url}` });
//     res.end();
//   }).listen(PORT);
//   Also set hsts: { maxAge: 31536000, includeSubDomains: true } in the Helmet config above.

// Only bind the port and start background jobs when run directly (node server.js).
// When imported (e.g. by the test suite via supertest) we just export the app.
if (require.main === module) {
  const httpServer = app.listen(PORT, () => {
    logger.info(`HTTP server listening on http://localhost:${PORT}`);
  });

  // ── Schedule daily database backups + token/session cleanup ─
  scheduleBackups();
  scheduleCleanup();

  // ── Graceful shutdown ──────────────────────────────────────
  const shutdown = (signal) => {
    logger.info(`${signal} received — closing gracefully...`);

    // Give in-flight requests up to 10 seconds to finish
    const timer = setTimeout(() => {
      logger.error('Shutdown timeout — forcing exit');
      process.exit(1);
    }, 10_000);
    timer.unref(); // don't let timer prevent exit if everything closes cleanly

    httpServer.close(() => {
      try { db.close(); } catch { /* ignore */ }
      logger.info('Clean exit');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException',  (err) => { logger.fatal({ err }, 'uncaught exception'); shutdown('uncaughtException'); });
  process.on('unhandledRejection', (err) => { logger.error({ err }, 'unhandled rejection'); });
}

module.exports = app;

const pino = require('pino');

const isTest = process.env.NODE_ENV === 'test';
const isProd = process.env.NODE_ENV === 'production';

// JSON to stdout in production (CloudWatch-friendly), pretty-printed in dev,
// silent under test. Secrets are redacted from request logs.
const logger = pino({
  level: process.env.LOG_LEVEL || (isTest ? 'silent' : 'info'),
  redact: {
    paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
    remove: true,
  },
  transport:
    !isProd && !isTest
      ? { target: 'pino-pretty', options: { translateTime: 'SYS:standard', ignore: 'pid,hostname' } }
      : undefined,
});

module.exports = logger;

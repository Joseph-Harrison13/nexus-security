# Security Policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub's private vulnerability reporting](https://github.com/Joseph-Harrison13/nexus-security/security/advisories/new)
rather than opening a public issue.

I'll acknowledge within a few days. This is a personal project, not a funded programme — there
is no bounty, but credit is given for anything valid.

## Scope

This repository is a portfolio project. **There is no production deployment to test against**,
so please don't scan or attack any host — run it locally instead.

In scope: anything in this repository. Particularly welcome are findings in the tenant
isolation primitives (`lib/scope.js`), upload handling (`routes/files.js`), the encryption at
rest (`lib/fileCrypto.js`), and authentication and session handling (`routes/auth.js`,
`middleware/auth.js`).

Out of scope: missing hardening on a local dev configuration that the README already documents
as a known gap, and anything requiring a compromised developer machine.

## Running it safely

- **`JWT_SECRET` is required** and the app refuses to boot without it. In production it also
  refuses to start on the placeholder value or on a secret shorter than 32 characters — see
  `lib/validateEnv.js`.
- **Set `FILE_ENCRYPTION_KEY`** or uploaded files are stored unencrypted on disk. Back the key
  up: losing it makes existing files unreadable.
- **Never set `FORCE_HTTP` in production.** It exists so local development can run without
  certificates.
- `DEMO_2FA_CODE` is a development convenience and is ignored when `NODE_ENV=production`.

## Known gaps

These are documented rather than hidden; see the *Known gaps* section of the
[README](README.md). The notable ones are no local TLS, `scriptSrcAttr: 'unsafe-inline'` still
being required by legacy inline handlers in the dashboard pages, and single-node assumptions
(in-process rate limiting, local SQLite file).

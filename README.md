# Nexus Security

[![CI](https://github.com/Joseph-Harrison13/nexus-security/actions/workflows/ci.yml/badge.svg)](https://github.com/Joseph-Harrison13/nexus-security/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-100%20passing-2ea44f)](test)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Multi-tenant encrypted file storage.** Organisations store files under per-tenant isolation,
mandatory TOTP two-factor, AES-256-GCM encryption at rest, malware scanning on upload, and an
admin console with an audit trail.

Node + Express 5 + SQLite. 100 tests, ESLint clean, zero high-severity advisories.

```bash
cp .env.example .env    # JWT_SECRET is required — openssl rand -hex 48
npm install
npm start               # http://localhost:3001
npm test                # 100 tests across 20 files
npm run lint
```

---

## Why this repo is worth a look

I built the product, then went looking for holes in it — the same way someone would if it
were live. **This section is the interesting part of the repository**: five real
vulnerabilities I found in my own code and fixed, and what each one actually taught me.

### 1. Broken access control — account takeover between colleagues (High)

`canManageUser` in [`lib/scope.js`](lib/scope.js) decides whether a caller may manage another
user's row. It checked that the target was in the caller's organisation, but not what *role*
the caller held. Any ordinary `User` could therefore manage a peer in the same org — including
overwriting their password. That is full account takeover by a colleague.

```js
if (req.user.role === 'Admin' && target.org_id != null && target.org_id === req.user.org_id)
  return true;
```

The fix was one added role check, which is exactly the point. **The lesson that keeps
repeating: most real bugs are a single inconsistency — a safety habit followed everywhere but
one place.** The sibling function `canAccessRow` had always checked role correctly; this one
didn't, so the two disagreed and only one of them was wrong.

### 2. SSRF via an unvalidated push endpoint (High)

A Web Push subscription contains a URL *the server will later POST to*. Accepting it
unvalidated lets any user aim the server at internal infrastructure — cloud metadata at
`169.254.169.254`, an internal admin panel, anything the server can reach but the attacker
can't.

The fix in [`routes/notifications.js`](routes/notifications.js) is an **allowlist of known push
providers**, not a blocklist of private IP ranges. That choice matters: blocklisting private
ranges loses to DNS rebinding, decimal/octal IP encodings, and redirects. An allowlist doesn't
have to win that arms race.

### 3. Stored XSS in the admin contact-leads view (High)

A `data-search` attribute was built from unescaped submitted text. The victim was the
SuperAdmin — the one account that can reach every organisation — and the payload arrived
through a public form anyone on the internet could fill in. Unauthenticated input, highest-
privilege target.

### 4. HTML injection in the contact notification email (Low)

The same submission was interpolated into an HTML email. `escHtml` in
[`routes/contact.js`](routes/contact.js) now escapes it **server-side**, before it reaches a
mail client that will happily render whatever it's given.

### 5. Four dependency CVEs

Found with `npm audit`, resolved with `npm audit fix`. `npm audit --omit=dev --audit-level=high`
now runs in CI on every push, so this can't quietly rot.

### And one thing that was already right

CSV export ([`lib/csv.js`](lib/csv.js)) correctly defangs formula injection — a cell beginning
`=`, `+`, `-`, `@`, tab or CR is quote-prefixed before export. A user's own name is
attacker-controlled text as far as Excel is concerned, and Excel will execute it. Worth
recording that auditing something and finding it clean is also a result.

---

## Security architecture

**Tenant isolation is a primitive, not a habit.** [`lib/scope.js`](lib/scope.js) exposes
`canAccessRow`, `listScope` and `canManageUser`, and routes are written against them rather
than hand-rolling `WHERE org_id = ?` per query. `listScope` returns a SQL fragment plus params,
so a listing endpoint physically cannot forget to scope itself. `test/tenancy.test.js` asserts
the boundary from the outside.

**Two-factor is mandatory, not optional.** An account that hasn't enrolled an authenticator
app is blocked from data routes entirely — `test/adminTwoFactor.test.js` pins that. Optional
2FA protects the people who were already going to be careful.

**Files are encrypted at rest** with AES-256-GCM ([`lib/fileCrypto.js`](lib/fileCrypto.js)),
carrying a magic header so an encrypted file is identifiable and versionable. The env var that
enables it is documented with a warning that losing the key makes existing files unreadable —
because that is the failure mode people discover too late.

**Uploads are treated as hostile.** Magic-byte type detection rather than trusting the
extension, optional ClamAV scanning, and a filename sanitiser that strips control characters
and path components before the name is stored — because that value later reaches the database,
the logs, and a `Content-Disposition` header.

**The session token is never readable by JavaScript.** The access token lives in an httpOnly,
`sameSite=strict`, `secure`-in-production cookie, so even a successful XSS cannot exfiltrate a
session — and `sameSite=strict` is the CSRF control that pairs with it. The refresh token gets
its own cookie scoped to `path=/api/auth`, so it is not sent on ordinary API calls at all. A
`Bearer` header is accepted as a fallback for the test suite and non-browser clients.

**Other controls:** bcrypt at cost 12, Helmet with a CSP built from computed inline-script
hashes ([`lib/cspScriptHashes.js`](lib/cspScriptHashes.js)), rate limiting split between auth
and general API routes, Zod schemas at the boundary, session revocation, and breach-checking on
password set via HIBP's range API using **k-anonymity** — only the first five characters of the
SHA-1 hash leave the server, so the password itself is never disclosed to the lookup.

---

## Layout

```
server.js          Express 5 app: helmet, CORS, rate limits, route mounting
db/                SQLite schema + migrations (better-sqlite3)
lib/
  scope.js         tenant isolation primitives — the security core
  fileCrypto.js    AES-256-GCM at rest
  antivirus.js     ClamAV integration
  csv.js           formula-injection-safe export
  validateEnv.js   refuses to boot on an insecure config
  breachCheck.js   k-anonymity password breach lookup
routes/            auth, users, files, folders, shares, sessions, stripe, …
middleware/        auth guard, maintenance mode, request scoping
public/            marketing site + dashboard (vanilla JS, no build step)
test/              20 files, 100 tests (vitest + supertest)
```

`AWS-DEPLOYMENT.md` covers deploying behind CloudFront with secrets in SSM Parameter Store.

---

## Testing

```
npm test        # 100 tests, 20 files
npm run lint    # eslint, clean
npm run audit   # npm audit --omit=dev
```

Tests cover the security boundaries specifically: cross-tenant access, mandatory 2FA
enrolment, upload restrictions, file encryption round-trips, share-link scoping, trash
restore permissions, account suspension, and seat limits. CI runs lint, tests and the audit on
Node 20 and 22.

---

## Known gaps

- **No HTTPS locally** — certs were removed; `server.js` has the HTTPS block ready to
  uncomment, and HSTS is disabled until it's live behind TLS.
- **`scriptSrcAttr: 'unsafe-inline'`** is still required by inline `onclick` handlers in the
  older dashboard pages. Those handlers should move to listeners so the directive can go.
- Single-node only: rate limiting is in-process and SQLite is a local file.

---

## Contributing

```bash
npm install
npm run setup     # enables the pre-push hook (lint + tests before every push)
```

## Licence

MIT — see [LICENSE](LICENSE).

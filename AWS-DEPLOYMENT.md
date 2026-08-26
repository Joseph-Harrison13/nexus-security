# AWS Deployment Runbook — Nexus Security

A step-by-step guide to running this app on AWS. The recommended shape for the
current stage is **one small instance + S3 + SES + edge TLS** — simple, cheap,
encrypted, and it leaves a clean path to scale later.

```
            ┌──────────────┐      ┌──────────────────────────┐
  users ──▶ │ CloudFront   │ ───▶ │ EC2 / Lightsail (Node)   │
            │  + ACM TLS   │      │  • app.js (HTTP, :3000)  │
            │  + AWS WAF   │      │  • SQLite on EBS volume  │
            └──────────────┘      │  • TRUST_PROXY=1         │
                                   └─────────┬────────────────┘
                                             │
                        ┌────────────────────┼─────────────────────┐
                        ▼                    ▼                      ▼
                  ┌───────────┐       ┌────────────┐        ┌──────────────┐
                  │ S3 (files)│       │ SES (email)│        │ SSM (secrets)│
                  │  SSE-KMS  │       │  SMTP      │        │  SecureString│
                  └───────────┘       └────────────┘        └──────────────┘
```

> **Why keep SQLite for now?** It lives on the instance's EBS volume and needs
> persistent local disk, so it works on EC2/Lightsail but **not** on Fargate or
> Lambda (no persistent local FS). Don't migrate to RDS until you actually need a
> second app instance — that's a large async rewrite. Files go to S3 today anyway,
> so the only thing tying you to one box is the database.

---

## 0. Prerequisites

- An AWS account + the AWS CLI configured (`aws configure`).
- A registered domain (Route 53 or elsewhere) for TLS + SES.
- Node.js 18+ on the instance.

---

## 1. Cloud storage — S3 (this is the "cloud storage" piece)

The app already supports S3 via a driver switch (`lib/storage.js`); no code
changes are needed, just config.

**1.1 Create a private, encrypted bucket**
```bash
aws s3api create-bucket --bucket nexus-sec-files-PROD --region us-east-1
aws s3api put-public-access-block --bucket nexus-sec-files-PROD \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# default encryption (SSE-S3). For customer-managed KMS, see 1.2
aws s3api put-bucket-encryption --bucket nexus-sec-files-PROD \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

**1.2 (Optional, stronger) Customer-managed KMS key**
```bash
aws kms create-key --description "Nexus Security file encryption"
# note the KeyId → set S3_KMS_KEY_ID below; the app will use aws:kms automatically
```

**1.3 IAM** — give the instance role (or an IAM user) least-privilege access:
`s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on `arn:aws:s3:::nexus-sec-files-PROD/*`
(plus `kms:Encrypt`/`kms:Decrypt`/`kms:GenerateDataKey` on the key if using 1.2).
Prefer an **instance profile (IAM role)** over static keys.

**1.4 Install the SDK and flip the switch**
```bash
npm i @aws-sdk/client-s3
```
```ini
STORAGE_DRIVER=s3
S3_BUCKET=nexus-sec-files-PROD
AWS_REGION=us-east-1
# S3_KMS_KEY_ID=<key-id>        # only if using 1.2
```
Restart the app — you'll see `[storage] driver: s3` on boot. Default (`disk`)
behaviour is unchanged when `STORAGE_DRIVER` is unset, so nothing breaks before
you're ready.

**1.5 Migrate existing local files** (if any have already been uploaded)
```bash
aws s3 sync ./uploads s3://nexus-sec-files-PROD/
```
(The DB's `disk_path` values are the object keys — they match the local filenames.)

---

## 2. Email — SES

SES exposes SMTP, so this is purely a credentials swap (no code change —
`lib/mailer.js` already reads these env vars).

1. Verify your domain (or a single sender) in SES, add the DKIM/SPF DNS records.
2. Request production access (moves you out of the SES sandbox).
3. Create SMTP credentials in the SES console.
4. Set:
```ini
EMAIL_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_PORT=587
EMAIL_USER=<ses-smtp-username>
EMAIL_PASS=<ses-smtp-password>
EMAIL_FROM="Nexus Security <noreply@yourdomain.com>"
EMAIL_TO=alerts@yourdomain.com
```

---

## 3. Secrets — SSM Parameter Store

Keep secrets out of the `.env` file on disk. Store them as encrypted
SecureString parameters and load them into the environment at boot.

```bash
aws ssm put-parameter --name /nexus/prod/JWT_SECRET --type SecureString --value "$(openssl rand -hex 48)"
aws ssm put-parameter --name /nexus/prod/STRIPE_SECRET_KEY --type SecureString --value "sk_live_..."
aws ssm put-parameter --name /nexus/prod/STRIPE_WEBHOOK_SECRET --type SecureString --value "whsec_..."
aws ssm put-parameter --name /nexus/prod/EMAIL_PASS --type SecureString --value "..."
```
Grant the instance role `ssm:GetParametersByPath` on `/nexus/prod/*` (+ `kms:Decrypt`).
Fetch them in your start script, e.g.:
```bash
eval "$(aws ssm get-parameters-by-path --path /nexus/prod --with-decryption \
  --query 'Parameters[].[Name,Value]' --output text \
  | sed -E 's#/nexus/prod/([A-Z_]+)\t(.*)#export \1="\2"#')"
node server.js
```

---

## 4. Compute — EC2 / Lightsail

1. Launch a small instance (e.g. Lightsail $10 plan, or EC2 `t3.small`) with an
   **EBS/SSD volume** — SQLite (`db/app.db`) and the local upload temp dir live here.
2. Install Node, clone the app, `npm ci`.
3. Run under a process manager so it restarts on crash/reboot:
```bash
# systemd unit (recommended) or:
npm i -g pm2 && pm2 start server.js --name nexus && pm2 save && pm2 startup
```
4. Required production env:
```ini
NODE_ENV=production
PORT=3000
TRUST_PROXY=1          # REQUIRED behind CloudFront/ALB — fixes req.ip, secure cookies, rate limiting
SITE_URL=https://yourdomain.com
```
> The app listens on plain HTTP; TLS terminates at the edge (step 5). Graceful
> shutdown on SIGTERM is already handled, and `/api/health` is ready for health checks.

---

## 5. TLS & edge — CloudFront + ACM (+ optional WAF)

1. Request a free **ACM certificate** for `yourdomain.com` (in `us-east-1` for CloudFront).
2. Create a **CloudFront distribution** with your instance (or its ALB) as origin,
   viewer protocol policy **redirect-HTTP-to-HTTPS**, and forward `Host`, cookies,
   and query strings to the origin.
3. Point Route 53 `A`/`ALIAS` at the distribution.
4. Confirm `TRUST_PROXY=1` is set (step 4) so the real client IP survives.

**Optional but recommended — AWS WAF** on the distribution:
- Attach the **AWS Managed Rules** (Common + Known Bad Inputs).
- Add a **rate-based rule** as a first line of defense in front of the app's own limiter.

---

## 6. Backups → S3

`lib/backup.js` already writes a consistent SQLite snapshot daily (via the online
backup API). Push those snapshots off-box:
```bash
# add to the cron/systemd timer after the local backup runs:
aws s3 sync ./backups s3://nexus-sec-backups-PROD/ --storage-class STANDARD_IA
```
Enable **versioning** + a **lifecycle rule** (e.g. expire after 30–90 days) on the
backup bucket. (Consider widening backups beyond the 7-file local cap once they're in S3.)

---

## 7. Monitoring

- **CloudWatch Logs**: run the app so logs go to stdout (containerized) or install
  the CloudWatch agent to ship `logs/access.log`. Alarm on `/api/health` returning non-200.
- **GuardDuty**: enable account-wide — cheap, set-and-forget threat detection.
- **CloudTrail**: enable a multi-region trail for an audit log of all AWS API activity.

---

## 8. Environment variable reference

| Variable | Used by | Notes |
|---|---|---|
| `NODE_ENV` | everywhere | set to `production` |
| `PORT` | server.js | app listen port (default 3000) |
| `TRUST_PROXY` | server.js | **set to `1`** behind CloudFront/ALB |
| `SITE_URL` | emails, stripe | public https URL, e.g. `https://yourdomain.com` |
| `JWT_SECRET` | auth | long random string (from SSM) |
| `JWT_EXPIRES_IN` / `JWT_2FA_EXPIRES_IN` | auth | optional, default `1h` / `5m` |
| `STORAGE_DRIVER` | storage | `disk` (default) or `s3` |
| `S3_BUCKET` / `AWS_REGION` | storage | required when `STORAGE_DRIVER=s3` |
| `S3_KMS_KEY_ID` | storage | optional; enables SSE-KMS instead of AES256 |
| `EMAIL_HOST` / `EMAIL_PORT` / `EMAIL_USER` / `EMAIL_PASS` | mailer | SES SMTP |
| `EMAIL_FROM` / `EMAIL_TO` | mailer/alerts | sender + alert recipient |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | stripe | from SSM |
| `STRIPE_PRICE_STARTER` / `_GROWTH` / `_PRO` | stripe | Stripe price IDs |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` | notifications | web-push (optional) |

> `DEMO_2FA_CODE` is intentionally **dev-only** now and is ignored in production —
> production logins use TOTP (if enabled) or password-only, never a static code.

---

## What to revisit when you outgrow one instance

- **RDS (Postgres)** instead of SQLite — needed before running 2+ app instances.
  This is a sizeable change: the data layer is synchronous raw SQL today.
- **ElastiCache (Redis)** for the rate-limiter store and the 2FA attempt counter
  (both are in-process today and won't be consistent across instances).
- **ECS/Fargate** behind an ALB for horizontal scaling once the above are in place.

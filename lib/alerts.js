const { sendMail } = require('./mailer');
const { smsUser } = require('./sms');

const ADMIN_EMAIL = () => process.env.EMAIL_TO || process.env.EMAIL_USER;

async function alertNewIPLogin(user, ip, userAgent) {
  // Best-effort SMS alongside the email (no-op unless SMS is configured + opted in).
  smsUser(user, `Nexus Security: new sign-in to your account from IP ${ip}. If this wasn't you, change your password now.`).catch(() => {});
  await sendMail({
    to: user.email,
    subject: '[Nexus Security] New login from an unfamiliar location',
    text: `Hi ${user.name},\n\nWe noticed a login to your account from a new IP address.\n\nIP Address: ${ip}\nBrowser: ${userAgent || 'Unknown'}\nTime: ${new Date().toUTCString()}\n\nIf this was you, no action is needed.\nIf this wasn't you, please contact us immediately and change your password.\n\n— Nexus Security Team`,
    html: `<h2>New Login Detected</h2><p>Hi ${user.name},</p><p>A login to your account was detected from a new location:</p><ul><li><strong>IP:</strong> ${ip}</li><li><strong>Browser:</strong> ${userAgent || 'Unknown'}</li><li><strong>Time:</strong> ${new Date().toUTCString()}</li></ul><p>If this wasn't you, <strong>change your password immediately</strong> and contact us.</p>`,
  });
}

async function alertNewLocationCode(user, code, ip) {
  await sendMail({
    to: user.email,
    subject: '[Nexus Security] Your sign-in verification code',
    text: `Hi ${user.name},\n\nWe noticed a sign-in attempt from a new location (IP ${ip}).\n\nYour verification code is: ${code}\n\nEnter it to finish signing in. This code expires in 10 minutes.\n\nIf this wasn't you, do NOT share this code — and change your password right away.\n\n— Nexus Security Team`,
    html: `<h2>Verify your sign-in</h2><p>Hi ${user.name},</p><p>We noticed a sign-in attempt from a new location (IP <strong>${ip}</strong>).</p><p>Your verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:6px;font-family:monospace">${code}</p><p>Enter it to finish signing in. This code expires in 10 minutes.</p><p>If this wasn't you, <strong>do not share this code</strong> and change your password right away.</p>`,
  });
}

async function alertAccountLocked(user, ip) {
  // Notify the account owner
  await sendMail({
    to: user.email,
    subject: '[Nexus Security] Your account has been locked',
    text: `Hi ${user.name},\n\nYour account was locked after 5 failed login attempts.\nIP: ${ip}\nTime: ${new Date().toUTCString()}\n\nIt will automatically unlock in 30 minutes. If this wasn't you, contact us immediately.`,
    html: `<h2>Account Locked</h2><p>Hi ${user.name},</p><p>Your account was locked after <strong>5 failed login attempts</strong>.</p><ul><li><strong>IP:</strong> ${ip}</li><li><strong>Time:</strong> ${new Date().toUTCString()}</li></ul><p>It will automatically unlock in 30 minutes. If this wasn't you, contact support immediately.</p>`,
  });

  // Notify admin too
  await sendMail({
    to: ADMIN_EMAIL(),
    subject: `[Alert] Account locked: ${user.email}`,
    text: `Account locked due to repeated failed logins.\nUser: ${user.email}\nIP: ${ip}\nTime: ${new Date().toUTCString()}`,
    html: `<h2>Account Lockout Alert</h2><p><strong>${user.email}</strong> was locked after 5 failed attempts from IP <strong>${ip}</strong>.</p>`,
  });
}

async function alertPasswordResetRequested(user, resetLink) {
  await sendMail({
    to: user.email,
    subject: '[Nexus Security] Password Reset Request',
    text: `Hi ${user.name},\n\nA password reset was requested for your account.\n\nClick the link below to reset your password (expires in 15 minutes):\n${resetLink}\n\nIf you did not request this, you can safely ignore this email.`,
    html: `<h2>Password Reset Request</h2><p>Hi ${user.name},</p><p>Click the button below to reset your password. This link expires in <strong>15 minutes</strong>.</p><p><a href="${resetLink}" style="background:#3B82F6;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Reset Password</a></p><p>If you didn't request this, ignore this email.</p>`,
  });
}

async function alertSuspiciousActivity(user, action, detail, ip) {
  await sendMail({
    to: ADMIN_EMAIL(),
    subject: `[Alert] Suspicious activity: ${action} by ${user.email}`,
    text: `Suspicious activity detected.\nUser: ${user.email}\nAction: ${action}\nDetail: ${detail}\nIP: ${ip}\nTime: ${new Date().toUTCString()}`,
    html: `<h2>Suspicious Activity Alert</h2><ul><li><strong>User:</strong> ${user.email}</li><li><strong>Action:</strong> ${action}</li><li><strong>Detail:</strong> ${detail}</li><li><strong>IP:</strong> ${ip}</li><li><strong>Time:</strong> ${new Date().toUTCString()}</li></ul>`,
  });
}

module.exports = { alertNewIPLogin, alertNewLocationCode, alertAccountLocked, alertPasswordResetRequested, alertSuspiciousActivity };

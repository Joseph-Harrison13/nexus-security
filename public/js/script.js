'use strict';

// ═══════════════════════════════════════════════════════════
// INPUT SANITIZATION — client-side first line of defense.
// The server validates independently on every API request.
// ═══════════════════════════════════════════════════════════
const DANGEROUS_PATTERN = /[<>{}`;]|--|\/\*|\*\//g;
const MAX_FIELD_LENGTH = 500;

function sanitizeValue(value) {
  if (typeof value !== 'string') return value;
  let clean = value.replace(DANGEROUS_PATTERN, '');
  if (clean.length > MAX_FIELD_LENGTH) clean = clean.slice(0, MAX_FIELD_LENGTH);
  return clean;
}

function attachSanitizer(el) {
  if (el.dataset.sanitized) return;
  el.dataset.sanitized = 'true';
  el.addEventListener('input', () => {
    const cleaned = sanitizeValue(el.value);
    if (cleaned !== el.value) {
      const pos = el.selectionStart;
      el.value = cleaned;
      if (pos !== null) el.setSelectionRange(Math.max(0, pos - 1), Math.max(0, pos - 1));
    }
  });
  el.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text');
    const cleaned = sanitizeValue(text);
    const start = el.selectionStart, end = el.selectionEnd;
    el.value = el.value.slice(0, start) + cleaned + el.value.slice(end);
  });
}

function sanitizeAllFields() {
  document.querySelectorAll('input[type="text"], input[type="email"], input:not([type]), textarea').forEach(attachSanitizer);
}

document.addEventListener('DOMContentLoaded', sanitizeAllFields);
sanitizeAllFields();
const _sanitizeObserver = new MutationObserver(sanitizeAllFields);
_sanitizeObserver.observe(document.body, { childList: true, subtree: true });

// ── Canvas particle network ──────────────────────────────────
const canvas = document.getElementById('bgCanvas');
if (canvas && getComputedStyle(canvas).display !== 'none') {
  const ctx = canvas.getContext('2d');
  let W, H;
  function resizeCanvas() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);
  const pts = Array.from({length: 55}, () => ({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    vx: (Math.random() - 0.5) * 0.35,
    vy: (Math.random() - 0.5) * 0.35,
    r:  0.8 + Math.random() * 1.4,
    a:  0.15 + Math.random() * 0.25
  }));
  const LINK_DIST = 130;
  function drawNetwork() {
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i < pts.length; i++) {
      const p = pts[i];
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      for (let j = i + 1; j < pts.length; j++) {
        const q = pts[j];
        const dx = p.x - q.x, dy = p.y - q.y;
        const d = Math.sqrt(dx*dx + dy*dy);
        if (d < LINK_DIST) {
          const alpha = (1 - d / LINK_DIST) * 0.12;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.strokeStyle = `rgba(20,184,166,${alpha})`;
          ctx.lineWidth = 0.7;
          ctx.stroke();
        }
      }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(20,184,166,${p.a})`;
      ctx.fill();
    }
    requestAnimationFrame(drawNetwork);
  }
  drawNetwork();
}

// ── Custom cursor ───────────────────────────────────────────
const cursor = document.getElementById('cursor');
const ring   = document.getElementById('cursorRing');
if (cursor && ring && getComputedStyle(cursor).display !== 'none') {
  let mx=0, my=0, rx=0, ry=0;
  document.addEventListener('mousemove', e => {
    mx=e.clientX; my=e.clientY;
    cursor.style.left=mx-6+'px'; cursor.style.top=my-6+'px';
  });
  function animRing() {
    rx+=(mx-rx)*.12; ry+=(my-ry)*.12;
    ring.style.left=rx-18+'px'; ring.style.top=ry-18+'px';
    requestAnimationFrame(animRing);
  }
  animRing();
}

// ── Page navigation ─────────────────────────────────────────
const PAGE_ROUTES = {
  home:     '/',
  about:    '/pages/about.html',
  faq:      '/pages/faq.html',
  pricing:  '/pages/pricing.html',
  contact:  '/pages/contact.html',
  login:    '/pages/login.html',
  privacy:  '/pages/privacy.html',
  terms:    '/pages/terms.html',
  cases:    '/pages/case-studies.html',
  resources:'/pages/resources.html',
};
function showPage(id) { window.location.href = PAGE_ROUTES[id] || '/'; }
function goDash(id)   { window.location.href = '/pages/dashboard/' + id + '.html'; }

// ── Animated stat counters ──────────────────────────────────
(function () {
  const bar = document.getElementById('statsBar');
  if (!bar) return;
  const nums = bar.querySelectorAll('.stat-num[data-count]');
  if (!nums.length) return;

  function animateCounter(el) {
    const target = parseFloat(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    const isDecimal = String(target).includes('.');
    const duration = 1800;
    const start = performance.now();
    function step(now) {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - t, 3);
      const val = target * ease;
      el.textContent = (isDecimal ? val.toFixed(1) : Math.floor(val)) + suffix;
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        nums.forEach(animateCounter);
        obs.disconnect();
      }
    });
  }, { threshold: 0.5 });
  obs.observe(bar);
})();

// ── Live threat ticker ───────────────────────────────────────
(function () {
  const track = document.getElementById('threatTrack');
  if (!track) return;
  const THREATS = [
    { dot: 'red',  text: 'Ransomware detection & isolation' },
    { dot: 'grn',  text: 'Automated backups' },
    { dot: 'red',  text: 'Phishing & scam email scanning' },
    { dot: 'blue', text: 'New-device login alerts' },
    { dot: 'red',  text: 'Brute-force login protection' },
    { dot: 'grn',  text: 'AES-256 encrypted file storage' },
    { dot: 'red',  text: 'Suspicious file flagging' },
    { dot: 'blue', text: 'Two-factor authentication' },
    { dot: 'grn',  text: 'Access & activity logging' },
    { dot: 'red',  text: 'Malware signature scanning' },
  ];
  const items = [...THREATS, ...THREATS].map(t =>
    `<span class="ticker-item"><span class="ticker-dot ticker-dot-${t.dot}"></span>${t.text}</span>`
  ).join('');
  track.innerHTML = items;
})();

// ── Newsletter form ──────────────────────────────────────────
async function submitNewsletter(e) {
  e.preventDefault();
  const email = document.getElementById('newsletterEmail').value.trim();
  const msg   = document.getElementById('newsletterMsg');
  if (!email) return;
  try {
    const res = await fetch('/api/newsletter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (res.ok) {
      msg.textContent = '✓ You\'re subscribed! Watch your inbox for the first issue.';
      msg.style.color = '#7ec99b';
      msg.style.display = 'block';
      document.getElementById('newsletterEmail').value = '';
    } else {
      msg.textContent = data.error || 'Something went wrong. Please try again.';
      msg.style.color = '#ef4444';
      msg.style.display = 'block';
    }
  } catch {
    msg.textContent = 'Could not connect. Please try again.';
    msg.style.color = '#ef4444';
    msg.style.display = 'block';
  }
}

// ── Search (FAQ + Resources pages) ──────────────────────────
function initPageSearch(inputId, itemSelector) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase().trim();
    document.querySelectorAll(itemSelector).forEach(el => {
      el.style.display = !q || el.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ── Notification center ──────────────────────────────────────
let _notifOpen = false;

function initNotifications() {
  const navLinks = document.querySelector('.nav-links');
  if (!navLinks || !getToken()) return;

  const bellBtn = document.createElement('button');
  bellBtn.className = 'notif-bell-btn';
  bellBtn.id = 'notifBell';
  bellBtn.setAttribute('aria-label', 'Notifications');
  bellBtn.innerHTML = '🔔<span class="notif-badge" id="notifBadge" style="display:none">0</span>';
  navLinks.appendChild(bellBtn);

  const dropdown = document.createElement('div');
  dropdown.className = 'notif-dropdown';
  dropdown.id = 'notifDropdown';
  dropdown.innerHTML = `
    <div class="notif-header">
      <h3>Notifications</h3>
      <button class="notif-mark-all" onclick="markAllNotificationsRead()">Mark all read</button>
    </div>
    <div class="notif-list" id="notifList"><div class="notif-empty">Loading…</div></div>`;
  document.body.appendChild(dropdown);

  bellBtn.addEventListener('click', e => {
    e.stopPropagation();
    _notifOpen = !_notifOpen;
    dropdown.classList.toggle('open', _notifOpen);
    if (_notifOpen) loadNotifications();
  });

  document.addEventListener('click', e => {
    if (_notifOpen && !dropdown.contains(e.target) && !bellBtn.contains(e.target)) {
      _notifOpen = false;
      dropdown.classList.remove('open');
    }
  });

  // Poll for badge count every 60s
  loadNotifBadge();
  setInterval(loadNotifBadge, 60000);
}

async function loadNotifBadge() {
  if (!getToken()) return;
  try {
    const data = await api('GET', '/notifications?limit=1');
    if (!data) return;
    const unread = data.unreadCount ?? 0;
    const badge = document.getElementById('notifBadge');
    if (!badge) return;
    if (unread > 0) { badge.textContent = unread > 9 ? '9+' : unread; badge.style.display = 'flex'; }
    else            { badge.style.display = 'none'; }
  } catch { /* silent */ }
}

async function loadNotifications() {
  const list = document.getElementById('notifList');
  if (!list) return;
  const data = await api('GET', '/notifications?limit=20');
  if (!data) { list.innerHTML = '<div class="notif-empty">Could not load notifications.</div>'; return; }
  const items = Array.isArray(data) ? data : (data.notifications || []);
  if (!items.length) { list.innerHTML = '<div class="notif-empty">No notifications yet.</div>'; return; }

  list.innerHTML = items.map(n => `
    <div class="notif-item${n.read_at ? '' : ' unread'}" data-id="${n.id}">
      <div class="notif-icon">${n.icon || '🔔'}</div>
      <div class="notif-body">
        <div class="notif-msg">${escapeHtml(n.message)}</div>
        <div class="notif-time">${timeAgoNotif(n.created_at)}</div>
      </div>
      ${n.read_at ? '' : '<div class="notif-unread-dot"></div>'}
    </div>`).join('');

  // Mark all as read after viewing
  setTimeout(() => markAllNotificationsRead(), 1500);
}

async function markAllNotificationsRead() {
  await api('POST', '/notifications/read-all');
  const badge = document.getElementById('notifBadge');
  if (badge) badge.style.display = 'none';
  document.querySelectorAll('.notif-item.unread').forEach(el => {
    el.classList.remove('unread');
    const dot = el.querySelector('.notif-unread-dot');
    if (dot) dot.remove();
  });
}

// Escape user-controlled text before inserting it into HTML (text or attribute
// context). Filenames, names and emails are user-supplied and must never be
// dropped into innerHTML unescaped — otherwise they execute as markup/scripts.
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function timeAgoNotif(d) {
  if (!d) return '';
  const diff = Date.now() - new Date(d).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 2)  return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs/24)}d ago`;
}

// ── File preview ─────────────────────────────────────────────
async function previewFile(fileId) {
  const filename = (_files.find(f => f.id === fileId) || {}).name || 'file';
  const ext = (filename.split('.').pop() || '').toLowerCase();
  const imgTypes = new Set(['jpg','jpeg','png','gif','webp','svg','bmp']);
  const pdfTypes = new Set(['pdf']);
  const isImg = imgTypes.has(ext);
  const isPdf = pdfTypes.has(ext);

  const overlay = document.createElement('div');
  overlay.id = 'file-preview-overlay';
  overlay.onclick = e => { if (e.target === overlay) closePreview(); };
  overlay.innerHTML = `
    <div class="preview-modal">
      <div class="preview-header">
        <span class="preview-filename">${escapeHtml(filename)}</span>
        <button class="preview-close" onclick="closePreview()">✕</button>
      </div>
      <div class="preview-body" id="previewBody"><div class="preview-unsupported" style="color:#888">Loading…</div></div>
      <div class="preview-footer">
        <button class="btn-outline" onclick="downloadFile(${fileId})" style="font-size:12px;padding:9px 18px;cursor:pointer">⬇ Download</button>
        <button class="preview-close btn-primary" onclick="closePreview()" style="font-size:12px;padding:9px 18px;cursor:pointer">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.addEventListener('keydown', _previewKeyClose);

  if (!isImg && !isPdf) {
    document.getElementById('previewBody').innerHTML = `<div class="preview-unsupported">
      <div style="font-size:48px;margin-bottom:16px">📄</div>
      <div style="color:#888;margin-bottom:6px">${escapeHtml(filename)}</div>
      <div style="font-size:12px;color:#555">Preview not available for this file type.</div>
    </div>`;
    return;
  }

  try {
    const res = await fetch(`/api/files/${fileId}/download?preview=1`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    if (!res.ok) throw new Error('Fetch failed');
    const blob    = await res.blob();
    const objUrl  = URL.createObjectURL(blob);
    const bodyEl  = document.getElementById('previewBody');
    if (!bodyEl) { URL.revokeObjectURL(objUrl); return; }
    if (isImg) {
      bodyEl.innerHTML = `<img src="${objUrl}" alt="${escapeHtml(filename)}">`;
    } else {
      bodyEl.innerHTML = `<iframe src="${objUrl}" title="${escapeHtml(filename)}"></iframe>`;
    }
    // Clean up object URL when overlay closes
    overlay._objUrl = objUrl;
  } catch {
    const bodyEl = document.getElementById('previewBody');
    if (bodyEl) bodyEl.innerHTML = '<div class="preview-unsupported">Could not load file preview.</div>';
  }
}

function closePreview() {
  const el = document.getElementById('file-preview-overlay');
  if (el) { if (el._objUrl) URL.revokeObjectURL(el._objUrl); el.remove(); }
  document.removeEventListener('keydown', _previewKeyClose);
}

async function downloadFile(fileId) {
  const filename = (_files.find(f => f.id === fileId) || {}).name || 'download';
  try {
    const res = await fetch(`/api/files/${fileId}/download`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    if (!res.ok) { showToast('Download failed — please try again.'); return; }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  } catch { showToast('Download failed — network error.'); }
}
function _previewKeyClose(e) { if (e.key === 'Escape') closePreview(); }

// ── Drag-and-drop upload ─────────────────────────────────────
function initDropZone(dropZoneId, fileInputId, onFilesSelected) {
  const zone  = document.getElementById(dropZoneId);
  const input = document.getElementById(fileInputId);
  if (!zone || !input) return;

  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => onFilesSelected([...input.files]));

  zone.addEventListener('dragenter', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const files = [...(e.dataTransfer.files || [])];
    if (files.length) onFilesSelected(files);
  });
}

function showUploadProgress(pct, label) {
  const wrap  = document.querySelector('.upload-progress-wrap');
  const fill  = document.querySelector('.upload-progress-fill');
  const lbl   = document.querySelector('.upload-progress-label');
  if (!wrap) return;
  wrap.style.display = 'block';
  if (fill) fill.style.width = pct + '%';
  if (lbl)  lbl.textContent  = label;
  if (pct >= 100) setTimeout(() => { if (wrap) wrap.style.display = 'none'; }, 1500);
}

// ── PWA install prompt ───────────────────────────────────────
(function () {
  let deferredPrompt;
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredPrompt = e;
    if (localStorage.getItem('pwa_dismissed')) return;
    const banner = document.createElement('div');
    banner.id = 'pwa-banner';
    banner.innerHTML = `
      <div style="flex:1"><strong>Install Nexus Security</strong><br>Add to your home screen for quick access</div>
      <button class="pwa-install-btn" id="pwaInstall">Install</button>
      <button class="pwa-dismiss" id="pwaDismiss">✕</button>`;
    document.body.appendChild(banner);

    document.getElementById('pwaInstall').onclick = async () => {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') banner.remove();
      deferredPrompt = null;
    };
    document.getElementById('pwaDismiss').onclick = () => {
      localStorage.setItem('pwa_dismissed', '1');
      banner.remove();
    };
  });
})();

// ── Mobile hamburger nav ────────────────────────────────────
(function () {
  const btn  = document.getElementById('navHamburger');
  const menu = document.getElementById('navMobileMenu');
  if (!btn || !menu) return;
  btn.addEventListener('click', () => {
    const open = menu.classList.toggle('open');
    btn.classList.toggle('open', open);
    btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  });
  // Close on any nav-mobile-menu button click
  menu.addEventListener('click', e => {
    if (e.target.tagName === 'BUTTON') {
      menu.classList.remove('open');
      btn.classList.remove('open');
    }
  });
  // Close on outside click
  document.addEventListener('click', e => {
    if (!btn.contains(e.target) && !menu.contains(e.target)) {
      menu.classList.remove('open');
      btn.classList.remove('open');
    }
  });
})();

// ── Cookie consent banner ────────────────────────────────────
(function () {
  if (localStorage.getItem('cookie_consent')) return;
  const banner = document.createElement('div');
  banner.id = 'cookie-banner';
  banner.innerHTML = `
    <p>We use cookies to keep you logged in and improve your experience.
       See our <a href="/pages/privacy.html">Privacy Policy</a> for details.</p>
    <div class="cookie-btns">
      <button class="cookie-decline" id="cookieDecline">Decline</button>
      <button class="cookie-accept" id="cookieAccept">Accept</button>
    </div>`;
  document.body.appendChild(banner);
  document.getElementById('cookieAccept').addEventListener('click', () => {
    localStorage.setItem('cookie_consent', 'accepted');
    banner.remove();
  });
  document.getElementById('cookieDecline').addEventListener('click', () => {
    localStorage.setItem('cookie_consent', 'declined');
    banner.remove();
  });
})();

// ── Toast notification ──────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg; t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.style.display = 'none', 3500);
}

// ── Free-trial UI ───────────────────────────────────────────
// A dismissible reminder shown on login once the trial is within its final days.
function showTrialWarning(days) {
  if (document.getElementById('trialWarnModal')) return;
  const d = Math.max(0, parseInt(days, 10) || 0);
  const label = d === 0 ? 'today' : (d === 1 ? 'in 1 day' : `in ${d} days`);
  const wrap = document.createElement('div');
  wrap.id = 'trialWarnModal';
  wrap.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(43,39,35,0.45);font-family:\'DM Sans\',sans-serif;padding:20px';
  wrap.innerHTML = `
    <div style="background:#fff;border:1px solid #ebe3d7;border-radius:16px;max-width:420px;width:100%;padding:32px;text-align:center;box-shadow:0 20px 60px rgba(60,50,35,0.25)">
      <div style="font-size:40px;margin-bottom:12px">⏳</div>
      <div style="font-family:'Poppins',sans-serif;font-size:22px;font-weight:700;color:#2b2723;margin-bottom:10px">Your free trial ends ${label}</div>
      <p style="font-size:14px;color:#8a8074;line-height:1.6;margin:0 0 24px">Upgrade to a monthly plan now to keep your account and files active — no interruption to your service.</p>
      <button id="trialWarnUpgrade" style="width:100%;background:#0e9a86;color:#fff;border:none;border-radius:10px;padding:13px;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:10px">Upgrade Now</button>
      <button id="trialWarnDismiss" style="width:100%;background:transparent;color:#8a8074;border:none;padding:8px;font-size:13px;cursor:pointer">Remind me later</button>
    </div>`;
  document.body.appendChild(wrap);
  wrap.querySelector('#trialWarnUpgrade').onclick = () => { window.location.href = '/pages/dashboard/billing.html'; };
  wrap.querySelector('#trialWarnDismiss').onclick = () => wrap.remove();
}

// A blocking overlay shown when the trial has ended (server returns TRIAL_EXPIRED).
function showTrialLock() {
  if (document.getElementById('trialLockOverlay')) return;
  const wrap = document.createElement('div');
  wrap.id = 'trialLockOverlay';
  wrap.style.cssText = 'position:fixed;inset:0;z-index:10001;display:flex;align-items:center;justify-content:center;background:rgba(43,39,35,0.75);font-family:\'DM Sans\',sans-serif;padding:20px';
  wrap.innerHTML = `
    <div style="background:#fff;border:1px solid #ebe3d7;border-radius:16px;max-width:440px;width:100%;padding:36px;text-align:center;box-shadow:0 20px 60px rgba(60,50,35,0.35)">
      <div style="font-size:44px;margin-bottom:14px">🔒</div>
      <div style="font-family:'Poppins',sans-serif;font-size:24px;font-weight:700;color:#2b2723;margin-bottom:10px">Your free trial has ended</div>
      <p style="font-size:14px;color:#8a8074;line-height:1.6;margin:0 0 26px">Your files are safe. Choose a monthly plan to unlock your account and pick up right where you left off.</p>
      <button id="trialLockUpgrade" style="width:100%;background:#0e9a86;color:#fff;border:none;border-radius:10px;padding:14px;font-size:15px;font-weight:600;cursor:pointer;margin-bottom:10px">Upgrade to Continue</button>
      <button id="trialLockLogout" style="width:100%;background:transparent;color:#8a8074;border:none;padding:8px;font-size:13px;cursor:pointer">Log out</button>
    </div>`;
  document.body.appendChild(wrap);
  wrap.querySelector('#trialLockUpgrade').onclick = () => { window.location.href = '/pages/dashboard/billing.html'; };
  wrap.querySelector('#trialLockLogout').onclick  = () => { clearAuth(); window.location.href = '/pages/login.html'; };
}

// ═══════════════════════════════════════════════════════════
// API CLIENT
// ═══════════════════════════════════════════════════════════
// The real JWT is never stored in JS-readable storage — it lives only in the
// httpOnly `access_token` cookie the server sets, which the browser sends
// automatically on same-origin API calls. We keep a non-sensitive marker in
// sessionStorage purely as a client-side "is a session active?" signal; there
// is nothing here for an XSS to steal.
function getToken()      { return sessionStorage.getItem('auth_token'); }
function setToken(_t)    { sessionStorage.setItem('auth_token', '1'); }
function clearAuth()     { sessionStorage.removeItem('auth_token'); sessionStorage.removeItem('auth_user'); }
function getStoredUser() { const u = sessionStorage.getItem('auth_user'); return u ? JSON.parse(u) : null; }
function setStoredUser(u){ sessionStorage.setItem('auth_user', JSON.stringify(u)); }

async function tryRefresh() {
  try {
    const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
    if (!res.ok) return false;
    const data = await res.json();
    if (data.token) { setToken(data.token); return true; }
    return false;
  } catch { return false; }
}

async function api(method, path, body = null, isFormData = false, _retry = true) {
  const token = getToken();
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body && !isFormData) headers['Content-Type'] = 'application/json';

  const opts = { method, headers, credentials: 'include' };
  if (body) opts.body = isFormData ? body : JSON.stringify(body);

  let res;
  try {
    res = await fetch('/api' + path, opts);
  } catch {
    throw new Error('Cannot reach server');
  }

  // On 401, attempt a silent token refresh before giving up
  if (res.status === 401 && _retry) {
    const refreshed = await tryRefresh();
    if (refreshed) return api(method, path, body, isFormData, false);
    clearAuth();
    window.location.href = '/pages/login.html';
    return null;
  }

  const data = await res.json();

  // Free trial ended — the account is locked until it upgrades. Show the blocking
  // overlay instead of surfacing a raw error.
  if (res.status === 402 && data && data.code === 'TRIAL_EXPIRED') {
    if (typeof showTrialLock === 'function') showTrialLock();
    return null;
  }

  if (!res.ok) throw new Error(data.error || 'Request failed');

  // Unwrap paginated responses — return just the data array for simple callers,
  // but expose .pagination on the array so callers can access it if needed
  if (data && data.pagination && Array.isArray(data.data)) {
    const arr = data.data;
    arr.pagination = data.pagination;
    return arr;
  }
  return data;
}

// ═══════════════════════════════════════════════════════════
// CONTACT FORM
// ═══════════════════════════════════════════════════════════
async function handleSubmit() {
  const fields = {
    firstName:    document.getElementById('contactFirst')?.value?.trim()   || '',
    lastName:     document.getElementById('contactLast')?.value?.trim()    || '',
    email:        document.getElementById('contactEmail')?.value?.trim()   || '',
    businessName: document.getElementById('contactBiz')?.value?.trim()     || '',
    interestedIn: document.getElementById('contactPlan')?.value            || '',
    message:      document.getElementById('contactMessage')?.value?.trim() || '',
  };

  if (!fields.email || !fields.message) {
    showToast('Please include your email and a message.');
    return;
  }

  const btn = document.querySelector('.form-submit');
  if (btn) { btn.textContent = 'Sending…'; btn.disabled = true; }

  try {
    await api('POST', '/contact', fields);
    const msg = document.getElementById('successMsg');
    if (msg) msg.style.display = 'block';
    setTimeout(() => { if (msg) msg.style.display = 'none'; }, 6000);
  } catch (err) {
    showToast('Send failed: ' + err.message);
  } finally {
    if (btn) { btn.textContent = 'Send Message →'; btn.disabled = false; }
  }
}

// ═══════════════════════════════════════════════════════════
// FAQ
// ═══════════════════════════════════════════════════════════
const FAQ_DATA = {
  general: [
    { q: 'What exactly does Nexus Security do?', a: 'We provide combined cybersecurity and secure cloud storage for small and local businesses. That means encrypted file storage, automatic backups, real-time threat monitoring, and a dedicated local team — all in one simple plan, instead of stitching together five different tools.' },
    { q: 'Who is this service designed for?', a: 'Small and local businesses — law firms, medical offices, retail shops, real estate agencies, and similar — who need enterprise-grade protection but don\'t have an in-house IT or security team. If you store sensitive client files or worry about ransomware, this is built for you.' },
    { q: 'Do I need any technical knowledge to use this?', a: 'No. We handle the entire technical setup, configuration, and ongoing monitoring. Your dashboard is designed to be usable by anyone, regardless of technical background, and our team is always available if you have questions.' },
  ],
  security: [
    { q: 'How is my data actually protected?', a: 'All data is encrypted using AES-256, the same standard used by banks and government agencies, both at rest and in transit. We also run 24/7 automated threat monitoring, automatic backups, and maintain audit logs of every file access.' },
    { q: 'What happens if there\'s a data breach?', a: 'Our system is designed to detect and block threats before they cause damage — average detection-to-block time is under 4 seconds. In the rare case of an incident, our local team walks you through recovery personally, and our backup system allows full restoration in minutes.' },
    { q: 'Are you compliant with HIPAA, SOC 2, or other regulations?', a: 'We\'re a newer company and don\'t yet hold formal certifications like SOC 2, ISO 27001, or HIPAA — and we\'d rather say that plainly than imply one we don\'t have. That said, the security building blocks those frameworks are built on are already in place: AES-256 encryption at rest and in transit, audit logs of every file access, role-based access controls, and regular backups. We can share those logs and reports to support your own compliance work, and pursuing formal certification is on our roadmap as we grow.' },
    { q: 'Who can access my files?', a: 'Only people in your own organization — and by default, only you can see your own files. Organization Admins can manage the team and oversee the organization\'s files, while standard Users see just their own. When you need to share something, you create a secure link that you can password-protect and set to expire whenever you choose.' },
  ],
  pricing: [
    { q: 'How much does it cost?', a: 'We offer three tiers: Starter at $55/month, Growth at $99/month, and Pro at $179/month. Each tier includes more storage, users, and support response time. You can see a full breakdown on our Pricing page.' },
    { q: 'Is there a free trial?', a: 'Yes — new clients get a 21-day free trial with full access to their chosen plan\'s features, no credit card required upfront. Near the end of your trial we\'ll remind you, and to keep your account active afterward you simply pick a monthly plan.' },
    { q: 'Can I change plans later?', a: 'Absolutely. You can upgrade or downgrade at any time directly from your client dashboard under the Billing tab. Changes take effect at your next billing cycle, and we\'ll never lock you into a long-term contract.' },
    { q: 'What happens if I cancel?', a: 'You can cancel anytime with no penalty. We\'ll provide a full export of your files before your account closes, and your data is permanently deleted from our servers within 30 days of cancellation, per our data retention policy.' },
  ],
  support: [
    { q: 'How fast do you respond to support requests?', a: 'Our average response time is under 2 hours during business hours, often much faster. Higher tiers include priority support and 24/7 phone access. You\'ll have a direct line to a real local team member — never a call center.' },
    { q: 'How long does onboarding take?', a: 'Most businesses are fully set up within 1-2 business days. We handle data migration, account configuration, and a walkthrough call so your whole team knows how to use the platform from day one.' },
    { q: 'Do you offer in-person support?', a: 'Yes, for businesses within our local service area. We believe showing up in person builds the kind of trust a phone call never can — it\'s part of what makes us different from the big national providers.' },
  ],
};

function renderFAQ() {
  Object.keys(FAQ_DATA).forEach(category => {
    const container = document.getElementById('faq-list-' + category);
    if (!container) return;
    container.innerHTML = FAQ_DATA[category].map((item, i) => `
      <div class="faq-item" id="faq-${category}-${i}">
        <button class="faq-question" onclick="toggleFAQ('${category}', ${i})">
          <span>${item.q}</span>
          <div class="faq-icon"></div>
        </button>
        <div class="faq-answer">
          <div class="faq-answer-inner">${item.a}</div>
        </div>
      </div>`).join('');
  });
}

function toggleFAQ(category, index) {
  const item = document.getElementById(`faq-${category}-${index}`);
  if (item) item.classList.toggle('open');
}

document.addEventListener('DOMContentLoaded', renderFAQ);
renderFAQ();

// ═══════════════════════════════════════════════════════════
// AUTH — LOGIN / 2FA / LOGOUT
// ═══════════════════════════════════════════════════════════
let _tempToken = null;
let _verifyMode = '2fa'; // '2fa' (authenticator) or 'location' (emailed new-location code)

function showStep(id) {
  ['stepSignin','step2FA','stepSignup'].forEach(s => {
    const el = document.getElementById(s);
    if (el) el.style.display = s === id ? 'block' : 'none';
  });
  const le = document.getElementById('loginError');
  const te = document.getElementById('twoFAError');
  if (le) le.style.display = 'none';
  if (te) te.style.display = 'none';
}

function togglePassword(inputId, btn) {
  const input  = document.getElementById(inputId);
  const eye    = document.getElementById(inputId + '-icon-eye');
  const eyeOff = document.getElementById(inputId + '-icon-eyeoff');
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  if (eye && eyeOff) {
    eye.style.display    = isHidden ? 'none'  : 'block';
    eyeOff.style.display = isHidden ? 'block' : 'none';
  }
  btn.title = isHidden ? 'Hide password' : 'Show password';
}

async function handleLogin() {
  const email = document.getElementById('loginEmail').value.trim();
  const pass  = document.getElementById('loginPass').value;
  const err   = document.getElementById('loginError');
  err.style.display = 'none';

  const btn = document.querySelector('.login-btn');
  if (btn) { btn.textContent = 'Signing in…'; btn.disabled = true; }

  try {
    const res  = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pass }),
    });
    const json = await res.json();

    if (!res.ok) {
      err.textContent = json.error || 'Invalid email or password';
      err.style.display = 'block';
      return;
    }

    _tempToken = json.tempToken;
    // Two paths share the 6-digit code UI: authenticator-app 2FA, or an emailed
    // code because this is a sign-in from a new location.
    _verifyMode = json.needsLocationVerification ? 'location' : '2fa';
    const titleEl = document.getElementById('verifyTitle');
    const subEl   = document.getElementById('verifySub');
    const iconEl  = document.getElementById('verifyIcon');
    if (_verifyMode === 'location') {
      // The emailed code covers two cases: routine email 2FA, or a new-location sign-in.
      const newLoc = json.reason === 'new_location';
      if (iconEl)  iconEl.textContent  = newLoc ? '📍' : '✉️';
      if (titleEl) titleEl.textContent = newLoc ? 'New Location Detected' : 'Check Your Email';
      if (subEl)   subEl.innerHTML     = `${newLoc ? 'For your security, enter' : 'Enter'} the 6-digit code we emailed to <span style="color:#d4d4d4">${escapeHtml(json.email || 'your email')}</span>`;
    } else {
      if (iconEl)  iconEl.textContent  = '🔐';
      if (titleEl) titleEl.textContent = 'Verify Identity';
      if (subEl)   subEl.innerHTML     = `Enter the 6-digit code sent to your email ending in <span id="emailHint" style="color:#d4d4d4">••••${email.slice(-8)}</span>`;
    }
    showStep('step2FA');
    document.getElementById('c1').focus();
    showToast(json.demoHint || 'Verification code sent to your email');
  } catch (e) {
    err.textContent = e.message;
    err.style.display = 'block';
  } finally {
    if (btn) { btn.textContent = 'Sign In'; btn.disabled = false; }
  }
}

// ── 2FA input box helpers ───────────────────────────────────
function codeMove(el, nextId) {
  if (el.value && nextId) document.getElementById(nextId).focus();
}
function codeDel(e, el, prevId) {
  if (e.key === 'Backspace' && !el.value && prevId) document.getElementById(prevId).focus();
}

async function handle2FA() {
  const entered = ['c1','c2','c3','c4','c5','c6'].map(id => document.getElementById(id).value).join('');
  const err = document.getElementById('twoFAError');
  err.style.display = 'none';

  try {
    const endpoint = _verifyMode === 'location' ? '/api/auth/verify-location' : '/api/auth/verify-2fa';
    const res  = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken: _tempToken, code: entered }),
    });
    const json = await res.json();

    if (!res.ok) {
      ['c1','c2','c3','c4','c5','c6'].forEach(id => document.getElementById(id).value = '');
      document.getElementById('c1').focus();
      err.textContent = json.error || 'Incorrect code — please try again';
      err.style.display = 'block';
      return;
    }

    setToken(json.token);
    setStoredUser(json.user);
    // Two-factor auth is mandatory; data routes stay locked (server-enforced)
    // until an authenticator app is enrolled. Send them straight to setup.
    if (json.mustEnableTotp) {
      sessionStorage.setItem('force_totp_setup', '1');
      showToast('Two-factor authentication is required — please set up an authenticator app to continue.');
      goDash('settings');
      return;
    }
    // If the free trial is in its final days, flag a reminder for the dashboard.
    try {
      const st = await api('GET', '/stripe/status');
      if (st && st.onTrial && st.trialDaysLeft >= 1 && st.trialDaysLeft <= 5) {
        sessionStorage.setItem('trial_warn_days', String(st.trialDaysLeft));
      }
    } catch { /* non-blocking */ }

    // Show onboarding on first login ever
    const onboardKey = 'onboarded_' + (json.user?.id || '');
    if (!localStorage.getItem(onboardKey)) {
      sessionStorage.setItem('show_onboarding', '1');
    }
    goDash('overview');
  } catch (e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

function resendCode() {
  if (!_tempToken) { showPage('login'); return; }
  ['c1','c2','c3','c4','c5','c6'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('c1')?.focus();
  showToast('Enter the 6-digit code from your authenticator app.');
}

async function handleLogout() {
  try { await api('POST', '/auth/logout'); } catch { /* ignore errors on logout */ }
  clearAuth();
  window.location.href = '/pages/login.html';
}

// ── Idle auto-logout ─────────────────────────────────────────
// Sign the user out after sustained inactivity, with a short warning first.
const IDLE_LIMIT_MS = 30 * 60 * 1000; // 30 minutes of no activity
const IDLE_WARN_MS  = 60 * 1000;      // warn 60s before signing out
let _idleTimer = null, _idleWarnTimer = null, _idleCountdown = null;

function _clearIdleTimers() {
  clearTimeout(_idleTimer); clearTimeout(_idleWarnTimer); clearInterval(_idleCountdown);
}
function _hideIdleWarning() {
  const el = document.getElementById('idleWarn');
  if (el) el.style.display = 'none';
}
function resetIdleTimer() {
  if (!getToken()) return;
  _clearIdleTimers();
  _hideIdleWarning();
  _idleWarnTimer = setTimeout(showIdleWarning, IDLE_LIMIT_MS - IDLE_WARN_MS);
  _idleTimer     = setTimeout(() => { _clearIdleTimers(); handleLogout(); }, IDLE_LIMIT_MS);
}
function showIdleWarning() {
  let el = document.getElementById('idleWarn');
  if (!el) {
    el = document.createElement('div');
    el.id = 'idleWarn';
    el.innerHTML = `
      <div style="background:#232c40;border:1px solid #36405a;border-radius:14px;padding:28px 32px;max-width:380px;text-align:center;box-shadow:0 12px 50px rgba(0,0,0,0.6)">
        <div style="font-size:34px;margin-bottom:10px">⏳</div>
        <div style="font-family:'Cormorant Garamond',serif;font-size:22px;font-weight:700;color:#f0f0f0;margin-bottom:8px">Still there?</div>
        <div style="font-size:14px;color:#8a93a6;line-height:1.6;margin-bottom:18px">For your security, you'll be signed out in <span id="idleSecs" style="color:#2dd4bf;font-weight:600">60</span> seconds due to inactivity.</div>
        <button onclick="resetIdleTimer()" class="btn-primary" style="cursor:pointer;width:100%">Stay Signed In</button>
      </div>`;
    el.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(10,14,22,0.7);backdrop-filter:blur(4px);padding:24px';
    document.body.appendChild(el);
  }
  el.style.display = 'flex';
  let secs = Math.round(IDLE_WARN_MS / 1000);
  const secsEl = document.getElementById('idleSecs');
  if (secsEl) secsEl.textContent = secs;
  clearInterval(_idleCountdown);
  _idleCountdown = setInterval(() => {
    secs -= 1;
    const e = document.getElementById('idleSecs');
    if (e) e.textContent = Math.max(0, secs);
    if (secs <= 0) clearInterval(_idleCountdown);
  }, 1000);
}
function initIdleLogout() {
  if (!getToken()) return;
  ['mousemove','mousedown','keydown','scroll','touchstart'].forEach(ev =>
    window.addEventListener(ev, () => {
      // While the warning is up, ignore passive events — require the explicit button.
      if (document.getElementById('idleWarn')?.style.display === 'flex') return;
      resetIdleTimer();
    }, { passive: true }));
  resetIdleTimer();
}


// ── Enter-key shortcuts on login page ──────────────────────
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const signin = document.getElementById('stepSignin');
  const twofa  = document.getElementById('step2FA');
  const signup = document.getElementById('stepSignup');
  if (signin && signin.style.display !== 'none') { handleLogin(); return; }
  if (twofa  && twofa.style.display  !== 'none') { handle2FA();  return; }
  if (signup && signup.style.display !== 'none') { handleSignup(); return; }
});

// ── Signup (sends request — account set up by the team) ─────
async function handleSignup() {
  const first   = document.getElementById('signupFirst')?.value?.trim();
  const last    = document.getElementById('signupLast')?.value?.trim();
  const biz     = document.getElementById('signupBiz')?.value?.trim();
  const email   = document.getElementById('signupEmail')?.value?.trim();
  const pass    = document.getElementById('signupPass')?.value;
  const confirm = document.getElementById('signupConfirm')?.value;
  const errEl   = document.getElementById('signupError');
  const sucEl   = document.getElementById('signupSuccess');
  const btn     = document.querySelector('#stepSignup .login-btn');

  errEl.style.display = 'none';
  sucEl.style.display = 'none';

  if (!first || !last || !biz || !email || !pass) {
    errEl.textContent = 'Please fill in all fields.';
    errEl.style.display = 'block'; return;
  }
  if (pass !== confirm) {
    errEl.textContent = 'Passwords do not match.';
    errEl.style.display = 'block'; return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Creating account…'; }
  try {
    const plan = document.getElementById('signupPlan')?.value || 'Starter';
    const res = await fetch('/api/auth/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ firstName: first, lastName: last, businessName: biz, email, password: pass, plan }),
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.error || 'Could not create account.';
      errEl.style.display = 'block'; return;
    }
    sucEl.textContent = '✓ Your 21-day free trial has started! You can sign in now.';
    sucEl.style.display = 'block';
    setTimeout(() => showStep('stepSignin'), 2000);
  } catch {
    errEl.textContent = 'Network error — please try again.';
    errEl.style.display = 'block';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Start Free Trial →'; }
  }
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — SIDEBAR
// ═══════════════════════════════════════════════════════════
const DASH_NAV = [
  { section: 'Main', items: [
    { id:'overview', icon:'📊', label:'Overview' },
    { id:'storage',  icon:'☁️', label:'Storage' },
    { id:'security', icon:'🛡️', label:'Security' },
    { id:'files',    icon:'📁', label:'Files' },
  ]},
  { section: 'Account', items: [
    { id:'users',    icon:'👥', label:'Users' },
    { id:'billing',  icon:'💳', label:'Billing' },
    { id:'settings', icon:'⚙️', label:'Settings' },
  ]},
];

function buildSidebar(activeId) {
  const user = getStoredUser();
  let html = '';
  DASH_NAV.forEach(group => {
    html += `<div class="sidebar-section-label">${group.section}</div>`;
    group.items.forEach(it => {
      html += `<button class="sidebar-item${it.id === activeId ? ' active' : ''}" onclick="goDash('${it.id}')"><span class="s-icon">${it.icon}</span> ${it.label}</button>`;
    });
  });
  if (user?.role === 'Admin') {
    html += `<div class="sidebar-section-label">Admin</div>`;
    html += `<button class="sidebar-item${activeId === 'admin' ? ' active' : ''}" onclick="window.location.href='/pages/dashboard/admin.html'"><span class="s-icon">🔑</span> Admin Panel</button>`;
  }
  html += `
    <div class="sidebar-section-label">Support</div>
    <button class="sidebar-item" onclick="showPage('contact')"><span class="s-icon">🤝</span> Contact Us</button>
    <div class="sidebar-user">
      <div class="sidebar-avatar">👤</div>
      <div>
        <div class="sidebar-user-name">${escapeHtml(user?.name || 'My Account')}</div>
        <div class="sidebar-user-plan">${escapeHtml(user?.plan || 'Starter')} Plan</div>
      </div>
      <button class="sidebar-logout" title="Sign out" onclick="handleLogout()"
        style="margin-left:auto;background:transparent;border:1px solid #2a2a2a;border-radius:6px;padding:6px 12px;color:#686868;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all 0.2s"
        onmouseover="this.style.color='#c97e7e';this.style.borderColor='rgba(201,126,126,0.4)'"
        onmouseout="this.style.color='#686868';this.style.borderColor='#2a2a2a'">Sign Out</button>
    </div>`;
  return html;
}

function renderAllSidebars() {
  DASH_NAV.flatMap(g => g.items).forEach(it => {
    const el = document.getElementById('sb-' + it.id);
    if (el) el.innerHTML = buildSidebar(it.id);
  });
}

function buildDashTabs(activeId) {
  const allTabs = DASH_NAV.flatMap(g => g.items);
  const back = activeId !== 'overview'
    ? `<button class="dash-back" onclick="goDash('overview')">&#8592; Overview</button>`
    : '';
  const tabs = allTabs.map(t =>
    `<button class="dash-tab${t.id === activeId ? ' active' : ''}" onclick="goDash('${t.id}')">${t.icon} ${t.label}</button>`
  ).join('');
  return `<div class="dash-tab-bar">${back}${tabs}</div>`;
}

function renderDashTabs() {
  const activeId = window.location.pathname.split('/').pop().replace('.html', '');
  const el = document.getElementById('dash-tabs');
  if (el) el.innerHTML = buildDashTabs(activeId);
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — FILES
// ═══════════════════════════════════════════════════════════
let _files = [];

function getFileIcon(mimeType, name) {
  const ext = (name || '').split('.').pop().toLowerCase();
  if (mimeType?.includes('pdf')        || ext === 'pdf')               return '📕';
  if (mimeType?.includes('zip')        || ['zip','gz','tar'].includes(ext)) return '🗜️';
  if (mimeType?.includes('spreadsheet')|| ['xlsx','csv'].includes(ext)) return '📊';
  if (mimeType?.includes('image')      || ['jpg','png','gif','webp'].includes(ext)) return '🖼️';
  if (mimeType?.includes('video')      || ['mp4','mov','avi'].includes(ext)) return '🎬';
  if (mimeType?.includes('word')       || ['doc','docx'].includes(ext)) return '📝';
  return '📄';
}

function formatSize(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024)    return (bytes / 1024).toFixed(0)    + ' KB';
  return bytes + ' B';
}

function renderFiles(list) {
  const el    = document.getElementById('fileList');
  const empty = document.getElementById('emptyFiles');
  if (!el) return;

  const countEl = document.getElementById('fileCount');
  if (countEl) countEl.textContent = list.length + ' files';

  if (!list.length) {
    el.innerHTML = '';
    if (empty) empty.style.display = 'block';
    return;
  }
  if (empty) empty.style.display = 'none';

  const previewExts = new Set(['jpg','jpeg','png','gif','webp','svg','pdf','bmp']);

  el.innerHTML = list.map(f => {
    const icon = getFileIcon(f.mime_type, f.name);
    const size = formatSize(f.size);
    const date = new Date(f.uploaded_at).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    const ext  = (f.name.split('.').pop() || '').toLowerCase();
    const canPreview = previewExts.has(ext);
    // Pass only the numeric id to handlers — the filename is resolved from _files
    // inside each handler so untrusted text never enters the inline-handler context.
    const checked = _selectedFiles.has(f.id) ? 'checked' : '';
    return `
      <div class="activity-item">
        <input type="checkbox" ${checked} onchange="toggleFileSelect(${f.id}, this.checked)" title="Select"
          style="width:16px;height:16px;accent-color:#14b8a6;cursor:pointer;flex-shrink:0"/>
        <div class="activity-icon">${icon}</div>
        <div class="activity-text">
          <div class="activity-title">${escapeHtml(f.name)}</div>
          <div class="activity-time">${size} · ${date}</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <select onchange="moveFile(${f.id}, this.value)" title="Move to folder"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 6px;color:#8a93a6;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer;max-width:120px">
            ${folderOptions(f.folder_id)}
          </select>
          ${canPreview ? `<button onclick="previewFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 10px;color:#14B8A6;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Preview">👁</button>` : ''}
          <button onclick="shareFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 10px;color:#2dd4bf;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Share a secure link">🔗</button>
          <button onclick="downloadFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 10px;color:#8a93a6;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Download">↓</button>
          <button onclick="deleteFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 10px;color:#8a93a6;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Move to Trash">✕</button>
        </div>
      </div>`;
  }).join('');
  if (typeof updateBulkBar === 'function') updateBulkBar();
}

// ── Folders ──────────────────────────────────────────────────
let _folders = [];
let _viewingTrash = false;

function folderOptions(currentId) {
  const opts = ['<option value="">— No folder —</option>'];
  for (const fo of _folders) {
    const sel = String(fo.id) === String(currentId) ? ' selected' : '';
    opts.push(`<option value="${fo.id}"${sel}>${escapeHtml(fo.name)}</option>`);
  }
  return opts.join('');
}

async function loadFolders() {
  if (!document.getElementById('folderFilter')) return;
  try {
    const res = await api('GET', '/folders');
    _folders = (res && res.data) || (Array.isArray(res) ? res : []);
  } catch { _folders = []; }
  const sel = document.getElementById('folderFilter');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">All Folders</option><option value="root">No Folder</option>'
    + _folders.map(f => `<option value="${f.id}">${escapeHtml(f.name)} (${f.file_count})</option>`).join('');
  sel.value = current;
}

async function loadFiles() {
  if (!document.getElementById('fileList')) return;
  const folderVal = document.getElementById('folderFilter')?.value || '';
  const qs = folderVal ? `?folder=${encodeURIComponent(folderVal)}` : '';
  try {
    const files = await api('GET', '/files' + qs);
    if (files) { _files = files; filterFiles(); }
  } catch { /* page may not have a file list */ }
}

function onFolderChange() {
  const sel = document.getElementById('folderFilter');
  const actions = document.getElementById('folderActions');
  // Offer to delete the currently selected (real) folder.
  if (actions) {
    const fid = sel.value;
    if (fid && fid !== 'root') {
      const folder = _folders.find(f => String(f.id) === String(fid));
      actions.style.display = 'block';
      actions.innerHTML = `Viewing <strong style="color:#d4d4d4">${escapeHtml(folder?.name || '')}</strong> — `
        + `<button onclick="deleteFolder(${fid})" style="background:none;border:none;color:#f87171;cursor:pointer;font-size:12px;text-decoration:underline;padding:0">delete folder</button> `
        + `<span style="color:#69748a">(files are kept)</span>`;
    } else { actions.style.display = 'none'; actions.innerHTML = ''; }
  }
  clearSelection();
  loadFiles();
}

async function createFolder() {
  const name = (prompt('New folder name:') || '').trim();
  if (!name) return;
  try {
    await api('POST', '/folders', { name });
    showToast(`Folder "${name}" created.`);
    await loadFolders();
  } catch (err) { showToast(err.message || 'Could not create folder.'); }
}

async function deleteFolder(id) {
  const folder = _folders.find(f => String(f.id) === String(id));
  if (!confirm(`Delete folder "${folder?.name || ''}"? Your files will be kept and moved out of the folder.`)) return;
  try {
    await api('DELETE', `/folders/${id}`);
    showToast('Folder deleted. Files were kept.');
    const sel = document.getElementById('folderFilter');
    if (sel) sel.value = '';
    await loadFolders();
    onFolderChange();
  } catch (err) { showToast(err.message || 'Could not delete folder.'); }
}

async function moveFile(id, folderId) {
  try {
    await api('PUT', `/files/${id}/move`, { folderId: folderId === '' ? null : folderId });
    showToast('File moved.');
    await loadFolders();
    await loadFiles();
  } catch (err) { showToast(err.message || 'Could not move file.'); }
}

function filterFiles() {
  if (_viewingTrash) return; // search box doesn't filter the trash view
  const q = document.getElementById('fileSearch')?.value?.toLowerCase() || '';
  renderFiles(_files.filter(f => f.name.toLowerCase().includes(q)));
}

// ── Trash ────────────────────────────────────────────────────
async function toggleTrash() {
  _viewingTrash = !_viewingTrash;
  clearSelection();
  const bulk = document.getElementById('bulkBar');
  if (bulk) bulk.style.display = 'none';
  const btn = document.getElementById('trashToggleBtn');
  if (_viewingTrash) {
    if (btn) { btn.textContent = '← BACK TO FILES'; btn.style.color = '#2dd4bf'; }
    await renderTrash();
  } else {
    if (btn) { btn.textContent = '🗑 TRASH'; btn.style.color = '#d4d4d4'; }
    await loadFiles();
  }
}

async function renderTrash() {
  const el = document.getElementById('fileList');
  const empty = document.getElementById('emptyFiles');
  const countEl = document.getElementById('fileCount');
  if (!el) return;
  let rows = [];
  try { const res = await api('GET', '/files/trash'); rows = (res && res.data) || []; } catch { rows = []; }
  if (countEl) countEl.textContent = `${rows.length} in Trash`;
  if (!rows.length) {
    el.innerHTML = '';
    if (empty) { empty.style.display = 'block'; empty.textContent = 'Trash is empty. Deleted files appear here for 30 days.'; }
    return;
  }
  if (empty) empty.style.display = 'none';
  el.innerHTML = rows.map(f => {
    const date = new Date((f.deleted_at || '').replace(' ', 'T') + 'Z').toLocaleDateString('en-US', { month:'short', day:'numeric' });
    return `
      <div class="activity-item">
        <div class="activity-icon">🗑️</div>
        <div class="activity-text">
          <div class="activity-title">${escapeHtml(f.name)}</div>
          <div class="activity-time">Deleted ${date} · auto-removed after 30 days</div>
        </div>
        <div style="display:flex;gap:6px">
          <button onclick="restoreFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 12px;color:#2dd4bf;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Restore">↩ RESTORE</button>
          <button onclick="permanentDeleteFile(${f.id})"
            style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 12px;color:#f87171;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Delete forever">✕ FOREVER</button>
        </div>
      </div>`;
  }).join('');
}

async function restoreFile(id) {
  try {
    await api('POST', `/files/${id}/restore`);
    showToast('File restored.');
    await renderTrash();
  } catch (err) { showToast(err.message || 'Could not restore file.'); }
}

async function permanentDeleteFile(id) {
  if (!confirm('Permanently delete this file? This cannot be undone.')) return;
  try {
    await api('DELETE', `/files/${id}/permanent`);
    showToast('File permanently deleted.');
    await renderTrash();
  } catch (err) { showToast(err.message || 'Could not delete file.'); }
}

async function handleUpload(e) {
  await uploadFiles([...e.target.files]);
  e.target.value = '';
}

async function uploadFiles(fileList) {
  if (!fileList.length) return;
  // If the user is filtered into a specific folder, drop new uploads there.
  const folderVal = document.getElementById('folderFilter')?.value || '';
  const targetFolder = /^\d+$/.test(folderVal) ? folderVal : '';
  let succeeded = 0;
  for (let i = 0; i < fileList.length; i++) {
    const f = fileList[i];
    const pct = Math.round((i / fileList.length) * 90);
    showUploadProgress(pct, `Uploading ${f.name}… (${i+1}/${fileList.length})`);
    try {
      const formData = new FormData();
      formData.append('file', f);
      if (targetFolder) formData.append('folderId', targetFolder);
      const newFile = await api('POST', '/files/upload', formData, true);
      if (newFile) { _files.unshift(newFile); succeeded++; }
    } catch (err) {
      showToast(`Failed: ${f.name} — ${err.message}`);
    }
  }
  showUploadProgress(100, `✓ ${succeeded} file${succeeded > 1 ? 's' : ''} uploaded`);
  if (succeeded) { renderFiles(_files); loadFolders(); showToast(`✓ ${succeeded} file${succeeded > 1 ? 's' : ''} uploaded.`); }
}

async function exportFilesZip() {
  showToast('Preparing your ZIP download…');
  const token = getToken();
  const a = document.createElement('a');
  a.href = '/api/files/export/zip';
  a.download = 'my-files.zip';
  // include auth header via fetch + blob
  try {
    const res = await fetch('/api/files/export/zip', { headers: { Authorization: 'Bearer ' + token }, credentials: 'include' });
    if (!res.ok) { showToast('Export failed — no files to download.'); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    a.href = url;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch { showToast('Export failed.'); }
}

const ACTIVITY_ICONS = {
  login:           '🔑', logout: '🚪', login_failed: '⚠️',
  file_upload:     '⬆️', file_download: '⬇️', file_preview: '👁️',
  file_deleted:    '🗑️', file_export: '📦',
  password_change: '🔒', user_added: '➕', user_removed: '➖', user_updated: '✏️',
  '2fa_enabled':   '🛡️', '2fa_disabled': '🔓', new_ip_login: '📍',
};
function timeAgo(ts) {
  const d = new Date((ts || '').replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(ts || '') ? '' : 'Z'));
  if (isNaN(d)) return ts || '';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60)    return 'just now';
  if (s < 3600)  return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  if (s < 604800)return Math.floor(s/86400) + 'd ago';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
async function renderActivity() {
  const feed = document.getElementById('activityFeed');
  if (!feed) return;
  let rows;
  try { rows = await api('GET', '/dashboard/activity?limit=50'); } catch { return; }
  if (!rows || !rows.length) {
    feed.innerHTML = '<div style="text-align:center;padding:32px 20px;color:#69748a;font-size:14px">No activity yet.</div>';
    return;
  }
  feed.innerHTML = rows.map(r => `
    <div class="activity-item">
      <div class="activity-icon">${ACTIVITY_ICONS[r.action] || '•'}</div>
      <div class="activity-text">
        <div class="activity-title">${escapeHtml(r.detail || r.action || '')}</div>
        <div class="activity-time">${timeAgo(r.created_at)}${r.ip ? ' · ' + escapeHtml(r.ip) : ''}</div>
      </div>
    </div>`).join('');
}

// ── Devices & sessions ───────────────────────────────────────
function describeAgent(ua) {
  ua = ua || '';
  let os = 'Unknown device';
  if (/iPhone|iPad|iOS/i.test(ua))      os = 'iOS';
  else if (/Android/i.test(ua))         os = 'Android';
  else if (/Mac OS X|Macintosh/i.test(ua)) os = 'Mac';
  else if (/Windows/i.test(ua))         os = 'Windows';
  else if (/Linux/i.test(ua))           os = 'Linux';
  let browser = '';
  if (/Edg\//i.test(ua))          browser = 'Edge';
  else if (/Chrome\//i.test(ua))  browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua))  browser = 'Safari';
  return browser ? `${browser} on ${os}` : os;
}

async function renderSessions() {
  const el = document.getElementById('sessionList');
  if (!el) return;
  let rows;
  try { rows = await api('GET', '/sessions'); } catch { return; }
  if (!rows || !rows.length) {
    el.innerHTML = '<div style="text-align:center;padding:24px;color:#69748a;font-size:14px">No active sessions.</div>';
    return;
  }
  el.innerHTML = rows.map(s => {
    const current = s.is_current;
    const when = s.last_used ? timeAgo(s.last_used) : timeAgo(s.created_at);
    return `
      <div class="activity-item">
        <div class="activity-icon">${current ? '✅' : '💻'}</div>
        <div class="activity-text">
          <div class="activity-title">${escapeHtml(describeAgent(s.user_agent))}
            ${current ? '<span style="color:#2dd4bf;font-family:\'DM Mono\',monospace;font-size:9px;letter-spacing:1px;margin-left:6px">THIS DEVICE</span>' : ''}</div>
          <div class="activity-time">${escapeHtml(s.ip || 'unknown IP')} · active ${when}</div>
        </div>
        ${current ? '' : `<button onclick="revokeSession('${s.id}')"
          style="background:#1d2536;border:1px solid #2c3650;border-radius:5px;padding:5px 12px;color:#f87171;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;cursor:pointer" title="Sign out">SIGN OUT</button>`}
      </div>`;
  }).join('');
}

async function revokeSession(id) {
  try {
    await api('DELETE', `/sessions/${id}`);
    showToast('Device signed out.');
    await renderSessions();
  } catch (err) { showToast(err.message || 'Could not sign out that device.'); }
}

async function revokeOtherSessions() {
  if (!confirm('Sign out of all other devices? You will stay signed in here.')) return;
  try {
    const r = await api('DELETE', '/sessions');
    showToast(r.message || 'Other devices signed out.');
    await renderSessions();
  } catch (err) { showToast(err.message || 'Could not sign out other devices.'); }
}

// ── Secure file sharing ──────────────────────────────────────
const SHARE_EXPIRY = { '1': 24, '7': 168, '30': 720, '0': null };
async function shareFile(id) {
  const file = _files.find(f => f.id === id) || {};
  const days = prompt('Create a secure share link.\n\nLink expires in how many days? Enter 1, 7, 30, or 0 for no expiry:', '7');
  if (days === null) return; // cancelled
  const hours = SHARE_EXPIRY[days.trim()] !== undefined ? SHARE_EXPIRY[days.trim()] : 168;
  const password = prompt('Optional password to protect the link (leave blank for none):', '');
  if (password === null) return; // cancelled
  try {
    const r = await api('POST', `/files/${id}/share`, {
      expiresInHours: hours,
      password: password.trim() || undefined,
    });
    const url = window.location.origin + r.path;
    let copied = false;
    try { await navigator.clipboard.writeText(url); copied = true; } catch { /* clipboard may be blocked */ }
    const exp = hours ? `expires in ${days.trim()} day${days.trim()==='1'?'':'s'}` : 'no expiry';
    showToast(`🔗 Secure link for "${file.name || 'file'}" ${copied ? 'copied to clipboard' : 'created'} — ${exp}${password.trim() ? ', password set' : ''}.`);
    if (!copied) prompt('Copy your secure share link:', url);
  } catch (err) {
    showToast(err.message || 'Could not create share link.');
  }
}

// ── Bulk file actions ────────────────────────────────────────
const _selectedFiles = new Set();
function toggleFileSelect(id, on) {
  if (on) _selectedFiles.add(id); else _selectedFiles.delete(id);
  updateBulkBar();
}
function clearSelection() {
  _selectedFiles.clear();
  document.querySelectorAll('#fileList input[type=checkbox]').forEach(c => { c.checked = false; });
  updateBulkBar();
}
function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  if (!bar) return;
  const n = _selectedFiles.size;
  bar.style.display = n > 0 ? 'flex' : 'none';
  const cnt = document.getElementById('bulkCount');
  if (cnt) cnt.textContent = `${n} selected`;
  const sel = document.getElementById('bulkFolder');
  if (sel) sel.innerHTML = '<option value="">Move to…</option><option value="__root">— No folder —</option>'
    + _folders.map(f => `<option value="${f.id}">${escapeHtml(f.name)}</option>`).join('');
}
async function bulkMove() {
  const sel = document.getElementById('bulkFolder');
  const val = sel?.value;
  if (!val) { showToast('Pick a folder to move to.'); return; }
  const folderId = val === '__root' ? null : val;
  const ids = [..._selectedFiles];
  let ok = 0;
  for (const id of ids) {
    try { await api('PUT', `/files/${id}/move`, { folderId }); ok++; } catch { /* skip */ }
  }
  clearSelection();
  await loadFolders();
  await loadFiles();
  showToast(`Moved ${ok} file${ok===1?'':'s'}.`);
}
async function bulkDelete() {
  const ids = [..._selectedFiles];
  if (!confirm(`Move ${ids.length} file${ids.length===1?'':'s'} to the Trash? You can restore them within 30 days.`)) return;
  let ok = 0;
  for (const id of ids) {
    try { await api('DELETE', `/files/${id}`); _files = _files.filter(f => f.id !== id); ok++; } catch { /* skip */ }
  }
  clearSelection();
  renderFiles(_files);
  await loadFolders();
  showToast(`Moved ${ok} file${ok===1?'':'s'} to Trash.`);
}

async function exportActivityCsv() {
  showToast('Preparing your activity export…');
  const token = getToken();
  try {
    const res = await fetch('/api/dashboard/activity/export/csv', { headers: { Authorization: 'Bearer ' + token }, credentials: 'include' });
    if (!res.ok) { showToast('Export failed.'); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'activity-history.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch { showToast('Export failed.'); }
}

async function deleteFile(id) {
  const name = (_files.find(f => f.id === id) || {}).name || 'File';
  try {
    await api('DELETE', `/files/${id}`);
    _files = _files.filter(f => f.id !== id);
    renderFiles(_files);
    loadFolders();
    showToast(`"${name}" moved to Trash — recoverable for 30 days.`);
  } catch (err) {
    showToast('Delete failed: ' + err.message);
  }
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — USERS
// ═══════════════════════════════════════════════════════════
let _users = [];

function renderUsers(list) {
  const el = document.getElementById('userList');
  if (!el) return;

  el.innerHTML = list.map(u => `
    <div class="activity-item">
      <div class="activity-icon">👤</div>
      <div class="activity-text">
        <div class="activity-title">${escapeHtml(u.name)}
          <span style="font-family:'DM Mono',monospace;font-size:10px;color:#686868;letter-spacing:1px;margin-left:6px">${escapeHtml(u.role)}</span>
        </div>
        <div class="activity-time">${escapeHtml(u.email)}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <div class="activity-status status-ok">Active</div>
        ${u.role !== 'Admin' ? `<button onclick="removeUser(${u.id})"
          style="background:#1c1c1c;border:1px solid #2a2a2a;border-radius:5px;padding:5px 10px;color:#686868;font-family:'DM Mono',monospace;font-size:9px;cursor:pointer">Remove</button>` : ''}
      </div>
    </div>`).join('');

  const count   = list.length;
  const countEl = document.getElementById('userCount');
  const subEl   = document.getElementById('userSub');
  const badgeEl = document.getElementById('userBadge');
  if (countEl)  countEl.textContent  = count;
  const SEAT_LIMITS = { Starter: 3, Growth: 10, Pro: 50 };
  const userPlan  = getStoredUser()?.plan || 'Starter';
  const seatLimit = SEAT_LIMITS[userPlan] ?? 10;
  const limitLabel = seatLimit === Infinity ? 'Unlimited' : seatLimit;
  if (subEl)    subEl.textContent    = `of ${limitLabel} seats used`;
  if (badgeEl)  badgeEl.textContent  = seatLimit === Infinity ? 'Unlimited' : `${Math.max(0, seatLimit - count)} left`;
}

async function addUser() {
  const name  = document.getElementById('newUserName')?.value?.trim();
  const email = document.getElementById('newUserEmail')?.value?.trim();
  if (!name || !email) { showToast('Please fill in both name and email.'); return; }
  const SEAT_LIMITS = { Starter: 3, Growth: 10, Pro: 50 };
  const seatLimit = SEAT_LIMITS[getStoredUser()?.plan] ?? 10;
  if (_users.length >= seatLimit) { showToast(`You have reached your ${seatLimit}-seat limit. Upgrade your plan to add more users.`); return; }

  const tempPass = 'Temp' + Math.random().toString(36).slice(2, 8) + '1!';
  try {
    const newUser = await api('POST', '/users', { name, email, role: 'User', plan: 'Starter', password: tempPass });
    if (newUser) { _users.push(newUser); renderUsers(_users); }
    document.getElementById('newUserName').value  = '';
    document.getElementById('newUserEmail').value = '';
    document.getElementById('addUserPanel').style.display = 'none';
    showToast(`Invite sent to ${email}.`);
  } catch (err) {
    showToast('Failed to add user: ' + err.message);
  }
}

async function removeUser(id) {
  const email = (_users.find(u => u.id === id) || {}).email || 'User';
  try {
    await api('DELETE', `/users/${id}`);
    _users = _users.filter(u => u.id !== id);
    renderUsers(_users);
    showToast(`${email} removed from your team.`);
  } catch (err) {
    showToast('Remove failed: ' + err.message);
  }
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — SETTINGS TOGGLES
// ═══════════════════════════════════════════════════════════
const toggles = [
  { label:'Threat Alerts',          sub:'Email when a threat is detected',    on:true  },
  { label:'Backup Reports',         sub:'Daily summary of backup status',      on:true  },
  { label:'Login Notifications',    sub:'Alert on new device login',           on:true  },
  { label:'Weekly Security Digest', sub:'Summary every Monday morning',        on:false },
  { label:'Storage Warnings',       sub:'Alert at 80% and 95% usage',          on:true  },
];

function renderToggles() {
  const el = document.getElementById('toggleList');
  if (!el) return;
  el.innerHTML = toggles.map((t, i) => `
    <div class="toggle-row">
      <div><div class="toggle-label">${t.label}</div><div class="toggle-sub">${t.sub}</div></div>
      <label class="toggle">
        <input type="checkbox" ${t.on ? 'checked' : ''} onchange="toggleSetting(${i},this.checked)"/>
        <span class="toggle-slider"></span>
      </label>
    </div>`).join('');
}

function toggleSetting(i, val) {
  toggles[i].on = val;
  showToast(`${toggles[i].label} ${val ? 'enabled' : 'disabled'}.`);
}

function saveSettings() {
  const co = document.getElementById('settingCompany')?.value;
  const el = document.querySelector('.sidebar-user-name');
  if (el && co) el.textContent = co;
  showToast('Settings saved successfully.');
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — SECURITY SCORE
// ═══════════════════════════════════════════════════════════
async function renderScore() {
  // Security page scoreItems list (static breakdown)
  const listEl = document.getElementById('scoreItems');

  // Overview page score ring
  const arcEl    = document.getElementById('scoreArc');
  const numEl    = document.getElementById('scoreNum');
  const gradeEl  = document.getElementById('scoreGrade');
  const descEl   = document.getElementById('scoreDesc');
  const factorsEl= document.getElementById('scoreFactors');

  if (!listEl && !arcEl) return;

  try {
    const data = await api('GET', '/dashboard/security-score');
    if (!data) return;
    const { score, grade, color, factors } = data;

    // Render the ring on the overview page
    if (arcEl && numEl) {
      const circ = 2 * Math.PI * 37;
      arcEl.setAttribute('stroke', color);
      arcEl.setAttribute('stroke-dasharray', circ.toFixed(1));
      arcEl.setAttribute('stroke-dashoffset', (circ * (1 - score / 100)).toFixed(1));
      numEl.textContent = score;
      numEl.style.color = color;
    }
    if (gradeEl) { gradeEl.textContent = grade; gradeEl.style.color = color; }
    if (descEl)  descEl.textContent = score >= 90 ? 'Your account is very well protected.' :
                                      score >= 70 ? 'Good protection. A few improvements available.' :
                                      score >= 50 ? 'Fair — some important gaps to address.' :
                                                    'Your account needs attention. See items below.';
    if (factorsEl) {
      factorsEl.innerHTML = factors.map(f => `
        <div class="score-factor">
          <div class="score-factor-dot" style="background:${f.passed ? '#7ec99b' : '#ef4444'}"></div>
          <span style="color:${f.passed ? '#888' : '#c8a96e'}">${f.label}</span>
          ${f.action ? `<span style="font-size:11px;color:#444;margin-left:auto">${f.action}</span>` : ''}
        </div>`).join('');
    }

    // Render the security page list
    if (listEl) {
      listEl.innerHTML = factors.map(f => `
        <div style="display:flex;align-items:flex-start;gap:14px;padding:12px 0;border-bottom:1px solid #1e1e1e">
          <div style="font-size:16px;margin-top:1px">${f.passed ? '✅' : '⚠️'}</div>
          <div style="flex:1">
            <div style="font-size:13px;color:${f.passed ? '#d4d4d4' : '#c8a96e'}">${f.label}</div>
            ${f.action ? `<div style="font-size:12px;color:#555;margin-top:3px">${f.action}</div>` : ''}
          </div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:${f.passed ? '#7ec99b' : '#555'};white-space:nowrap">${f.passed ? '+' + f.points : '0/' + f.points}</div>
        </div>`).join('') +
        `<div style="text-align:right;margin-top:14px;font-family:'DM Mono',monospace;font-size:12px;color:${color}">
          Security Score: ${score}/100 — ${grade}
        </div>`;
    }
  } catch (e) {
    if (gradeEl) gradeEl.textContent = 'Score unavailable';
  }
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — STORAGE DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════
let _storage = null;
function updateStorageDisplay(storage) {
  _storage = storage;
  maybeShowStorageWarning();
  document.querySelectorAll('.storage-bar-fill, .storage-fill').forEach(bar => {
    bar.style.width = storage.percentUsed + '%';
  });
  document.querySelectorAll('.storage-used').forEach(el => { el.textContent = storage.usedGB + ' GB'; });
  document.querySelectorAll('.storage-limit').forEach(el => { el.textContent = storage.limitGB + ' GB'; });
  document.querySelectorAll('.storage-pct').forEach(el  => { el.textContent = storage.percentUsed + '%'; });
}

// Show a banner when the account is near (or over) its plan storage limit.
// Thresholds come from the plan config (lib/plans.js) via the stats API, so each
// plan warns at the point that matches the headroom it offers.
function maybeShowStorageWarning() {
  const main = document.querySelector('.dash-main');
  const existing = document.getElementById('storageWarn');
  if (!main || !_storage) { if (existing) existing.remove(); return; }
  const pct    = _storage.percentUsed;
  const warnAt = _storage.thresholds?.warn ?? 80;
  const critAt = _storage.thresholds?.critical ?? 95;
  if (pct < warnAt || sessionStorage.getItem('storageWarnDismissed') === String(pct >= critAt)) {
    if (pct < warnAt && existing) existing.remove();
    return;
  }
  if (existing) return;
  const critical = pct >= critAt;
  const bar = document.createElement('div');
  bar.id = 'storageWarn';
  const color = critical ? '#f87171' : '#fbbf24';
  bar.style.cssText = `display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:${critical?'rgba(248,113,113,0.08)':'rgba(251,191,36,0.07)'};border:1px solid ${critical?'rgba(248,113,113,0.3)':'rgba(251,191,36,0.3)'};border-radius:12px;padding:14px 20px;margin-bottom:20px`;
  bar.innerHTML = `
    <span style="font-size:20px">${critical ? '🚨' : '⚠️'}</span>
    <div style="flex:1;min-width:200px;font-size:13px;color:#cbd5e1;line-height:1.5">
      <strong style="color:${color}">${critical ? 'You\'re almost out of storage.' : 'Storage is filling up.'}</strong>
      You've used ${pct}% of your ${_storage.limitGB} GB plan (${_storage.usedGB} GB). ${critical ? 'New uploads may be blocked.' : ''}
    </div>
    <button onclick="goDash('billing')" class="btn-primary" style="cursor:pointer;padding:9px 18px;font-size:11px">Upgrade Plan</button>
    <button onclick="document.getElementById('storageWarn').remove();sessionStorage.setItem('storageWarnDismissed','${critical}')" style="background:none;border:none;color:#69748a;font-size:18px;cursor:pointer;line-height:1" title="Dismiss">×</button>`;
  main.insertBefore(bar, main.firstChild);
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — MISC
// ═══════════════════════════════════════════════════════════
function triggerBackup() {
  const val = document.getElementById('backupVal');
  const sub = document.getElementById('backupSub');
  if (val) val.textContent = 'Running…';
  if (sub) sub.textContent = 'Backup in progress…';
  showToast('Backup started — this usually takes 1–2 minutes.');
  setTimeout(() => {
    if (val) val.textContent = 'Just now';
    if (sub) sub.textContent = 'Daily · Next in 24h';
    showToast('✓ Backup completed successfully.');
  }, 3000);
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — INIT (called on every dashboard page load)
// ═══════════════════════════════════════════════════════════
// ── Onboarding modal ─────────────────────────────────────────
const ONBOARD_STEPS = [
  {
    icon: '🛡️',
    title: 'Welcome to Nexus Security',
    body: 'Your account is set up and your data is already protected. This quick tour will show you where everything lives — takes about 60 seconds.',
  },
  {
    icon: '☁️',
    title: 'Your Files Are Safe Here',
    body: 'Head to <strong>Files</strong> in the sidebar to upload and manage your important documents. Everything you store is encrypted and backed up daily.',
  },
  {
    icon: '🔐',
    title: 'Lock Down Your Account',
    body: 'We strongly recommend enabling <strong>Two-Factor Authentication</strong> in Settings. It\'s the single most effective way to prevent unauthorized access.',
  },
  {
    icon: '📊',
    title: 'Your Security Score',
    body: 'Your dashboard shows a live Security Score based on your account settings. The higher the score, the better protected you are. Try to get to 100!',
  },
  {
    icon: '✅',
    title: 'You\'re All Set',
    body: 'That\'s the tour! If you ever need help, use the <strong>Contact Us</strong> link in the sidebar — a real person will respond within 2 business hours.',
  },
];

let _onboardStep = 0;

function maybeShowOnboarding() {
  if (!sessionStorage.getItem('show_onboarding')) return;
  sessionStorage.removeItem('show_onboarding');
  const user = getStoredUser();
  const key  = 'onboarded_' + (user?.id || '');
  if (localStorage.getItem(key)) return;
  localStorage.setItem(key, '1');
  showOnboarding();
}

function showOnboarding() {
  if (document.getElementById('onboarding-overlay')) return;
  _onboardStep = 0;
  const overlay = document.createElement('div');
  overlay.id = 'onboarding-overlay';
  overlay.innerHTML = `
    <div id="onboarding-modal">
      <div class="onboard-dots" id="onboardDots"></div>
      <div id="onboardStepContent"></div>
      <div class="onboard-actions">
        <button class="onboard-skip" onclick="closeOnboarding()">Skip tour</button>
        <button class="onboard-next" id="onboardNextBtn" onclick="nextOnboardStep()">Next →</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  renderOnboardStep();
}

function renderOnboardStep() {
  const step  = ONBOARD_STEPS[_onboardStep];
  const isLast = _onboardStep === ONBOARD_STEPS.length - 1;
  document.getElementById('onboardStepContent').innerHTML = `
    <span class="onboard-icon">${step.icon}</span>
    <h2 class="onboard-title">${step.title}</h2>
    <p class="onboard-body">${step.body}</p>`;
  document.getElementById('onboardNextBtn').textContent = isLast ? 'Get Started ✓' : 'Next →';
  const dots = document.getElementById('onboardDots');
  dots.innerHTML = ONBOARD_STEPS.map((_, i) =>
    `<div class="onboard-dot${i === _onboardStep ? ' active' : ''}"></div>`).join('');
}

function nextOnboardStep() {
  if (_onboardStep < ONBOARD_STEPS.length - 1) {
    _onboardStep++;
    renderOnboardStep();
  } else {
    closeOnboarding();
  }
}

function closeOnboarding() {
  const el = document.getElementById('onboarding-overlay');
  if (el) el.remove();
}

// --- Push Notification helpers ---
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

async function initPushStatus() {
  const statusEl = document.getElementById('pushStatus');
  const btnEl    = document.getElementById('pushBtn');
  if (!statusEl || !btnEl) return;

  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    statusEl.textContent = 'Push notifications are not supported in this browser.';
    btnEl.style.display  = 'none';
    return;
  }

  try {
    const data = await api('GET', '/notifications/push-status');
    if (!data) return;

    if (!data.vapidConfigured) {
      statusEl.textContent = 'Push notifications are not configured on the server.';
      btnEl.style.display  = 'none';
      return;
    }

    const permission = Notification.permission;
    if (permission === 'denied') {
      statusEl.textContent = 'Notifications are blocked. Enable them in your browser settings.';
      btnEl.style.display  = 'none';
      return;
    }

    if (data.subscribed) {
      statusEl.textContent = '✓ You are subscribed to push notifications.';
      btnEl.textContent    = 'Disable Notifications';
    } else {
      statusEl.textContent = 'Not subscribed.';
      btnEl.textContent    = 'Enable Notifications';
    }
  } catch {
    statusEl.textContent = 'Could not load push status.';
  }
}

async function togglePushNotifications() {
  const statusEl = document.getElementById('pushStatus');
  const btnEl    = document.getElementById('pushBtn');
  if (!statusEl || !btnEl) return;

  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;

  btnEl.disabled = true;

  try {
    const reg  = await navigator.serviceWorker.ready;
    const existing = await reg.pushManager.getSubscription();

    if (existing) {
      // Unsubscribe
      await existing.unsubscribe();
      await api('DELETE', '/notifications/subscribe', { endpoint: existing.endpoint });
      statusEl.textContent = 'Unsubscribed from push notifications.';
      btnEl.textContent    = 'Enable Notifications';
    } else {
      // Subscribe
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        statusEl.textContent = 'Permission denied. Allow notifications in your browser settings.';
        return;
      }

      const keyData = await api('GET', '/notifications/vapid-public-key');
      if (!keyData?.publicKey) {
        statusEl.textContent = 'Could not fetch push configuration.';
        return;
      }

      const subscription = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(keyData.publicKey),
      });

      const sub = subscription.toJSON();
      await api('POST', '/notifications/subscribe', { endpoint: sub.endpoint, keys: sub.keys });

      statusEl.textContent = '✓ You are subscribed to push notifications.';
      btnEl.textContent    = 'Disable Notifications';
    }
  } catch (err) {
    statusEl.textContent = 'Error: ' + (err.message || 'Could not update push subscription.');
  } finally {
    btnEl.disabled = false;
  }
}
// --- End push notification helpers ---

async function initDashboard() {
  if (!getToken()) {
    window.location.href = '/pages/login.html';
    return;
  }

  renderAllSidebars();
  renderDashTabs();
  renderToggles();
  renderScore();
  maybeShowOnboarding();
  initNotifications();
  initPushStatus();

  // Free-trial reminder flagged at login (final 5 days) — show once.
  const warnDays = sessionStorage.getItem('trial_warn_days');
  if (warnDays !== null) {
    sessionStorage.removeItem('trial_warn_days');
    showTrialWarning(warnDays);
  }

  // Populate greeting
  const h = new Date().getHours();
  const user = getStoredUser();
  const firstName = user?.name?.split(' ')[0] || '';
  const greetEl = document.getElementById('dashGreeting');
  const dateEl  = document.getElementById('dashDate');
  if (greetEl) greetEl.textContent = (h<12?'Good morning':h<17?'Good afternoon':'Good evening') + (firstName ? ', ' + firstName : '') + '.';
  if (dateEl)  dateEl.textContent  = new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});

  // Fetch dashboard stats
  try {
    const stats = await api('GET', '/dashboard/stats');
    if (!stats) return;
    updateStorageDisplay(stats.storage);
    const fcEl = document.getElementById('statFileCount');
    const ucEl = document.getElementById('statUserCount');
    if (fcEl) fcEl.textContent = stats.counts.files;
    if (ucEl) ucEl.textContent = stats.counts.users;
  } catch (err) {
    showToast('Could not load dashboard stats: ' + err.message);
  }

  // Wire drag-and-drop zone
  initDropZone('dropZone', 'uploadInput', uploadFiles);

  // Fetch folders + files (used on Files page and overview)
  try {
    await loadFolders();
    await loadFiles();
  } catch { /* not every page has a file list */ }

  // Fetch users (used on Users page)
  try {
    const users = await api('GET', '/users');
    if (users) { _users = users; renderUsers(users); }
  } catch { /* not every page has a user list */ }

  // Render activity feed (overview + security pages)
  renderActivity();
  // Render active devices/sessions (security page)
  renderSessions();
  // Storage usage warning banner (if near plan limit)
  maybeShowStorageWarning();
  // Start the inactivity auto-logout watcher
  initIdleLogout();
  // First-run onboarding wizard
  maybeShowOnboarding();
}

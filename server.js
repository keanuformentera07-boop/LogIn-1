const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const API_USERS_URL = 'https://event-driven-user-api.onrender.com/users'; // tracking params (?fbclid=...) removed
const API_TIMEOUT_MS = 40000;          // Render free tier may need time to wake up
const OTP_TTL_MS = 30 * 1000;          // OTP expires after 30 seconds
const OTP_MAX_TRIES = 5;
const OTP_RESEND_AFTER_MS = 10 * 1000;
const DEV_SHOW_OTP = process.env.DEV_SHOW_OTP !== 'false'; // DEMO: show OTP on screen. Set DEV_SHOW_OTP=false in production.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const app = express();
app.set('trust proxy', 1); // needed behind Render's proxy
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 60 * 1000 },
}));

// ---------- Helpers ----------
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  return req.session.csrf;
}
function csrfOk(req) {
  const a = Buffer.from(String(req.body.csrf || ''));
  const b = Buffer.from(String(req.session.csrf || ''));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}
const safeEqual = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

// API fields are capitalised ("Email", "Password"), so read keys case-insensitively
const uget = (u, key) => {
  const k = Object.keys(u || {}).find((k) => k.toLowerCase() === key.toLowerCase());
  return k !== undefined && u[k] != null ? String(u[k]) : null;
};

async function fetchUsers() {
  try {
    const res = await fetch(API_USERS_URL, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(API_TIMEOUT_MS) });
    if (!res.ok) return { error: `API returned HTTP ${res.status}` };
    let data = await res.json();
    if (!Array.isArray(data)) data = data.users || data.data;
    if (!Array.isArray(data)) return { error: 'API returned an unexpected format' };
    return { users: data };
  } catch (err) {
    return { error: `API connection failed: ${err.name === 'TimeoutError' ? 'timed out' : err.message}` };
  }
}

const findUser = (users, login) =>
  users.find((u) => ['email', 'username'].some((f) => (uget(u, f) || '').toLowerCase() === login.toLowerCase()));

// ---------- OTP ----------
function issueOtp(req) {
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const salt = crypto.randomBytes(16).toString('hex');
  req.session.otp = {
    salt,
    hash: crypto.createHash('sha256').update(salt + otp).digest('hex'),
    expires: Date.now() + OTP_TTL_MS,
    issued: Date.now(),
    tries: 0,
  };
  if (DEV_SHOW_OTP) req.session.devOtp = otp;
  // TODO: real delivery (email via nodemailer / SMS provider) to the user's Email here.
}
function checkOtp(req, input) {
  const o = req.session.otp;
  if (!o) return [false, 'No OTP pending. Please log in again.'];
  if (Date.now() > o.expires) { delete req.session.otp; return [false, 'OTP expired. Request a new one.']; }
  if (o.tries >= OTP_MAX_TRIES) { delete req.session.otp; return [false, 'Too many attempts. Request a new OTP.']; }
  o.tries += 1;
  const hash = crypto.createHash('sha256').update(o.salt + input).digest('hex');
  if (!safeEqual(hash, o.hash)) return [false, 'Incorrect OTP.'];
  delete req.session.otp; delete req.session.devOtp; // single use
  return [true, ''];
}

const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));

// ---------- Views ----------
const css = `body{font-family:system-ui,sans-serif;background:#f3f4f6;display:grid;place-items:center;min-height:100vh;margin:0}
.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 20px #0001;width:min(360px,92vw)}
h1{font-size:1.3rem;margin:0 0 1rem}label{display:block;font-size:.85rem;margin:.8rem 0 .25rem}
input{width:100%;padding:.6rem;border:1px solid #ccd;border-radius:8px;box-sizing:border-box;font-size:1rem}
button{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:8px;background:#2563eb;color:#fff;font-size:1rem;cursor:pointer}
button.alt{background:#e5e7eb;color:#111}button:disabled{opacity:.5;cursor:not-allowed}
.err{background:#fee2e2;color:#991b1b;padding:.6rem;border-radius:8px;margin-bottom:.8rem;font-size:.9rem}
.note{background:#fef9c3;padding:.6rem;border-radius:8px;font-size:.85rem;margin-bottom:.8rem}
.timer{text-align:center;font-weight:600;margin-top:.8rem}`;
const page = (title, body, script = '') => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${css}</style></head><body>${body}${script}</body></html>`;

const loginPage = (req, error = '', login = '') => page('Login', `
<form class="card" method="post" action="/login" novalidate>
  <h1>Sign in</h1>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <input type="hidden" name="csrf" value="${csrfToken(req)}">
  <label for="login">Email or username</label>
  <input id="login" name="login" value="${esc(login)}" autocomplete="username" required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Continue</button>
</form>`);

const verifyPage = (req, error = '') => {
  const remaining = req.session.otp ? Math.max(0, Math.ceil((req.session.otp.expires - Date.now()) / 1000)) : 0;
  return page('Verify OTP', `
<form class="card" method="post" action="/verify">
  <h1>Enter verification code</h1>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  ${DEV_SHOW_OTP && req.session.devOtp ? `<div class="note">Demo mode – your OTP is <b>${esc(req.session.devOtp)}</b></div>` : ''}
  <input type="hidden" name="csrf" value="${csrfToken(req)}">
  <label for="otp">6-digit code</label>
  <input id="otp" name="otp" inputmode="numeric" maxlength="6" pattern="\\d{6}" autocomplete="one-time-code" autofocus>
  <div class="timer">Expires in <span id="t">${remaining}</span>s</div>
  <button id="verify" type="submit">Verify</button>
  <button class="alt" type="submit" name="resend" value="1" formaction="/resend" formnovalidate>Resend code</button>
</form>`, `<script>
let s=${remaining};const t=document.getElementById('t'),v=document.getElementById('verify');
const tick=()=>{t.textContent=s;if(s<=0){v.disabled=true;t.parentElement.textContent='Code expired – request a new one.';clearInterval(i);}s--;};
const i=setInterval(tick,1000);tick();</script>`);
};

// ---------- Routes ----------
app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

app.get('/login', (req, res) => res.send(loginPage(req)));

app.post('/login', async (req, res) => {
  const login = String(req.body.login || '').trim();
  const password = String(req.body.password || '');
  const fail = (msg) => res.status(400).send(loginPage(req, msg, login));

  if (!csrfOk(req)) return fail('Invalid request. Refresh and try again.');
  if (!login || !password) return fail('Email/username and password are required.');
  if (login.length > 254 || password.length > 128) return fail('Input too long.');
  if (login.includes('@') && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login)) return fail('Invalid email format.');
  if (password.length < 6) return fail('Password must be at least 6 characters.');

  const { users, error } = await fetchUsers();
  if (error) return res.status(502).send(loginPage(req, error, login));

  const user = findUser(users, login);
  const stored = user ? uget(user, 'password') : null;
  // Same message for unknown user / wrong password (no account enumeration)
  if (!user || stored === null || !safeEqual(password, stored)) return fail('Invalid credentials.');

  // Password OK, but NOT logged in until the OTP passes
  const pending = Object.fromEntries(Object.entries(user).filter(([k]) => k.toLowerCase() !== 'password'));
  await regenerate(req);
  req.session.pendingUser = pending;
  issueOtp(req);
  res.redirect('/verify');
});

app.get('/verify', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');
  res.send(verifyPage(req));
});

app.post('/verify', async (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');
  if (!csrfOk(req)) return res.status(400).send(verifyPage(req, 'Invalid request.'));
  const code = String(req.body.otp || '').replace(/\D/g, '');
  if (code.length !== 6) return res.status(400).send(verifyPage(req, 'Enter the 6-digit code.'));

  const [ok, msg] = checkOtp(req, code);
  if (!ok) return res.status(400).send(verifyPage(req, msg));

  const user = req.session.pendingUser;
  await regenerate(req);
  req.session.user = user;
  res.redirect('/dashboard');
});

app.post('/resend', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');
  if (!csrfOk(req)) return res.status(400).send(verifyPage(req, 'Invalid request.'));
  const o = req.session.otp;
  if (o && Date.now() - o.issued < OTP_RESEND_AFTER_MS) return res.status(429).send(verifyPage(req, 'Please wait a few seconds before resending.'));
  issueOtp(req);
  res.redirect('/verify');
});

app.get('/dashboard', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/login');
  res.send(page('Dashboard', `<div class="card"><h1>Welcome, ${esc(uget(u, 'FirstName') || uget(u, 'username') || uget(u, 'Email') || 'user')}</h1>
<p>You are signed in with multi-factor authentication.</p><a href="/logout">Log out</a></div>`));
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
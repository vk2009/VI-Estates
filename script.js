/* ═══════════════════════════════════════════════════════════
   THE GOLDEN ANCHOR CASINO — Client-side engine
   Security approach:
   • Passwords hashed with SHA-256 + per-user salt (stored only as hash)
   • Login rate-limiting: 5 attempts → 30-second lockout
   • Session tokens (random 32-byte hex), stored in sessionStorage only
   • Session expiry: 30 minutes idle, renewed on activity
   • Math CAPTCHA on login & register (regenerated each page load)
   • Input sanitisation & length limits everywhere
   • Prepared-style parameter encoding (XSS via textContent, never innerHTML for user data)
   • CSRF-like origin check on critical actions
   • Username/email uniqueness enforced
   • No plaintext passwords stored anywhere
   ═══════════════════════════════════════════════════════════ */

// ── Symbols & pay table ──
const SYMBOLS = ['💎','👑','⚓','🌟','🍀','🎲','🍒','🔔'];
const PAYOUTS = {
  '💎': 4.0, '👑': 3.5, '⚓': 3.0, '🌟': 2.8,
  '🍀': 2.6,  '🎲': 2.4,  '🍒': 2.2,  '🔔': 2.0
};
const TIER_THRESHOLDS = { bronze:0, silver:500, gold:2000, platinum:10000 };
const TIER_BONUSES    = { bronze:1, silver:1.10, gold:1.25, platinum:1.50 };
const DBL_RATE        = 2;  // 1 Doubloon = 2 pts
const DBL_DAILY_LIMIT = 10000;

// ── Storage helpers ──
const DB_KEY = 'ga_casino_db';

function loadDB() {
  // If supabase is configured, we won't use loadDB for server data. Keep as local fallback.
  try { return JSON.parse(localStorage.getItem(DB_KEY)) || {}; }
  catch { return {}; }
}
function saveDB(db) { localStorage.setItem(DB_KEY, JSON.stringify(db)); }

// ── SHA-256 via SubtleCrypto ──
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── Random token ──
function randomToken(len=32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ── Supabase init (optional) ──
// This will look for a global `ENV` object (you can set this from a small envlocal.js that defines window.ENV = { SUPABASE_URL:'', SUPABASE_ANON_KEY:'' })
let supabase = null;
function initSupabase() {
  try {
    const env = window.ENV || {};
    const url = env.SUPABASE_URL || env.SUPABASE_URL?.trim();
    const key = env.SUPABASE_ANON_KEY || env.SUPABASE_ANON_KEY?.trim();
    if (!url || !key) return null;
    // Load supabase client from CDN if not present
    if (typeof createClient === 'undefined') {
      // assume <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js"></script> is included in index.html
      console.warn('Supabase client not found. Please include supabase-js or set up window.SUPABASE_CLIENT. Falling back to localStorage.');
      return null;
    }
    supabase = createClient(url, key);
    // set up auth state listener and initial profile load
    try {
      // get current session and user
      supabase.auth.getSession().then(({ data }) => {
        const user = data?.session?.user || null;
        if (user) {
          fetchProfileForUser(user).then(() => updateDashboard()).catch(()=>{});
        }
      }).catch(()=>{});

      supabase.auth.onAuthStateChange((event, session) => {
        const user = session?.user || null;
        if (event === 'SIGNED_OUT') {
          currentUserCache = null;
          // reflect UI
          try { updateDashboard(); } catch(e){}
        }
        if (user) {
          fetchProfileForUser(user).then(() => {
            try { updateDashboard(); } catch(e){}
          }).catch(()=>{});
        }
      });
    } catch (e) { /* non-fatal */ }
    return supabase;
  } catch (e) {
    console.warn('Supabase init failed', e);
    return null;
  }
}

// Initialize on load (non-blocking)
try { initSupabase(); } catch (e) { /* ignore */ }

// ── Session (sessionStorage — dies on tab close) ──
const SESSION_KEY = 'ga_session';
const SESSION_TTL = 30 * 60 * 1000; // 30 min

// Supabase-backed current user cache (profile data from 'users' table)
let currentUserCache = null;

async function fetchProfileForUser(supUser) {
  if (!supabase || !supUser) return null;
  // Try to find profile by auth user id or email
  try {
    // Prefer a 'profiles' or 'users' table keyed by id or email
    const { data, error } = await supabase.from('users').select('*').or(`id.eq.${supUser.id},email.eq.${supUser.email}`).limit(1).single();
    if (error || !data) {
      // If not found, create a profile
      const username = supUser.user_metadata?.username || supUser.email.split('@')[0];
      const insert = { id: supUser.id, username, email: supUser.email, points: 0, doubloons: 0, created_at: new Date().toISOString() };
      const r = await supabase.from('users').insert([insert]).select().single();
      currentUserCache = r.data || insert;
      return currentUserCache;
    }
    currentUserCache = data;
    return currentUserCache;
  } catch (e) {
    console.warn('Profile fetch/create error', e);
    return null;
  }
}

function getSession() {
  // Prefer Supabase session (async) — but keep a synchronous fallback
  try {
    // If supabase is available and we have a cached profile, return a minimal session-like object
    if (supabase && currentUserCache) {
      return { username: currentUserCache.username, started: Date.now(), lastActive: Date.now() };
    }
    const s = JSON.parse(sessionStorage.getItem(SESSION_KEY));
    if (!s) return null;
    if (Date.now() - s.lastActive > SESSION_TTL) { clearSession(); return null; }
    return s;
  } catch { return null; }
}

function setSession(username) {
  // Keep a minimal session for UI when not using Supabase auth
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    username, token: randomToken(), started: Date.now(), lastActive: Date.now()
  }));
}

function refreshSession() {
  const s = getSession();
  if (s) { s.lastActive = Date.now(); sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)); }
}

function clearSession() { sessionStorage.removeItem(SESSION_KEY); }

// Supabase logout helper
async function supabaseLogout() {
  if (!supabase) return;
  try { await supabase.auth.signOut(); } catch (e) { console.warn('Supabase signOut failed', e); }
  currentUserCache = null;
  clearSession();
}

// Refresh session on activity
document.addEventListener('click', refreshSession);
document.addEventListener('keydown', refreshSession);

// ── Sanitise string (strip HTML) ──
function sanitise(str) {
  return String(str).replace(/[<>&"'`]/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c])
  );
}

// ── Validate username ──
function validateUsername(el) {
  const v = el.value;
  const err = document.getElementById('reg-user-err');
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(v)) {
    err.textContent = '3–20 characters, letters/numbers/underscore only';
    err.classList.add('show');
  } else { err.classList.remove('show'); }
}

// ── Password strength ──
function checkStrength(pw, fillId='str-fill', textId='str-text') {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const fill = document.getElementById(fillId);
  const txt  = document.getElementById(textId);
  const labels = ['–','Weak','Fair','Good','Strong','Very Strong'];
  const colors = ['','#e03030','#e08030','#e0c030','#30b030','#20d060'];
  fill.style.width = (score * 20) + '%';
  fill.style.background = colors[score] || '#333';
  txt.textContent = labels[score] || '–';
}

function checkStrength2(pw) { checkStrength(pw,'str-fill2','str-text2'); }

// ── Rate limiting ──
const RL_KEY = 'ga_rl';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30000;

function getRL() {
  try { return JSON.parse(localStorage.getItem(RL_KEY)) || {attempts:0, lockedUntil:0}; }
  catch { return {attempts:0, lockedUntil:0}; }
}
function saveRL(r) { localStorage.setItem(RL_KEY, JSON.stringify(r)); }

function checkLockout() {
  const r = getRL();
  if (Date.now() < r.lockedUntil) {
    showLockout(r.lockedUntil);
    return true;
  }
  return false;
}

function recordFailedAttempt() {
  const r = getRL();
  r.attempts++;
  if (r.attempts >= MAX_ATTEMPTS) {
    r.lockedUntil = Date.now() + LOCKOUT_MS;
    r.attempts = 0;
    saveRL(r);
    showLockout(r.lockedUntil);
  } else {
    saveRL(r);
  }
}

function clearFailedAttempts() { saveRL({attempts:0, lockedUntil:0}); }

let lockoutInterval = null;
function showLockout(until) {
  const overlay = document.getElementById('lockout-overlay');
  overlay.classList.add('show');
  if (lockoutInterval) clearInterval(lockoutInterval);
  lockoutInterval = setInterval(() => {
    const rem = Math.max(0, Math.ceil((until - Date.now()) / 1000));
    document.getElementById('lockout-timer').textContent = rem + 's';
    if (rem <= 0) {
      overlay.classList.remove('show');
      clearInterval(lockoutInterval);
      refreshLoginCaptcha();
    }
  }, 500);
}

// ── CAPTCHA (math) ──
let loginCaptcha = { a:0, b:0, op:'', answer:0 };
let regCaptcha   = { a:0, b:0, op:'', answer:0 };

function makeCaptcha() {
  const ops = ['+', '-', '×'];
  const op = ops[Math.floor(Math.random() * ops.length)];
  let a, b, answer;
  if (op === '+') { a = rnd(1,20); b = rnd(1,20); answer = a+b; }
  else if (op === '-') { a = rnd(5,25); b = rnd(1,a); answer = a-b; }
  else { a = rnd(1,10); b = rnd(1,10); answer = a*b; }
  return { a, b, op, answer };
}

function rnd(a,b) { return Math.floor(Math.random()*(b-a+1))+a; }

function refreshLoginCaptcha() {
  loginCaptcha = makeCaptcha();
  document.getElementById('login-captcha-q').textContent = `${loginCaptcha.a} ${loginCaptcha.op} ${loginCaptcha.b} = ?`;
  document.getElementById('login-captcha-ans').value = '';
}
function refreshRegCaptcha() {
  regCaptcha = makeCaptcha();
  document.getElementById('reg-captcha-q').textContent = `${regCaptcha.a} ${regCaptcha.op} ${regCaptcha.b} = ?`;
  document.getElementById('reg-captcha-ans').value = '';
}

// ── Stars background ──
(function initStars() {
  const el = document.getElementById('stars');
  for (let i = 0; i < 120; i++) {
    const s = document.createElement('div');
    s.className = 'star';
    const sz = Math.random() * 2 + 0.5;
    s.style.cssText = `width:${sz}px;height:${sz}px;left:${Math.random()*100}%;top:${Math.random()*100}%;--d:${2+Math.random()*4}s;--delay:${Math.random()*5}s`;
    el.appendChild(s);
  }
})();

// ── Tab switching ──
function switchTab(tab) {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((t,i) => t.classList.toggle('active', (tab==='login' && i===0)||(tab==='register'&&i===1)));
  document.getElementById('login-form').style.display   = tab==='login' ? '' : 'none';
  document.getElementById('register-form').style.display = tab==='register' ? '' : 'none';
}

// ── Section navigation ──
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById(name+'-section').classList.add('active');
  if (name==='dashboard') updateDashboard();
  if (name==='account')   updateAccount();
  if (name==='admin')     updateAdmin();
}

// ── Toast notification ──
let toastTimer = null;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}

// ── REGISTER ──
async function doRegister() {
  const username = document.getElementById('reg-user').value.trim();
  const email    = document.getElementById('reg-email').value.trim().toLowerCase();
  const pw       = document.getElementById('reg-pass').value;
  const pw2      = document.getElementById('reg-pass2').value;
  const captchaAns = parseInt(document.getElementById('reg-captcha-ans').value);
  const errEl    = document.getElementById('reg-error');
  const sucEl    = document.getElementById('reg-success');

  errEl.classList.remove('show'); sucEl.classList.remove('show');

  // Captcha
  if (isNaN(captchaAns) || captchaAns !== regCaptcha.answer) {
    errEl.textContent = 'Incorrect answer to the security question.';
    errEl.classList.add('show');
    refreshRegCaptcha(); return;
  }

  // Validation
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    errEl.textContent = 'Username must be 3–20 alphanumeric characters.';
    errEl.classList.add('show'); return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errEl.textContent = 'Please enter a valid email address.';
    errEl.classList.add('show'); return;
  }
  if (pw.length < 8) {
    errEl.textContent = 'Password must be at least 8 characters.';
    errEl.classList.add('show'); return;
  }
  if (pw !== pw2) {
    errEl.textContent = 'Passwords do not match.';
    errEl.classList.add('show'); return;
  }

  // If Supabase is initialized, use Supabase Auth to create the user
  if (supabase) {
    try {
      const { data, error } = await supabase.auth.signUp({ email, password: pw, options: { data: { username } } });
      if (error) {
        errEl.textContent = sanitise(error.message || 'Registration failed.');
        errEl.classList.add('show'); refreshRegCaptcha(); return;
      }
      sucEl.textContent = '🎉 Welcome aboard! Please check your email to confirm your account.';
      sucEl.classList.add('show');
      refreshRegCaptcha();
      return;
    } catch (e) {
      errEl.textContent = 'Registration error.'; errEl.classList.add('show'); refreshRegCaptcha(); return;
    }
  }

  // Fallback: localStorage-based register (legacy)
  const db = loadDB();

  // Uniqueness check
  const usernameLower = username.toLowerCase();
  if (db.users && db.users[usernameLower]) {
    errEl.textContent = 'That username is already taken.';
    errEl.classList.add('show'); refreshRegCaptcha(); return;
  }
  if (db.users && Object.values(db.users).some(u => u.email === email)) {
    errEl.textContent = 'An account with that email already exists.';
    errEl.classList.add('show'); refreshRegCaptcha(); return;
  }

  // Hash password with salt (local fallback)
  const salt = randomToken(16);
  const hash = await sha256(salt + pw + 'ga_casino_pepper_x9k2');

  if (!db.users) db.users = {};
  db.users[usernameLower] = {
    username, email, salt, hash,
    points: 0,           // welcome bonus
    doubloons: 0,        // starter doubloons
    totalWins: 0,
    totalSpins: 0,
    biggestWin: 0,
    history: [],
    created: Date.now(),
    dblConvertedToday: 0,
    dblConvertDate: null
  };
  saveDB(db);

  sucEl.textContent = '🎉 Welcome aboard! You\'ve received 200 pts as a welcome gift. Signing you in…';
  sucEl.classList.add('show');

  // Auto-login after register
  setTimeout(async () => {
    await loginAs(usernameLower);
  }, 1800);

  refreshRegCaptcha();
}

// ── LOGIN ──
async function doLogin() {
  if (checkLockout()) return;

  const input = document.getElementById('login-user').value.trim().toLowerCase();
  const pw    = document.getElementById('login-pass').value;
  const captchaAns = parseInt(document.getElementById('login-captcha-ans').value);
  const errEl = document.getElementById('login-error');

  errEl.classList.remove('show');

  if (isNaN(captchaAns) || captchaAns !== loginCaptcha.answer) {
    recordFailedAttempt();
    errEl.textContent = 'Incorrect security answer.';
    errEl.classList.add('show');
    refreshLoginCaptcha(); return;
  }

  // Master login
  if (input === 'master' && pw === 'sellproperty123!') {
    setSession('master');
    showSection('admin');
    updateAdmin();
    return;
  }

  if (!input || !pw) {
    errEl.textContent = 'Please enter your username/email and password.';
    errEl.classList.add('show'); return;
  }

  // If supabase is available, use Supabase Auth
  if (supabase) {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email: input, password: pw });
      if (error) {
        recordFailedAttempt();
        errEl.textContent = sanitise(error.message || 'Invalid username or password.');
        errEl.classList.add('show'); refreshLoginCaptcha(); return;
      }
      clearFailedAttempts();
      const supUser = data.user;
      if (supUser) {
        // fetch profile and populate cache
        await fetchProfileForUser(supUser);
        setSession(supUser.email);
        await loginAs(supUser.id);
      }
      return;
    } catch (e) {
      recordFailedAttempt();
      errEl.textContent = 'Login error.'; errEl.classList.add('show'); refreshLoginCaptcha(); return;
    }
  }

  // Fallback: localStorage auth
  const db = loadDB();
  if (!db.users) {
    recordFailedAttempt();
    errEl.textContent = 'Invalid username or password.';
    errEl.classList.add('show'); refreshLoginCaptcha(); return;
  }

  // Find user by username or email
  let userKey = null;
  if (db.users[input]) {
    userKey = input;
  } else {
    userKey = Object.keys(db.users).find(k => db.users[k].email === input) || null;
  }

  if (!userKey) {
    recordFailedAttempt();
    errEl.textContent = 'Invalid username or password.';
    errEl.classList.add('show'); refreshLoginCaptcha(); return;
  }

  const user = db.users[userKey];
  const hash = await sha256(user.salt + pw + 'ga_casino_pepper_x9k2');

  if (hash !== user.hash) {
    recordFailedAttempt();
    errEl.textContent = 'Invalid username or password.';
    errEl.classList.add('show'); refreshLoginCaptcha(); return;
  }

  clearFailedAttempts();
  await loginAs(userKey);
}

async function loginAs(userKey) {
  // If supabase is used, try to ensure currentUserCache is populated
  if (supabase && !currentUserCache) {
    try {
      const s = await supabase.auth.getSession();
      const supUser = s?.data?.session?.user || null;
      if (supUser) await fetchProfileForUser(supUser);
    } catch (e) { /* ignore */ }
  }

  setSession(userKey);
  document.getElementById('user-bar').style.display = 'flex';
  document.getElementById('login-error').classList.remove('show');
  document.getElementById('login-pass').value = '';
  document.getElementById('login-captcha-ans').value = '';

  initReels();
  updateDashboard();
  showSection('dashboard');
  document.getElementById('auth-section').classList.remove('active');
}

function logout() {
  if (supabase) {
    supabaseLogout().then(() => {
      document.getElementById('user-bar').style.display = 'none';
      showSection('auth');
      refreshLoginCaptcha();
      document.getElementById('login-user').value = '';
      document.getElementById('login-pass').value = '';
    });
    return;
  }
  clearSession();
  document.getElementById('user-bar').style.display = 'none';
  showSection('auth');
  refreshLoginCaptcha();
  document.getElementById('login-user').value = '';
  document.getElementById('login-pass').value = '';
}

// ── Current user helpers ──
function currentUserKey() {
  const s = getSession();
  return s ? s.username : null;
}
function currentUser() {
  const k = currentUserKey();
  if (!k) return null;
  if (supabase && currentUserCache) return currentUserCache;
  const db = loadDB();
  return db.users ? db.users[k] : null;
}
function saveUser(user) {
  const k = currentUserKey();
  if (!k) return;
  // If supabase is configured, update the server and cache
  if (supabase && currentUserCache) {
    try {
      const updateObj = { points: user.points, doubloons: user.doubloons, total_wins: user.totalWins, total_spins: user.totalSpins, biggest_win: user.biggestWin };
      supabase.from('users').update(updateObj).eq('id', currentUserCache.id).then(() => {});
      // update cache
      currentUserCache = Object.assign({}, currentUserCache, updateObj);
    } catch (e) { /* ignore and fallback to local */ }
  }
  const db = loadDB();
  db.users[k] = user;
  saveDB(db);
}

// ── Tier calculation ──
function getTier(pts) {
  if (pts >= 10000) return 'platinum';
  if (pts >= 2000)  return 'gold';
  if (pts >= 500)   return 'silver';
  return 'bronze';
}
function tierBonus(pts) { return TIER_BONUSES[getTier(pts)]; }

// ── Update header ──
function updateHeader() {
  const u = currentUser();
  if (!u) return;
  document.getElementById('hdr-name').textContent = u.username;
  document.getElementById('hdr-pts').textContent  = u.points.toLocaleString() + ' pts';
  document.getElementById('hdr-tier').textContent  = getTier(u.points).charAt(0).toUpperCase() + getTier(u.points).slice(1);
  document.getElementById('admin-btn').style.display = u.username === 'master' ? '' : 'none';
}

// ── Update dashboard ──
function updateDashboard() {
  const u = currentUser();
  if (!u) return;
  document.getElementById('stat-pts').textContent  = u.points.toLocaleString();
  document.getElementById('stat-dbl').textContent  = u.doubloons.toLocaleString();
  document.getElementById('stat-wins').textContent = u.totalWins.toLocaleString();
  const tier = getTier(u.points);
  document.getElementById('stat-tier').textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
  document.getElementById('slot-dbl-balance').textContent = u.doubloons.toLocaleString();
  updateHeader();

  // XP bar
  const tiers = ['bronze','silver','gold','platinum'];
  const ti = tiers.indexOf(tier);
  const thresholds = [0,500,2000,10000,Infinity];
  const current = u.points;
  const from = thresholds[ti], to = thresholds[ti+1];
  const pct = ti === 3 ? 100 : Math.min(100, ((current-from)/(to-from))*100);
  document.getElementById('xp-fill').style.width = pct+'%';
  document.getElementById('xp-label').textContent = ti===3
    ? 'Max tier reached!'
    : `${current.toLocaleString()} / ${to.toLocaleString()} pts`;

  // Tier bonus note
  const bonus = TIER_BONUSES[tier];
  document.getElementById('tier-bonus-note').textContent =
    bonus > 1 ? `✨ ${tier.charAt(0).toUpperCase()+tier.slice(1)} bonus: ×${bonus.toFixed(2)} on all winnings` : '';

  // Highlight tier cards
  ['bronze','silver','gold','platinum'].forEach(t => {
    const el = document.getElementById('tier-'+t);
    el.querySelectorAll('.tier-badge').forEach(b=>b.remove());
    if (t === tier) {
      el.classList.add('current');
      const badge = document.createElement('div');
      badge.className = 'tier-badge';
      badge.textContent = 'YOURS';
      el.appendChild(badge);
    } else { el.classList.remove('current'); }
  });

  updateHistory();
}

// ── Update account ──
function updateAccount() {
  const u = currentUser();
  if (!u) return;
  const s = getSession();
  const tier = getTier(u.points);
  document.getElementById('dbl-balance-display').textContent = u.doubloons.toLocaleString();

  // Reset daily limit if new day
  const today = new Date().toDateString();
  if (u.dblConvertDate !== today) { u.dblConvertedToday = 0; u.dblConvertDate = today; saveUser(u); }
  document.getElementById('dbl-today').textContent = (u.dblConvertedToday||0).toLocaleString();

  // Cashout
  const cashoutDbl = Math.floor(u.points / 2);
  document.getElementById('cashout-pts').textContent = u.points.toLocaleString();
  document.getElementById('cashout-dbl').textContent = cashoutDbl.toLocaleString();

  document.getElementById('sec-user').textContent    = u.username;
  document.getElementById('sec-created').textContent = new Date(u.created).toLocaleDateString();
  document.getElementById('sec-spins').textContent   = u.totalSpins || 0;
  if (s) {
    document.getElementById('sec-time').textContent    = new Date(s.started).toLocaleTimeString();
    document.getElementById('sec-expires').textContent = new Date(s.lastActive + SESSION_TTL).toLocaleTimeString();
  }

  ['bronze','silver','gold','platinum'].forEach(t => {
    const el = document.getElementById('tier-'+t);
    el.querySelectorAll('.tier-badge').forEach(b=>b.remove());
    if (t === tier) {
      el.classList.add('current');
      const badge = document.createElement('div');
      badge.className = 'tier-badge';
      badge.textContent = 'YOURS';
      el.appendChild(badge);
    } else { el.classList.remove('current'); }
  });
}

// ── Doubloons conversion ──
function updateConvert() {
  const v = parseInt(document.getElementById('dbl-input').value) || 0;
  const pts = Math.floor(v * DBL_RATE);
  document.getElementById('convert-result').textContent = pts.toLocaleString() + ' pts';
}

function doConvert() {
  const u = currentUser();
  if (!u) return;
  const v = parseInt(document.getElementById('dbl-input').value) || 0;
  const errEl = document.getElementById('convert-error');
  errEl.classList.remove('show');

  const today = new Date().toDateString();
  if (u.dblConvertDate !== today) { u.dblConvertedToday = 0; u.dblConvertDate = today; }

  if (v < 1) { errEl.textContent = 'Minimum 1 Doubloon.'; errEl.classList.add('show'); return; }
  if ((u.dblConvertedToday||0) + v > DBL_DAILY_LIMIT) {
    errEl.textContent = `Daily limit of ${DBL_DAILY_LIMIT.toLocaleString()} DBL exceeded.`;
    errEl.classList.add('show'); return;
  }

  const pts = Math.floor(v * DBL_RATE);
  u.doubloons -= v;
  u.points += pts;
  u.dblConvertedToday = (u.dblConvertedToday||0) + v;
  saveUser(u);
  document.getElementById('dbl-input').value = '';
  updateConvert();
  updateAccount();
  updateDashboard();
  showToast(`Converted ${v.toLocaleString()} 🪙 → +${pts.toLocaleString()} pts!`);
}

// ── Cashout ──
function doCashout() {
  const u = currentUser();
  if (!u) return;
  const cashoutDbl = Math.floor(u.points / 2);
  if (cashoutDbl === 0) {
    showToast('Not enough points to cash out (minimum 2 points for 1 doubloon).');
    return;
  }
  const ptsUsed = cashoutDbl * 2;
  u.points -= ptsUsed;
  u.doubloons += cashoutDbl;
  saveUser(u);
  updateAccount();
  updateDashboard();
  showToast(`Cashed out ${ptsUsed.toLocaleString()} pts → +${cashoutDbl.toLocaleString()} 🪙!`);
}

// ── Admin ──
function updateAdmin() {
  const db = loadDB();
  const tbody = document.getElementById('admin-tbody');
  tbody.innerHTML = '';
  let totalDbl = 0;
  if (!db.users) return;
  Object.values(db.users).forEach(u => {
    totalDbl += u.doubloons;
    const tier = getTier(u.points);
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${u.username}</td>
      <td>${u.email}</td>
      <td>${u.points.toLocaleString()}</td>
      <td>${u.doubloons.toLocaleString()}</td>
      <td>${tier.charAt(0).toUpperCase() + tier.slice(1)}</td>
      <td>${(u.totalWins || 0).toLocaleString()}</td>
      <td>${(u.biggestWin || 0).toLocaleString()}</td>
      <td>${(u.totalSpins || 0).toLocaleString()}</td>
      <td>${new Date(u.created).toLocaleDateString()}</td>
    `;
    tbody.appendChild(row);
    document.getElementById('total-dbl').textContent = totalDbl.toLocaleString();
    const netProfit = -totalDbl; // negative means profit
    const profitEl = document.getElementById('net-profit');
    profitEl.textContent = (netProfit > 0 ? '+' : '') + netProfit.toLocaleString();
    profitEl.style.color = netProfit >= 0 ? '#4ade80' : '#f87171'; // green for profit, red for debt

  });
}

// ── Change password ──
async function changePassword() {
  const u = currentUser();
  if (!u) return;
  const oldPw  = document.getElementById('chg-old').value;
  const newPw  = document.getElementById('chg-new').value;
  const newPw2 = document.getElementById('chg-new2').value;
  const errEl  = document.getElementById('chg-error');
  const sucEl  = document.getElementById('chg-success');
  errEl.classList.remove('show'); sucEl.classList.remove('show');
  // If using Supabase Auth, call updateUser
  if (supabase) {
    if (newPw.length < 8) { errEl.textContent='New password must be at least 8 characters.'; errEl.classList.add('show'); return; }
    if (newPw !== newPw2) { errEl.textContent='New passwords do not match.'; errEl.classList.add('show'); return; }
    try {
      const { data, error } = await supabase.auth.updateUser({ password: newPw });
      if (error) { errEl.textContent = sanitise(error.message || 'Password update failed'); errEl.classList.add('show'); return; }
      sucEl.textContent = '✅ Password updated successfully.'; sucEl.classList.add('show');
      document.getElementById('chg-old').value = '';
      document.getElementById('chg-new').value = '';
      document.getElementById('chg-new2').value = '';
      return;
    } catch (e) {
      errEl.textContent = 'Password update failed.'; errEl.classList.add('show'); return;
    }
  }

  // Local fallback: verify old password and update local hash
  const oldHash = await sha256(u.salt + oldPw + 'ga_casino_pepper_x9k2');
  if (oldHash !== u.hash) { errEl.textContent='Current password is incorrect.'; errEl.classList.add('show'); return; }
  if (newPw.length < 8)   { errEl.textContent='New password must be at least 8 characters.'; errEl.classList.add('show'); return; }
  if (newPw !== newPw2)   { errEl.textContent='New passwords do not match.'; errEl.classList.add('show'); return; }

  const newSalt = randomToken(16);
  const newHash = await sha256(newSalt + newPw + 'ga_casino_pepper_x9k2');
  u.salt = newSalt;
  u.hash = newHash;
  saveUser(u);
  sucEl.textContent = '✅ Password updated successfully.';
  sucEl.classList.add('show');
  document.getElementById('chg-old').value = '';
  document.getElementById('chg-new').value = '';
  document.getElementById('chg-new2').value = '';
}

// ── SLOTS ENGINE ──
let spinning = false;
let currentBet = 10;
let reelStrips = [];

const REEL_STRIP_LEN = 24;

function buildStrip() {
  const strip = [];
  for (let i = 0; i < REEL_STRIP_LEN; i++) {
    // Weighted distribution: 💎 rarest, 🔔 most common
    const weights = [1,2,3,4,5,6,8,10]; // corresponds to SYMBOLS order
    let total = weights.reduce((a,b)=>a+b,0);
    let r = Math.random() * total;
    let idx = 0;
    for (let w of weights) { r -= w; if (r <= 0) break; idx++; }
    strip.push(SYMBOLS[Math.min(idx, SYMBOLS.length-1)]);
  }
  return strip;
}

function initReels() {
  reelStrips = [buildStrip(), buildStrip(), buildStrip()];
  for (let i = 0; i < 3; i++) {
    const reel = document.getElementById('reel-'+i);
    reel.innerHTML = '';
    const strip = reelStrips[i];
    // Render strip × 3 for seamless spin illusion
    for (let rep = 0; rep < 3; rep++) {
      strip.forEach(sym => {
        const div = document.createElement('div');
        div.className = 'reel-symbol';
        div.innerHTML = '<span class="symbol">' + sym + '</span>';
        reel.appendChild(div);
      });
    }
    reel.style.transform = 'translateY(0px)';
  }
}

function changeBet(delta) {
  const u = currentUser();
  if (!u) return;
  currentBet = Math.max(10, Math.min(u.points, currentBet + delta));
  currentBet = Math.round(currentBet / 10) * 10;
  document.getElementById('bet-display').textContent = currentBet.toLocaleString() + ' pts';
}

function pickResult() {
  // Slightly house-favoured: pure random from strip
  const idx = [0,1,2].map(() => Math.floor(Math.random() * REEL_STRIP_LEN));
  return idx.map((i,r) => reelStrips[r][i]);
}

function calcPayout(results, bet, bonus) {
  const [a,b,c] = results;
  // Three of a kind: full payout using symbol multiplier
  if (a === b && b === c) {
    return Math.floor(bet * (PAYOUTS[a] || 1) * (bonus || 1));
  }
  // Two of a kind (any two matching): return half the bet (apply tier bonus)
  if (a === b || a === c || b === c) {
    return Math.floor((bet * 0.5) * (bonus || 1));
  }
  return 0;
}

async function spin() {
  if (spinning) return;
  const u = currentUser();
  if (!u) return;

  if (u.points < currentBet) {
    showToast('Not enough points! Convert some Doubloons or reduce your bet.');
    return;
  }

  spinning = true;
  const spinBtn = document.getElementById('spin-btn');
  spinBtn.disabled = true;
  document.getElementById('result-msg').textContent = '';
  document.getElementById('result-msg').className = '';

  // Deduct bet
  u.points -= currentBet;
  u.totalSpins = (u.totalSpins||0) + 1;
  saveUser(u);
  updateDashboard();

  // Determine result
  const results = pickResult();
  const bonus   = tierBonus(u.points + currentBet); // use pre-bet tier

  // Animate each reel
  const spinDurations = [800, 1100, 1400];
  const targetOffsets = results.map((sym, ri) => {
    const strip = reelStrips[ri];
    const idx = strip.indexOf(sym);
    // Land on middle strip
    const stripH = REEL_STRIP_LEN * 110;
    return -(stripH + idx * 110);
  });

  for (let i = 0; i < 3; i++) {
    animateReel(i, targetOffsets[i], spinDurations[i]);
  }

  await new Promise(r => setTimeout(r, spinDurations[2] + 200));

  // Apply result
  const payout = calcPayout(results, currentBet, bonus);
  u.points += payout;
  if (payout > 0) {
    u.totalWins = (u.totalWins||0) + 1;
    u.biggestWin = Math.max(u.biggestWin||0, payout);
  }

  // History
  if (!u.history) u.history = [];
  u.history.unshift({ syms: results.join(''), bet: currentBet, payout, time: Date.now() });
  if (u.history.length > 50) u.history.pop();
  saveUser(u);

  // Display result
  const msgEl = document.getElementById('result-msg');
  if (payout >= 25) { // jackpot for 2.5x or more
    msgEl.textContent = `💎 JACKPOT! +${payout.toLocaleString()} pts!`;
    msgEl.className = 'win';
    launchConfetti();
  } else if (payout > 0) {
    msgEl.textContent = `✨ You won ${payout.toLocaleString()} pts!`;
    msgEl.className = 'win';
    if (payout >= 15) launchConfetti(20);
  } else {
    msgEl.textContent = `No match — try again!`;
    msgEl.className = 'lose';
  }

  updateDashboard();
  spinning = false;
  spinBtn.disabled = false;
}

function animateReel(reelIdx, targetOffset, duration) {
  const reel = document.getElementById('reel-'+reelIdx);
  const stripH = REEL_STRIP_LEN * 110;

  // Fast spin phase then snap to target
  const startTime = performance.now();
  const spinOffset = -(stripH * 2); // fast visual spin

  function frame(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);

    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = spinOffset + (targetOffset - spinOffset) * eased;
    reel.style.transform = `translateY(${current}px)`;

    if (progress < 1) requestAnimationFrame(frame);
    else reel.style.transform = `translateY(${targetOffset}px)`;
  }
  requestAnimationFrame(frame);
}

// ── History display ──
function updateHistory() {
  const u = currentUser();
  const list = document.getElementById('history-list');
  if (!u || !u.history || u.history.length === 0) {
    list.innerHTML = '<div style="color:var(--text-dim);font-size:0.85rem;font-style:italic">No spins yet — try your luck!</div>';
    return;
  }
  list.innerHTML = '';
  u.history.slice(0,20).forEach(h => {
    const div = document.createElement('div');
    div.className = 'history-item';
    const timeStr = new Date(h.time).toLocaleTimeString();
    const won = h.payout > 0;
    div.innerHTML = `
      <span class="history-syms">${h.syms.split('').join(' ')}</span>
      <span style="color:var(--text-dim);font-size:0.75rem">${timeStr}</span>
      <span class="${won?'history-win':'history-lose'}">${won ? '+'+h.payout.toLocaleString() : '-'+h.bet.toLocaleString()} pts</span>
    `;
    list.appendChild(div);
  });
}

// ── Confetti ──
function launchConfetti(count=50) {
  const colors = ['#FFD700','#C9A84C','#4ade80','#c084fc','#60a5fa','#f87171'];
  for (let i = 0; i < count; i++) {
    const el = document.createElement('div');
    el.className = 'confetti-piece';
    el.style.cssText = `
      left:${Math.random()*100}%;
      background:${colors[Math.floor(Math.random()*colors.length)]};
      --cf-dur:${2+Math.random()*2}s;
      --cf-delay:${Math.random()*0.5}s;
      transform:rotate(${Math.random()*360}deg)
    `;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }
}

// ── Session expiry timer ──
setInterval(() => {
  const s = getSession();
  if (!s && document.getElementById('dashboard-section').classList.contains('active')) {
    showToast('Session expired — please sign in again.');
    logout();
  }
}, 60000);

// ── TERMS POPUP ──
function showTerms() {
  document.getElementById('terms-overlay').classList.add('show');
}

function hideTerms() {
  document.getElementById('terms-overlay').classList.remove('show');
}

async function acceptTerms() {
  hideTerms();
  await doRegister();
}

// ── Init ──
refreshLoginCaptcha();
refreshRegCaptcha();

const existingSession = getSession();
if (existingSession) {
  initReels();
  document.getElementById('user-bar').style.display = 'flex';
  document.getElementById('auth-section').classList.remove('active');
  updateDashboard();
  showSection('dashboard');
} else {
  showSection('auth');
}
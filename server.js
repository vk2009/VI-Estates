const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'vi_estates.sqlite');
const SESSION_TTL = 30 * 60 * 1000;
const PEPPER = 'ga_casino_pepper_x9k2';
const DB_PATH = path.dirname(DB_FILE);

fs.mkdirSync(DB_PATH, { recursive: true });
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');

db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  username_lower TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 0,
  doubloons INTEGER NOT NULL DEFAULT 0,
  owed_doubloons INTEGER NOT NULL DEFAULT 0,
  total_wins INTEGER NOT NULL DEFAULT 0,
  total_spins INTEGER NOT NULL DEFAULT 0,
  biggest_win INTEGER NOT NULL DEFAULT 0,
  history TEXT NOT NULL DEFAULT '[]',
  created INTEGER NOT NULL,
  dbl_converted_today INTEGER NOT NULL DEFAULT 0,
  dbl_convert_date TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created INTEGER NOT NULL,
  last_active INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`).run();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

function hashPassword(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function generateToken(len = 32) {
  return crypto.randomBytes(len).toString('hex');
}

function safeUser(row) {
  if (!row) return null;
  return {
    username: row.username,
    email: row.email,
    points: row.points,
    doubloons: row.doubloons,
    owedDoubloons: row.owed_doubloons,
    totalWins: row.total_wins,
    totalSpins: row.total_spins,
    biggestWin: row.biggest_win,
    history: JSON.parse(row.history || '[]'),
    created: row.created,
    dblConvertedToday: row.dbl_converted_today,
    dblConvertDate: row.dbl_convert_date
  };
}

function createSession(userId) {
  const token = generateToken(32);
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created, last_active) VALUES (?, ?, ?, ?)').run(token, userId, now, now);
  return token;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = header.slice(7);
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  if (Date.now() - session.last_active > SESSION_TTL) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return res.status(401).json({ error: 'Session expired' });
  }

  db.prepare('UPDATE sessions SET last_active = ? WHERE token = ?').run(Date.now(), token);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return res.status(401).json({ error: 'Invalid session' });
  }

  req.user = user;
  req.sessionToken = token;
  next();
}

app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Missing username, email or password' });
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3–20 letters, numbers, or underscores' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const usernameLower = username.toLowerCase();
  const existingUser = db.prepare('SELECT id FROM users WHERE username_lower = ? OR email = ?').get(usernameLower, email.toLowerCase());
  if (existingUser) {
    return res.status(400).json({ error: 'Username or email already exists' });
  }

  const salt = generateToken(16);
  const hash = hashPassword(salt + password + PEPPER);
  const now = Date.now();
  const stmt = db.prepare(`INSERT INTO users (username, username_lower, email, salt, hash, points, doubloons, owed_doubloons, total_wins, total_spins, biggest_win, history, created, dbl_converted_today, dbl_convert_date)
    VALUES (?, ?, ?, ?, ?, 200, 500, 0, 0, 0, 0, '[]', ?, 0, NULL)`);
  const result = stmt.run(username, usernameLower, email.toLowerCase(), salt, hash, now);

  const token = createSession(result.lastInsertRowid);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  return res.json({ token, user: safeUser(user) });
});

app.post('/api/login', (req, res) => {
  const { input, password } = req.body || {};
  if (!input || !password) {
    return res.status(400).json({ error: 'Missing username/email or password' });
  }
  const normalized = input.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username_lower = ? OR email = ?').get(normalized, normalized);
  if (!user) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }
  const hash = hashPassword(user.salt + password + PEPPER);
  if (hash !== user.hash) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }

  const token = createSession(user.id);
  return res.json({ token, user: safeUser(user) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  return res.json(safeUser(req.user));
});

app.post('/api/logout', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.sessionToken);
  return res.json({ success: true });
});

app.post('/api/password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Missing old or new password' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const user = req.user;
  const oldHash = hashPassword(user.salt + oldPassword + PEPPER);
  if (oldHash !== user.hash) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const newSalt = generateToken(16);
  const newHash = hashPassword(newSalt + newPassword + PEPPER);
  db.prepare('UPDATE users SET salt = ?, hash = ? WHERE id = ?').run(newSalt, newHash, user.id);
  return res.json({ success: true });
});

app.post('/api/convert', authMiddleware, (req, res) => {
  const { amount } = req.body || {};
  const convert = parseInt(amount, 10);
  if (!Number.isInteger(convert) || convert < 1) {
    return res.status(400).json({ error: 'Invalid convert amount' });
  }
  const user = req.user;
  const today = new Date().toDateString();
  const dblConvertedToday = user.dbl_convert_date === today ? user.dbl_converted_today : 0;
  if (convert > user.doubloons) {
    return res.status(400).json({ error: 'Insufficient Doubloons' });
  }
  if (dblConvertedToday + convert > 10000) {
    return res.status(400).json({ error: 'Daily limit exceeded' });
  }
  const pointsGain = Math.floor(convert * 1.5);
  db.prepare(`UPDATE users SET doubloons = doubloons - ?, points = points + ?, dbl_converted_today = ?, dbl_convert_date = ? WHERE id = ?`)
    .run(convert, pointsGain, dblConvertedToday + convert, today, user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  return res.json(safeUser(updated));
});

app.post('/api/transfer', authMiddleware, (req, res) => {
  const { amount } = req.body || {};
  const transfer = parseInt(amount, 10);
  if (!Number.isInteger(transfer) || transfer <= 0) {
    return res.status(400).json({ error: 'Invalid transfer amount' });
  }
  db.prepare('UPDATE users SET owed_doubloons = owed_doubloons + ? WHERE id = ?').run(transfer, req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  return res.json(safeUser(updated));
});

app.post('/api/update', authMiddleware, (req, res) => {
  const { pointsDelta, doubloonsDelta, owedDoubloonsDelta, totalWinsDelta, totalSpinsDelta, biggestWin, historyEntry } = req.body || {};
  const updates = [];
  const values = [];

  if (Number.isInteger(pointsDelta) && pointsDelta !== 0) {
    updates.push('points = points + ?');
    values.push(pointsDelta);
  }
  if (Number.isInteger(doubloonsDelta) && doubloonsDelta !== 0) {
    updates.push('doubloons = doubloons + ?');
    values.push(doubloonsDelta);
  }
  if (Number.isInteger(owedDoubloonsDelta) && owedDoubloonsDelta !== 0) {
    updates.push('owed_doubloons = owed_doubloons + ?');
    values.push(owedDoubloonsDelta);
  }
  if (Number.isInteger(totalWinsDelta) && totalWinsDelta !== 0) {
    updates.push('total_wins = total_wins + ?');
    values.push(totalWinsDelta);
  }
  if (Number.isInteger(totalSpinsDelta) && totalSpinsDelta !== 0) {
    updates.push('total_spins = total_spins + ?');
    values.push(totalSpinsDelta);
  }
  if (Number.isInteger(biggestWin) && biggestWin > 0) {
    updates.push('biggest_win = MAX(biggest_win, ?)');
    values.push(biggestWin);
  }

  if (historyEntry) {
    const row = db.prepare('SELECT history FROM users WHERE id = ?').get(req.user.id);
    const history = JSON.parse(row.history || '[]');
    history.unshift(historyEntry);
    if (history.length > 50) history.length = 50;
    updates.push('history = ?');
    values.push(JSON.stringify(history));
  }

  if (updates.length === 0) {
    return res.json(safeUser(req.user));
  }

  values.push(req.user.id);
  const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
  db.prepare(sql).run(...values);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  return res.json(safeUser(updated));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`VI Estates server running on http://localhost:${PORT}`);
});

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = 'your-secret-key'; // Change this in production!

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public')); // Serve frontend from /public folder

const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error(err);
  console.log('Connected to SQLite DB.');
});

// Initialize DB tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, category TEXT, unit TEXT, building TEXT, location TEXT, condition TEXT, qty REAL, photo TEXT, attributes TEXT, updatedAt TEXT, history TEXT, fp TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, status TEXT, itemId INTEGER, qty REAL, name TEXT, email TEXT, note TEXT, createdAt TEXT, updatedAt TEXT, createdBy TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS auditLog (id INTEGER PRIMARY KEY, at TEXT, actor TEXT, action TEXT, details TEXT)`);
});

// Helper: Run query with params
const runQuery = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) { err ? reject(err) : resolve(this); });
});

const getQuery = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => { err ? reject(err) : resolve(rows); });
});

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (password !== 'tech') return res.status(401).json({ error: 'Wrong password' });
  const rows = await getQuery('SELECT * FROM users WHERE username = ?', [username]);
  if (!rows.length) {
    await runQuery('INSERT INTO users (username, password) VALUES (?, ?)', [username, 'tech']); // Simple, hash in prod
  }
  const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
  res.json({ token, username });
});

// Get state (items, requests, audit)
app.get('/api/state', auth, async (req, res) => {
  const items = await getQuery('SELECT * FROM items');
  const requests = await getQuery('SELECT * FROM requests');
  const auditLog = await getQuery('SELECT * FROM auditLog ORDER BY id DESC LIMIT 80');
  items.forEach(i => { i.history = JSON.parse(i.history || '[]'); i.attributes = JSON.parse(i.attributes || '{}'); });
  res.json({ items, requests, auditLog, nextId: items.length + 1, nextReqId: requests.length + 1 });
});

// Save state (full sync for simplicity)
app.post('/api/state', auth, async (req, res) => {
  const { items, requests, auditLog, nextId, nextReqId } = req.body;
  try {
    await runQuery('DELETE FROM items');
    await runQuery('DELETE FROM requests');
    await runQuery('DELETE FROM auditLog');
    for (const i of items) {
      await runQuery('INSERT INTO items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [i.id, i.name, i.category, i.unit, i.building, i.location, i.condition, i.qty, i.photo, JSON.stringify(i.attributes), i.updatedAt, JSON.stringify(i.history), i.fp]);
    }
    for (const r of requests) {
      await runQuery('INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [r.id, r.status, r.itemId, r.qty, r.name, r.email, r.note, r.createdAt, r.updatedAt, r.createdBy]);
    }
    for (const a of auditLog) {
      await runQuery('INSERT INTO auditLog (at, actor, action, details) VALUES (?, ?, ?, ?)',
        [a.at, a.actor, a.action, a.details]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
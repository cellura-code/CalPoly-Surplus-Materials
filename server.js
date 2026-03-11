require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'your-secret-key';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })); // Basic rate limit to prevent spam

const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error(err);
  console.log('Connected to SQLite DB.');
});

// Initialize DB tables with indexes for better performance
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, category TEXT, unit TEXT, building TEXT, location TEXT, condition TEXT, qty REAL, photo TEXT, attributes TEXT, updatedAt TEXT, history TEXT, fp TEXT)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_items_fp ON items(fp)`);
  db.run(`CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, status TEXT, itemId INTEGER, qty REAL, name TEXT, email TEXT, note TEXT, createdAt TEXT, updatedAt TEXT, createdBy TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS auditLog (id INTEGER PRIMARY KEY, at TEXT, actor TEXT, action TEXT, details TEXT)`);
  // Seed default tech user if none (with hashed password)
  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    if (row.count === 0) {
      bcrypt.hash('tech', 10, (err, hash) => {
        if (err) console.error(err);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', ['admin', hash]);
      });
    }
  });
});

// Helpers for DB queries
const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) { err ? reject(err) : resolve(this); });
});
const getAll = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => { err ? reject(err) : resolve(rows); });
});
const getOne = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => { err ? reject(err) : resolve(row); });
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

// Login (with password hashing check)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await getOne('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Register new tech users (requires auth, hashes password)
app.post('/api/register', auth, async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Items APIs (granular for better efficiency)
app.get('/api/items', async (req, res) => {
  try {
    const items = await getAll('SELECT * FROM items');
    items.forEach(i => {
      i.attributes = JSON.parse(i.attributes || '{}');
      i.history = JSON.parse(i.history || '[]');
    });
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

app.post('/api/items', auth, async (req, res) => {
  const item = req.body;
  try {
    const fp = item.fp; // Assume frontend sends fp; or define fingerprint here if needed
    const existing = await getOne('SELECT id, qty FROM items WHERE fp = ?', [fp]);
    if (existing) {
      // Merge: Add qty
      await run('UPDATE items SET qty = qty + ?, updatedAt = ? WHERE id = ?', [item.qty, new Date().toISOString(), existing.id]);
      // Add to history (optional - expand as needed)
    } else {
      await run('INSERT INTO items (name, category, unit, building, location, condition, qty, photo, attributes, updatedAt, history, fp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [item.name, item.category, item.unit, item.building, item.location, item.condition, item.qty, item.photo, JSON.stringify(item.attributes || {}), new Date().toISOString(), JSON.stringify(item.history || []), fp]);
    }
    // Audit log
    await run('INSERT INTO auditLog (at, actor, action, details) VALUES (?, ?, ?, ?)', [new Date().toISOString(), req.user.username, 'ADD_ITEM', `Added/merged item: ${item.name}`]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add/merge item' });
  }
});

// Requests APIs
app.get('/api/requests', auth, async (req, res) => {
  try {
    const requests = await getAll('SELECT * FROM requests');
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

app.post('/api/requests', async (req, res) => { // No auth for students
  const reqData = req.body;
  try {
    const id = await run('INSERT INTO requests (status, itemId, qty, name, email, note, createdAt, updatedAt, createdBy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['pending', reqData.itemId, reqData.qty, reqData.name, reqData.email, reqData.note, new Date().toISOString(), new Date().toISOString(), reqData.createdBy]);
    // Send email if configured
    if (EMAIL_USER && EMAIL_PASS) {
      const transporter = nodemailer.createTransport({
        host: 'smtp.office365.com',
        port: 587,
        secure: false,
        auth: { user: EMAIL_USER, pass: EMAIL_PASS }
      });
      await transporter.sendMail({
        from: EMAIL_USER,
        to: reqData.email,
        subject: 'Reservation Confirmed',
        text: `Your reservation #${id.lastID} for qty ${reqData.qty} is pending.`
      });
    }
    res.json({ id: id.lastID });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create reservation: ' + err.message });
  }
});

// Audit log
app.get('/api/audit', auth, async (req, res) => {
  try {
    const log = await getAll('SELECT * FROM auditLog ORDER BY id DESC LIMIT 80');
    res.json(log);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Export CSV (tech only)
app.get('/api/export/csv', auth, async (req, res) => {
  try {
    const items = await getAll('SELECT * FROM items');
    let csv = 'ID,Name,Category,Qty,Unit,Building,Location\n';
    items.forEach(i => {
      csv += `${i.id},"${i.name.replace(/"/g, '""')}",${i.category},${i.qty},${i.unit},"${i.building.replace(/"/g, '""')}","${i.location.replace(/"/g, '""')}"\n`;
    });
    res.header('Content-Type', 'text/csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export CSV' });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
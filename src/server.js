/**
 * telegram-storage — Node.js backend
 */

import express from 'express';
import multer from 'multer';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

import { db, initDb, DB_PATH, reloadDb } from './db.js';
import { requireAuth, requireAdmin, verifyAuth } from './auth.js';
import {
  hashPassword, verifyPassword, randomUUID,
  generateEncryptionKey, encryptData, decryptData,
  exportKey, importKey, generateIV, ivToBase64, ivFromBase64,
  arrayBufferToBase64, base64ToArrayBuffer,
} from './crypto.js';
import { uploadChunkToTelegram, downloadChunkFromTelegram } from './telegram.js';

// ─── Config ──────────────────────────────────────────────────────────────────

const envPath = join(dirname(fileURLToPath(import.meta.url)), '..', '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const idx = t.indexOf('=');
    if (idx < 0) continue;
    const k = t.slice(0, idx).trim(), v = t.slice(idx + 1).trim();
    if (!process.env[k]) process.env[k] = v;
  }
}

const PORT               = parseInt(process.env.PORT || '3000');
const CHUNK_SIZE_MIN     = parseInt(process.env.CHUNK_SIZE_MIN || '17825792');
const CHUNK_SIZE_MAX     = parseInt(process.env.CHUNK_SIZE_MAX || '20447232');
const MAX_PARALLEL       = parseInt(process.env.MAX_PARALLEL_UPLOADS || '4');
const IV_LENGTH          = parseInt(process.env.ENCRYPTION_IV_LENGTH || '12');
const MIN_PASSWORD_LENGTH= parseInt(process.env.MIN_PASSWORD_LENGTH || '12');
const SESSION_EXPIRY_DAYS= parseInt(process.env.SESSION_EXPIRY_DAYS || '30');

const __dirname  = dirname(fileURLToPath(import.meta.url));
// Standalone web version uses relative path
const PUBLIC_DIR = join(__dirname, '..', 'public');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getRandomChunkSize() {
  return Math.floor(Math.random() * (CHUNK_SIZE_MAX - CHUNK_SIZE_MIN + 1)) + CHUNK_SIZE_MIN;
}
function getBotsFromDB() {
  return db.prepare('SELECT token, name FROM bots ORDER BY id').all().results;
}
function getChannelsFromDB() {
  return db.prepare('SELECT name, channel_id as id FROM channels ORDER BY id').all().results;
}

function sseWrite(res, data) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function initializeDatabase() {
  try {
    await initDb(); // Initialize sql.js WASM database
    // Ensure data directory exists (important for Electron userData path)
    const dbPath = process.env.DB_PATH || './data/storage.db';
    const dbDir  = dirname(dbPath);
    if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

    // Apply schema if settings table doesn't exist yet
    let needsSchema = false;
    try { db.prepare("SELECT 1 FROM settings LIMIT 1").first(); }
    catch { needsSchema = true; }

    if (needsSchema) {
      const schemaPath = join(__dirname, '..', 'schema.sql');
      if (existsSync(schemaPath)) {
        const schema = readFileSync(schemaPath, 'utf8');
        for (const stmt of schema.split(';').map(s => s.trim()).filter(Boolean)) {
          try { db.prepare(stmt).run(); } catch(e) {
            if (!e.message.includes('already exists') && !e.message.includes('UNIQUE')) console.warn('Schema:', e.message);
          }
        }
        console.log('Schema applied from', schemaPath);
      }
    }

    // Ensure profile_image column exists
    try { db.prepare("SELECT profile_image FROM users LIMIT 1").first(); }
    catch { 
      db.prepare("ALTER TABLE users ADD COLUMN profile_image TEXT").run(); 
      console.log('Added profile_image column to users table');
    }

    const setting = db.prepare("SELECT value FROM settings WHERE key='superadmin_password_hash'").first();
    if (!setting?.value || !setting.value.includes(':') || setting.value === 'NEEDS_INITIALIZATION') {
      const hash = await hashPassword('superadmin123');
      db.prepare('UPDATE settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key=?').bind(hash, 'superadmin_password_hash').run();
      db.prepare("DELETE FROM password_history WHERE password_hash='NEEDS_INITIALIZATION'").run();
      try { db.prepare('INSERT INTO password_history (password_hash, changed_by) VALUES (?,?)').bind(hash, 'system').run(); } catch {}
      console.log('Superadmin password initialized');
    }
  } catch (err) { console.error('DB init error:', err); }
}

async function getSuperadminPasswordHash() {
  const s = db.prepare("SELECT value FROM settings WHERE key='superadmin_password_hash'").first();
  if (s?.value && s.value !== 'NEEDS_INITIALIZATION') return s.value;
  return hashPassword('superadmin123');
}

// ─── App ─────────────────────────────────────────────────────────────────────

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 4 * 1024 * 1024 * 1024 } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// ─── Static ───────────────────────────────────────────────────────────────────

app.use(express.static(PUBLIC_DIR));
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Use a more robust way to serve the main HTML files from ASAR
const serveHtml = (file) => (req, res) => {
  try {
    const p = join(PUBLIC_DIR, file);
    if (existsSync(p)) {
      res.setHeader('Content-Type', 'text/html');
      res.send(readFileSync(p));
    } else {
      res.status(404).send('Not Found: ' + file);
    }
  } catch (err) {
    res.status(500).send('Error loading ' + file + ': ' + err.message);
  }
};

app.get('/login', serveHtml('login.html'));
app.get('/login.html', serveHtml('login.html'));
['/','index.html','/bots','/channels','/files','/database'].forEach(route => {
  app.get(route, serveHtml('index.html'));
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

app.post('/api/init-superadmin', async (req, res) => {
  try {
    const s = db.prepare("SELECT value FROM settings WHERE key='superadmin_password_hash'").first();
    if (s?.value && s.value !== 'NEEDS_INITIALIZATION') return res.status(400).json({ success: false, error: 'Already initialized' });
    const hash = await hashPassword('superadmin123');
    db.prepare('UPDATE settings SET value=?,updated_at=CURRENT_TIMESTAMP WHERE key=?').bind(hash,'superadmin_password_hash').run();
    db.prepare("DELETE FROM password_history WHERE password_hash='NEEDS_INITIALIZATION'").run();
    try { db.prepare('INSERT INTO password_history (password_hash,changed_by) VALUES (?,?)').bind(hash,'system').run(); } catch {}
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    await initializeDatabase();
    const { email, password, superAdminPassword } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });
    if (!superAdminPassword) return res.status(403).json({ success: false, error: 'Superadmin password required' });
    if (password.length < MIN_PASSWORD_LENGTH) return res.status(400).json({ success: false, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, error: 'Invalid email format' });

    const storedHash = await getSuperadminPasswordHash();
    if (!(await verifyPassword(superAdminPassword, storedHash))) return res.status(403).json({ success: false, error: 'Invalid superadmin password' });

    const existing = db.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
    if (existing) return res.status(400).json({ success: false, error: 'Email already registered' });

    const hashedPassword = await hashPassword(password);
    db.prepare('INSERT INTO users (email,username,password,is_admin) VALUES (?,?,?,?)').bind(email, email.split('@')[0], hashedPassword, 1).run();
    res.status(201).json({ success: true, message: 'Admin registered successfully', isAdmin: true });
  } catch(err) {
    if (String(err).includes('UNIQUE')) return res.status(400).json({ success: false, error: 'Email already registered' });
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    await initializeDatabase();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });

    const user = db.prepare('SELECT id,username,password,is_admin FROM users WHERE email=?').bind(email).first();
    if (!user || !(await verifyPassword(password, user.password))) return res.status(401).json({ success: false, error: 'Invalid email or password' });

    const token = randomUUID();
    const sessionId = randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_EXPIRY_DAYS * 86400000).toISOString();
    db.prepare('INSERT INTO sessions (id,user_id,token,expires_at) VALUES (?,?,?,?)').bind(sessionId, user.id, token, expiresAt).run();

    res.setHeader('Set-Cookie', `token=${token}; HttpOnly; SameSite=Strict; Max-Age=${SESSION_EXPIRY_DAYS * 86400}`);
    res.json({ success: true, token, username: user.username, isAdmin: user.is_admin });
  } catch(err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.get('/api/validate-token', async (req, res) => {
  try {
    await initializeDatabase();
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ valid: false, error: 'No token provided' });
    const session = db.prepare(
      `SELECT s.user_id, u.profile_image FROM sessions s JOIN users u ON s.user_id=u.id
       WHERE s.token=? AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))`
    ).bind(token).first();
    if (!session) return res.status(401).json({ valid: false, error: 'Invalid or expired token' });
    res.json({ valid: true, profile_image: session.profile_image });
  } catch(err) { res.status(500).json({ valid: false, error: String(err) }); }
});

app.post('/api/user/profile-image', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No image provided' });
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const session = db.prepare('SELECT user_id FROM sessions WHERE token=?').bind(token).first();
    if (!session) return res.status(401).json({ success: false, error: 'Unauthorized' });

    const base64Image = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    db.prepare('UPDATE users SET profile_image=? WHERE id=?').bind(base64Image, session.user_id).run();
    res.json({ success: true, profile_image: base64Image });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Users ────────────────────────────────────────────────────────────────────

app.get('/api/users', requireAdmin, (req, res) => {
  try {
    const { results } = db.prepare('SELECT id,email,username,is_admin,created_at FROM users ORDER BY created_at DESC').all();
    res.json({ success: true, users: results });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const { email, password, isAdmin } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required' });
    if (password.length < MIN_PASSWORD_LENGTH) return res.status(400).json({ success: false, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    const hashedPassword = await hashPassword(password);
    db.prepare('INSERT INTO users (email,username,password,is_admin) VALUES (?,?,?,?)').bind(email, email.split('@')[0], hashedPassword, isAdmin ? 1 : 0).run();
    res.status(201).json({ success: true, message: 'User created' });
  } catch(err) {
    if (String(err).includes('UNIQUE')) return res.status(400).json({ success: false, error: 'Email already registered' });
    res.status(500).json({ success: false, error: String(err) });
  }
});

app.delete('/api/users/:userId', requireAdmin, (req, res) => {
  try {
    const user = db.prepare('SELECT is_admin FROM users WHERE id=?').bind(req.params.userId).first();
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    if (user.is_admin === 1 || user.is_admin === '1') return res.status(403).json({ success: false, error: 'Cannot delete admin users' });
    db.prepare('DELETE FROM users WHERE id=?').bind(req.params.userId).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Settings ─────────────────────────────────────────────────────────────────

app.get('/api/settings', requireAdmin, (req, res) => {
  try {
    const { results } = db.prepare('SELECT key,updated_at FROM settings').all();
    res.json({ success: true, settings: results });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.get('/api/settings/password-history', requireAdmin, (req, res) => {
  try {
    const { results } = db.prepare('SELECT id,changed_at,changed_by FROM password_history ORDER BY changed_at DESC LIMIT 10').all();
    res.json({ success: true, history: results });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/settings/update-superadmin-password', requireAdmin, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ success: false, error: 'Old and new passwords required' });
    if (newPassword.length < MIN_PASSWORD_LENGTH) return res.status(400).json({ success: false, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });

    const setting = db.prepare("SELECT value FROM settings WHERE key='superadmin_password_hash'").first();
    if (!setting || !(await verifyPassword(oldPassword, setting.value))) return res.status(401).json({ success: false, error: 'Invalid old password' });

    const newHash = await hashPassword(newPassword);
    const prev = db.prepare('SELECT id FROM password_history WHERE password_hash=?').bind(newHash).first();
    if (prev) return res.status(400).json({ success: false, error: 'Cannot reuse a previous password' });

    db.prepare('UPDATE settings SET value=?,updated_at=CURRENT_TIMESTAMP WHERE key=?').bind(newHash,'superadmin_password_hash').run();
    db.prepare('INSERT INTO password_history (password_hash,changed_by) VALUES (?,?)').bind(newHash,'admin').run();
    res.json({ success: true, message: 'Superadmin password updated' });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Bots ─────────────────────────────────────────────────────────────────────

app.get('/api/bots', (req, res) => {
  try { res.json({ success: true, data: getBotsFromDB() }); }
  catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/bots', (req, res) => {
  try {
    const { name, token } = req.body;
    if (!name || !token) return res.status(400).json({ success: false, error: 'Name and token required' });
    db.prepare('INSERT INTO bots (name,token) VALUES (?,?)').bind(name, token).run();
    res.status(201).json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.delete('/api/bots/:token', (req, res) => {
  try {
    db.prepare('DELETE FROM bots WHERE token=?').bind(decodeURIComponent(req.params.token)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.put('/api/bots/:token', (req, res) => {
  try {
    const { name, token: newToken } = req.body;
    if (!name || !newToken) return res.status(400).json({ success: false, error: 'Name and token required' });
    db.prepare('UPDATE bots SET name=?, token=? WHERE token=?').bind(name, newToken, decodeURIComponent(req.params.token)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Channels ─────────────────────────────────────────────────────────────────

app.get('/api/channels', (req, res) => {
  try { res.json({ success: true, data: getChannelsFromDB() }); }
  catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/channels', (req, res) => {
  try {
    const { name, id } = req.body;
    if (!name || !id) return res.status(400).json({ success: false, error: 'Name and ID required' });
    db.prepare('INSERT INTO channels (name,channel_id) VALUES (?,?)').bind(name, id).run();
    res.status(201).json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.delete('/api/channels/:channelId', (req, res) => {
  try {
    db.prepare('DELETE FROM channels WHERE channel_id=?').bind(decodeURIComponent(req.params.channelId)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.put('/api/channels/:channelId', (req, res) => {
  try {
    const { name, id: newId } = req.body;
    if (!name || !newId) return res.status(400).json({ success: false, error: 'Name and ID required' });
    db.prepare('UPDATE channels SET name=?, channel_id=? WHERE channel_id=?').bind(name, newId, decodeURIComponent(req.params.channelId)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Folders ─────────────────────────────────────────────────────────────────

app.get('/api/folders/:folderId', (req, res) => {
  try {
    const folderId = decodeURIComponent(req.params.folderId);
    let folders, files;
    if (folderId === 'root') {
      folders = db.prepare('SELECT id,name,created_at FROM folders WHERE parent_id IS NULL ORDER BY name').all();
      files   = db.prepare('SELECT id,filename,file_size,total_chunks,created_at FROM files WHERE folder_id IS NULL ORDER BY filename').all();
    } else {
      folders = db.prepare('SELECT id,name,created_at FROM folders WHERE parent_id=? ORDER BY name').bind(folderId).all();
      files   = db.prepare('SELECT id,filename,file_size,total_chunks,created_at FROM files WHERE folder_id=? ORDER BY filename').bind(folderId).all();
    }
    res.json({ folders: folders.results, files: files.results });
  } catch(err) { res.status(500).json({ error: String(err) }); }
});

app.post('/api/folders', (req, res) => {
  try {
    const { name, parent_id } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Folder name required' });
    const id = randomUUID();
    db.prepare('INSERT INTO folders (id,name,parent_id) VALUES (?,?,?)').bind(id, name, parent_id || null).run();
    res.status(201).json({ success: true, id });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.put('/api/folders/:folderId', (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Folder name required' });
    db.prepare('UPDATE folders SET name=? WHERE id=?').bind(name, decodeURIComponent(req.params.folderId)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.delete('/api/folders/:folderId', (req, res) => {
  try {
    const id = decodeURIComponent(req.params.folderId);
    db.prepare('DELETE FROM chunks WHERE file_id IN (SELECT id FROM files WHERE folder_id=?)').bind(id).run();
    db.prepare('DELETE FROM files WHERE folder_id=?').bind(id).run();
    db.prepare('DELETE FROM folders WHERE id=?').bind(id).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Files ────────────────────────────────────────────────────────────────────

app.delete('/api/files/:fileId', (req, res) => {
  try {
    const id = decodeURIComponent(req.params.fileId);
    db.prepare('DELETE FROM chunks WHERE file_id=?').bind(id).run();
    db.prepare('DELETE FROM files WHERE id=?').bind(id).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.put('/api/files/:fileId', (req, res) => {
  try {
    const { filename } = req.body;
    if (!filename) return res.status(400).json({ success: false, error: 'Filename required' });
    db.prepare('UPDATE files SET filename=? WHERE id=?').bind(filename, decodeURIComponent(req.params.fileId)).run();
    res.json({ success: true });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── DB inspection ────────────────────────────────────────────────────────────

app.get('/api/db/files', (req, res) => {
  try { res.json({ files: db.prepare('SELECT * FROM files ORDER BY created_at DESC').all().results }); }
  catch(err) { res.status(500).json({ error: String(err) }); }
});

app.get('/api/db/chunks', (req, res) => {
  try { res.json({ chunks: db.prepare('SELECT * FROM chunks ORDER BY file_id,chunk_index').all().results }); }
  catch(err) { res.status(500).json({ error: String(err) }); }
});

app.get('/api/db/stats', (req, res) => {
  try {
    const f = db.prepare('SELECT COUNT(*) as count FROM files').first();
    const c = db.prepare('SELECT COUNT(*) as count, COALESCE(SUM(chunk_size),0) as total_size FROM chunks').first();
    res.json({ total_files: Number(f?.count||0), total_chunks: Number(c?.count||0), total_size: Number(c?.total_size||0) });
  } catch(err) { res.status(500).json({ error: String(err) }); }
});

app.get('/api/check-encryption/:fileId', (req, res) => {
  try {
    const file = db.prepare('SELECT id,filename,encryption_key,encryption_iv FROM files WHERE id=?').bind(decodeURIComponent(req.params.fileId)).first();
    if (!file) return res.status(404).json({ success: false, error: 'File not found' });
    res.json({
      success: true, file_id: file.id, filename: file.filename,
      has_encryption_key: !!file.encryption_key, has_encryption_iv: !!file.encryption_iv,
      encryption_key_length: file.encryption_key?.length || 0,
    });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.get('/api/db/export', requireAdmin, (req, res) => {
  try {
    if (!existsSync(DB_PATH)) return res.status(404).send('Database file not found');
    res.download(DB_PATH, 'storage.db');
  } catch(err) { res.status(500).send(String(err)); }
});

app.post('/api/db/import', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    writeFileSync(DB_PATH, req.file.buffer);
    await reloadDb();
    res.json({ success: true, message: 'Database imported successfully' });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

app.post('/api/db/import-recovery', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    writeFileSync(DB_PATH, req.file.buffer);
    await reloadDb();
    res.json({ success: true, message: 'Database restored successfully' });
  } catch(err) { res.status(500).json({ success: false, error: String(err) }); }
});

// ─── Upload (SSE) ─────────────────────────────────────────────────────────────

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file || file.size === 0) return res.status(400).json({ success: false, error: 'No file provided' });

  // Get exact bytes from multer buffer (avoid backing-buffer offset issues)
  const fileBuffer = file.buffer.buffer.slice(file.buffer.byteOffset, file.buffer.byteOffset + file.buffer.byteLength);
  const filename   = file.originalname || 'file';
  const folderId   = req.query.folder_id || null;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const fileId    = randomUUID();
  const chunkSize = getRandomChunkSize();
  const totalChunks = Math.ceil(fileBuffer.byteLength / chunkSize);

  try {
    const bots     = getBotsFromDB();
    const channels = getChannelsFromDB();
    if (bots.length === 0) throw new Error('No bots configured. Please add bots at /bots');
    if (channels.length === 0) throw new Error('No channels configured. Please add channels at /channels');

    // Generate key and IV — store as clean base64
    const encryptionKey    = await generateEncryptionKey();
    const encryptionKeyStr = await exportKey(encryptionKey);
    const iv               = generateIV(IV_LENGTH);
    const ivStr            = ivToBase64(iv);

    db.prepare(
      'INSERT INTO files (id,filename,folder_id,total_chunks,file_size,encryption_key,encryption_iv) VALUES (?,?,?,?,?,?,?)'
    ).bind(fileId, filename, folderId, totalChunks, fileBuffer.byteLength, encryptionKeyStr, ivStr).run();

    sseWrite(res, {
      type: 'upload_start', fileId, filename, totalChunks,
      fileSize: fileBuffer.byteLength,
      fileSizeMB: (fileBuffer.byteLength / 1024 / 1024).toFixed(2),
      timestamp: new Date().toISOString(),
    });

    let uploadedChunks = 0;
    let uploadedBytes  = 0;

    // Build all chunk tasks upfront, distribute bots round-robin
    const chunkTasks = Array.from({ length: totalChunks }, (_, i) => ({
      chunkIndex: i,
      bot:        bots[i % bots.length],
      channel:    channels[i % channels.length],
      start:      i * chunkSize,
      end:        Math.min((i + 1) * chunkSize, fileBuffer.byteLength),
    }));

    // Run MAX_PARALLEL tasks concurrently
    const semaphore = async (tasks, concurrency, fn) => {
      const results = [];
      let idx = 0;
      const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
        while (idx < tasks.length) {
          const i = idx++;
          results[i] = await fn(tasks[i]);
        }
      });
      await Promise.all(workers);
      return results;
    };

    await semaphore(chunkTasks, MAX_PARALLEL, async (task) => {
      const { chunkIndex, bot, channel, start, end } = task;
      const chunkData         = fileBuffer.slice(start, end);
      const encryptedChunk    = await encryptData(chunkData, encryptionKey, iv);

      const { messageId, telegramFileId } = await uploadChunkToTelegram(
        bot.token, channel.id, encryptedChunk, fileId, chunkIndex
      );

      db.prepare(
        'INSERT INTO chunks (file_id,chunk_index,message_id,telegram_file_id,chunk_size,bot_token,channel_id) VALUES (?,?,?,?,?,?,?)'
      ).bind(fileId, chunkIndex, messageId, telegramFileId, end - start, bot.token, channel.id).run();

      uploadedChunks++;
      uploadedBytes += (end - start);
      const pct = Math.round((uploadedBytes / fileBuffer.byteLength) * 100);

      sseWrite(res, {
        type: 'upload_progress', fileId, chunkIndex, totalChunks,
        percentage: pct,
        processedBytes: uploadedBytes,
        totalBytes: fileBuffer.byteLength,
        processedMB: (uploadedBytes / 1024 / 1024).toFixed(2),
        totalMB: (fileBuffer.byteLength / 1024 / 1024).toFixed(2),
        status: `${pct}% - Chunk ${uploadedChunks}/${totalChunks}`,
        botName: bot.name,
        channelName: channel.name,
        timestamp: new Date().toISOString(),
      });
    });

    sseWrite(res, {
      type: 'upload_complete', fileId, filename, totalChunks,
      fileSize: fileBuffer.byteLength,
      fileSizeMB: (fileBuffer.byteLength / 1024 / 1024).toFixed(2),
      percentage: 100,
      message: '✅ File uploaded successfully',
      status: 'UPLOAD_COMPLETE',
      timestamp: new Date().toISOString(),
    });

    res.end();
  } catch (err) {
    console.error('Upload error:', err);
    try {
      db.prepare('DELETE FROM chunks WHERE file_id=?').bind(fileId).run();
      db.prepare('DELETE FROM files WHERE id=?').bind(fileId).run();
    } catch {}
    sseWrite(res, { type: 'upload_error', error: String(err), timestamp: new Date().toISOString() });
    res.end();
  }
});

// ─── Download (SSE) ───────────────────────────────────────────────────────────

app.get('/download/:fileId', requireAuth, async (req, res) => {
  const fileId = req.params.fileId;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  try {
    const fileResult = db.prepare('SELECT * FROM files WHERE id=?').bind(fileId).first();
    if (!fileResult) {
      sseWrite(res, { type: 'download_error', fileId, error: 'File not found', timestamp: new Date().toISOString() });
      return res.end();
    }

    const { results: chunkRows } = db.prepare('SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index ASC').bind(fileId).all();
    if (!chunkRows?.length) {
      sseWrite(res, { type: 'download_error', fileId, error: 'No chunks found', timestamp: new Date().toISOString() });
      return res.end();
    }

    // Import key and IV using the fixed helpers
    const encryptionKey = await importKey(fileResult.encryption_key);
    const iv            = ivFromBase64(fileResult.encryption_iv);

    sseWrite(res, {
      type: 'download_start', fileId,
      filename: fileResult.filename,
      totalChunks: chunkRows.length,
      fileSize: fileResult.file_size,
      fileSizeMB: (fileResult.file_size / 1024 / 1024).toFixed(2),
      timestamp: new Date().toISOString(),
    });

    const decryptedChunks = new Array(chunkRows.length);
    let downloadedChunks  = 0;
    let downloadedBytes   = 0;

    // Semaphore for parallel downloads
    const semaphore = async (tasks, concurrency, fn) => {
      let idx = 0;
      const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
        while (idx < tasks.length) {
          const i = idx++;
          await fn(tasks[i], i);
        }
      });
      await Promise.all(workers);
    };

    await semaphore(chunkRows, MAX_PARALLEL, async (chunk, i) => {
      const encryptedData = await downloadChunkFromTelegram(chunk.bot_token, chunk.telegram_file_id);
      const decrypted     = await decryptData(encryptedData, encryptionKey, iv);
      decryptedChunks[chunk.chunk_index] = decrypted;

      downloadedChunks++;
      downloadedBytes += decrypted.byteLength;
      const pct = Math.round((downloadedBytes / fileResult.file_size) * 100);

      sseWrite(res, {
        type: 'download_progress', fileId,
        chunkIndex: chunk.chunk_index,
        totalChunks: chunkRows.length,
        percentage: pct,
        processedBytes: downloadedBytes,
        totalBytes: fileResult.file_size,
        processedMB: (downloadedBytes / 1024 / 1024).toFixed(2),
        totalMB: (fileResult.file_size / 1024 / 1024).toFixed(2),
        status: `${pct}% - Chunk ${downloadedChunks}/${chunkRows.length}`,
        timestamp: new Date().toISOString(),
      });
    });

    // Merge chunks in correct order
    const totalSize = decryptedChunks.reduce((s, c) => s + c.byteLength, 0);
    const combined  = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of decryptedChunks) {
      combined.set(new Uint8Array(chunk), offset);
      offset += chunk.byteLength;
    }

    sseWrite(res, {
      type: 'download_complete', fileId,
      filename: fileResult.filename,
      fileSize: totalSize,
      fileSizeMB: (totalSize / 1024 / 1024).toFixed(2),
      totalChunks: chunkRows.length,
      percentage: 100,
      message: '✅ File downloaded successfully',
      status: 'DOWNLOAD_COMPLETE',
      timestamp: new Date().toISOString(),
    });

    // Send as base64 — Buffer.from is the fastest way in Node
    sseWrite(res, {
      type: 'download_data', fileId,
      filename: fileResult.filename,
      data: Buffer.from(combined).toString('base64'),
      timestamp: new Date().toISOString(),
    });

    res.end();
  } catch (err) {
    console.error('Download error:', err);
    sseWrite(res, { type: 'download_error', fileId, error: String(err), timestamp: new Date().toISOString() });
    res.end();
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

export async function startServer(port = PORT, host = '127.0.0.1') {
  await initializeDatabase();
  return new Promise((resolve, reject) => {
    const srv = app.listen(port, host, () => {
      console.log(`\n   Default superadmin password: superadmin123\n`);
      resolve(srv);
    }).on('error', reject);
  });
}

// Run directly: node index.js is preferred
if (fileURLToPath(import.meta.url) === process.argv[1]) {
  startServer().catch(err => { console.error('Startup error:', err); process.exit(1); });
}

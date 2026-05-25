const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');

// ===== Config =====
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('✖ 错误：必须设置环境变量 JWT_SECRET');
  console.error('   示例 (Windows PowerShell):');
  console.error('   $env:JWT_SECRET="你的随机密钥"');
  console.error('   示例 (CMD):');
  console.error('   set JWT_SECRET=你的随机密钥');
  process.exit(1);
}
const DB_PATH = path.join(__dirname, 'data.sqlite');
const CERT_DIR = path.join(__dirname, 'certs');
const CERT_KEY = path.join(CERT_DIR, 'server.key');
const CERT_PEM = path.join(CERT_DIR, 'server.cert');

let db;

// ===== DB Helper (sql.js — pure JS, no native build needed) =====
function dbRun(sql, params = []) {
  db.run(sql, params);
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length > 0) stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

function dbGet(sql, params = []) {
  const rows = dbAll(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

function dbInit() {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')))");
  db.run("CREATE TABLE IF NOT EXISTS vaults (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, encrypted_data TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 1, updated_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id))");
  // Login attempt tracking for rate limiting
  db.run("CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, ip TEXT NOT NULL, attempted_at TEXT DEFAULT (datetime('now')))");
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ===== Input Sanitization =====
function sanitize(str) {
  if (typeof str !== 'string') return '';
  // Strip null bytes and control characters (except common whitespace)
  return str.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
}

// ===== Generate Self-Signed HTTPS Certificate =====
function ensureCert() {
  if (fs.existsSync(CERT_KEY) && fs.existsSync(CERT_PEM)) {
    return { key: CERT_KEY, cert: CERT_PEM };
  }

  console.log('  🔐  正在生成自签名 SSL 证书...');
  if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  }

  const forge = require('node-forge');
  const pki = forge.pki;

  // Generate 2048-bit key pair
  console.log('  🗝️   生成 RSA 密钥对...');
  const keys = pki.rsa.generateKeyPair(2048);

  // Create certificate
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10); // 10 years validity

  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'organizationName', value: 'Password Vault' },
    { name: 'countryName', value: 'CN' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },     // DNS
        { type: 7, ip: '127.0.0.1' },        // IP
        { type: 7, ip: '::1' },               // IPv6 localhost
      ],
    },
  ]);

  // Self-sign
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // Export PEM
  const pemKey = pki.privateKeyToPem(keys.privateKey);
  const pemCert = pki.certificateToPem(cert);

  fs.writeFileSync(CERT_KEY, pemKey);
  fs.writeFileSync(CERT_PEM, pemCert);
  console.log('  ✅  自签名证书已生成（有效期10年）');
  return { key: CERT_KEY, cert: CERT_PEM };
}

// ===== Express App =====
const app = express();

// ===== Security Middleware =====

// 1. Helmet — security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // needed for inline scripts in index.html
      scriptSrcAttr: ["'unsafe-inline'"],         // needed for onclick="" handlers
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // allow loading resources
}));

// 2. CORS — dynamically allow known origins
const localOrigins = [
  'http://localhost:3000',
  'https://localhost:3000',
  'http://127.0.0.1:3000',
  'https://127.0.0.1:3000',
];
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (curl, server-to-server)
    if (!origin) return callback(null, true);
    // Allow localhost development
    if (localOrigins.includes(origin)) return callback(null, true);
    // In production, allow any origin (Render HTTPS reverse proxy handles security)
    if (IS_PROD) return callback(null, true);
    callback(new Error('不允许的跨域来源'));
  },
  credentials: true,
  maxAge: 86400,
}));

// Explicitly handle CORS preflight for all routes
app.options('*', cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (localOrigins.includes(origin)) return callback(null, true);
    if (IS_PROD) return callback(null, true);
    callback(new Error('不允许的跨域来源'));
  },
  credentials: true,
  maxAge: 86400,
}));

app.use(express.json({ limit: '1mb' })); // Reduced from 5mb to prevent DoS

// 3. Rate limiting — brute force protection
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 attempts per window per IP
  message: { error: '登录尝试过于频繁，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // max 100 requests per minute per IP
  message: { error: '请求过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', globalLimiter);

// 4. Auth Middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未授权，请先登录' });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    req.email = payload.email;
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

// ===== API Routes =====

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const rawEmail = sanitize(req.body.email || '');
    const rawPassword = req.body.password || '';
    const email = rawEmail.toLowerCase(); // normalize email

    if (!email || !rawPassword) {
      return res.status(400).json({ error: '邮箱和密码不能为空' });
    }
    if (rawPassword.length < 8) {
      return res.status(400).json({ error: '登录密码至少8位' });
    }
    if (rawPassword.length > 128) {
      return res.status(400).json({ error: '登录密码不能超过128位' });
    }
    if (email.length > 254) {
      return res.status(400).json({ error: '邮箱地址过长' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: '邮箱格式不正确' });
    }

    // Check existing
    const existing = dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({ error: '该邮箱已注册，请直接登录' });
    }

    const hash = await bcrypt.hash(rawPassword, 12); // increased from 10 to 12 rounds
    dbRun('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);

    const user = dbGet('SELECT id FROM users WHERE email = ?', [email]);
    dbRun('INSERT INTO vaults (user_id, encrypted_data, version) VALUES (?, ?, 1)', [user.id, '']);

    const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email, userId: user.id });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: '注册失败，请重试' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const rawEmail = sanitize(req.body.email || '');
    const rawPassword = req.body.password || '';
    const email = rawEmail.toLowerCase();

    if (!email || !rawPassword) {
      return res.status(400).json({ error: '邮箱和密码不能为空' });
    }

    const user = dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      // Use same timing to prevent email enumeration
      await bcrypt.compare(rawPassword, '$2a$12$0000000000000000000000000000000000000');
      return res.status(401).json({ error: '邮箱或密码错误' });
    }

    const ok = await bcrypt.compare(rawPassword, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: '邮箱或密码错误' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: user.email, userId: user.id });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: '登录失败，请重试' });
  }
});

// Get vault data
app.get('/api/vault', auth, (req, res) => {
  const vault = dbGet('SELECT encrypted_data, version, updated_at FROM vaults WHERE user_id = ?', [req.userId]);
  if (!vault) {
    return res.status(404).json({ error: '保险箱不存在' });
  }
  res.json({
    encrypted: vault.encrypted_data,
    version: vault.version,
    updatedAt: vault.updated_at
  });
});

// Update vault data
app.put('/api/vault', auth, (req, res) => {
  try {
    const encrypted = req.body.encrypted;
    const clientVersion = req.body.clientVersion;

    if (encrypted === undefined) {
      return res.status(400).json({ error: '缺少加密数据' });
    }
    if (typeof encrypted !== 'string' || encrypted.length > 10 * 1024 * 1024) {
      return res.status(400).json({ error: '数据格式错误' });
    }

    // Check for version conflict
    if (clientVersion !== undefined) {
      const vault = dbGet('SELECT version FROM vaults WHERE user_id = ?', [req.userId]);
      if (!vault) {
        return res.status(404).json({ error: '保险箱不存在' });
      }
      if (clientVersion !== vault.version) {
        return res.status(409).json({
          error: '数据冲突：服务器版本已更新，请刷新后重试',
          serverVersion: vault.version
        });
      }
    }

    dbRun("UPDATE vaults SET encrypted_data = ?, version = version + 1, updated_at = datetime('now') WHERE user_id = ?", [encrypted, req.userId]);
    const vault = dbGet('SELECT version FROM vaults WHERE user_id = ?', [req.userId]);
    res.json({ version: vault.version });
  } catch (e) {
    console.error('Vault update error:', e);
    res.status(500).json({ error: '保存失败，请重试' });
  }
});

// ===== Serve frontend =====
const frontendPath = path.join(__dirname, '..', 'index.html');
if (fs.existsSync(frontendPath)) {
  app.get('/', (req, res) => res.sendFile(frontendPath));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api/')) {
      res.sendFile(frontendPath);
    }
  });
}

// ===== Start =====
async function start() {
  const SQL = await initSqlJs();

  // Load or create database
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  dbInit();
  console.log('✓ 数据库初始化完成');

  if (IS_PROD) {
    // Production (Render): plain HTTP, Render reverse proxy provides HTTPS
    app.listen(PORT, '0.0.0.0', () => {
      console.log('');
      console.log('  🔐  密码保险箱服务器已启动 (HTTP → Render HTTPS)');
      console.log(`  📍  端口: ${PORT}`);
      console.log(`  📦  数据库: ${DB_PATH}`);
      console.log(`  🛡️  Helmet 安全头已启用`);
      console.log(`  🚦  登录限速: 每15分钟最多10次尝试`);
      console.log(`  🔑  JWT 密钥: 已从环境变量读取`);
      console.log('');
    });
  } else {
    // Local: self-signed HTTPS
    const certPaths = ensureCert();
    const httpsOptions = {
      key: fs.readFileSync(certPaths.key),
      cert: fs.readFileSync(certPaths.cert),
    };
    https.createServer(httpsOptions, app).listen(PORT, () => {
      console.log('');
      console.log('  🔐  密码保险箱服务器已启动 (HTTPS)');
      console.log(`  📍  https://localhost:${PORT}`);
      console.log(`  📦  数据库: ${DB_PATH}`);
      console.log(`  🛡️  Helmet 安全头已启用`);
      console.log(`  🚦  登录限速: 每15分钟最多10次尝试`);
      console.log(`  🔑  JWT 密钥: 已从环境变量读取`);
      console.log('');
      console.log('  ⚠️  自签名证书，首次访问会有安全提示，点"继续"即可');
      console.log('');
    });
  }
}

start().catch(e => {
  console.error('启动失败:', e);
  process.exit(1);
});

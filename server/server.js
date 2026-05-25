const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
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
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('✖ 错误：必须设置环境变量 DATABASE_URL（PostgreSQL 连接地址）');
  console.error('   Render: 在 Dashboard 添加 PostgreSQL 后自动生成');
  console.error('   本地: 可用 Docker 启动 PostgreSQL 或使用本地安装');
  process.exit(1);
}

const CERT_DIR = path.join(__dirname, 'certs');
const CERT_KEY = path.join(CERT_DIR, 'server.key');
const CERT_PEM = path.join(CERT_DIR, 'server.cert');

// ===== PostgreSQL Connection =====
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('✖ PostgreSQL 连接异常:', err.message);
});

// ===== DB Helper (PostgreSQL) =====
async function dbQuery(sql, params = []) {
  return await pool.query(sql, params);
}

async function dbRun(sql, params = []) {
  return await dbQuery(sql, params);
}

async function dbAll(sql, params = []) {
  const result = await dbQuery(sql, params);
  return result.rows;
}

async function dbGet(sql, params = []) {
  const result = await dbQuery(sql, params);
  return result.rows.length > 0 ? result.rows[0] : null;
}

async function dbInit() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await dbRun(`
    CREATE TABLE IF NOT EXISTS vaults (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE,
      encrypted_data TEXT NOT NULL DEFAULT '',
      version INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  await dbRun(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      ip TEXT NOT NULL,
      attempted_at TIMESTAMP DEFAULT NOW()
    )
  `);
  console.log('✓ 数据库表结构检查完成');
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
    const keyAge = Date.now() - fs.statSync(CERT_KEY).mtimeMs;
    const certAge = Date.now() - fs.statSync(CERT_PEM).mtimeMs;
    const maxAge = 365 * 24 * 60 * 60 * 1000; // 1 year
    if (keyAge < maxAge && certAge < maxAge) {
      console.log('ℹ 现有证书有效，跳过生成');
      return { key: CERT_KEY, cert: CERT_PEM };
    }
  }

  console.log('🔑 正在生成自签名证书...');
  if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  }

  try {
    const forge = require('node-forge');
    const pki = forge.pki;

    // Generate key pair
    console.log('   generating key pair...');
    const keys = pki.rsa.generateKeyPair(2048);

    // Create certificate
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + Date.now().toString(16);
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [
      { name: 'commonName', value: 'localhost' },
      { name: 'organizationName', value: 'Password Vault Dev' }
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
          { type: 2, value: 'localhost' },
          { type: 7, ip: '127.0.0.1' }
        ]
      }
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());

    // Write files
    fs.writeFileSync(CERT_KEY, pki.privateKeyToPem(keys.privateKey));
    fs.writeFileSync(CERT_PEM, pki.certificateToPem(cert));

    console.log('✅ 自签名证书已生成');
    return { key: CERT_KEY, cert: CERT_PEM };
  } catch (e) {
    console.error('❌ 证书生成失败:', e.message);
    console.log('ℹ 请手动安装 OpenSSL 或 node-forge，或使用已存在的证书');
    process.exit(1);
  }
}

// ===== Express App =====
const app = express();

// Trust Render's reverse proxy (for correct req.ip, rate limiting, etc.)
app.set('trust proxy', 1);

// ===== CORS & Security Middleware =====

// 1. Manual CORS — handles ALL requests including OPTIONS preflight.
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).send('');
  }
  next();
});

// 2. Helmet — security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));

// 3. Rate limiting — brute force protection
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '登录尝试过于频繁，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
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
    const email = rawEmail.toLowerCase();

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
    const existing = await dbGet('SELECT id FROM users WHERE email = $1', [email]);
    if (existing) {
      return res.status(409).json({ error: '该邮箱已注册，请直接登录' });
    }

    const hash = await bcrypt.hash(rawPassword, 12);
    const result = await dbRun(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
      [email, hash]
    );
    const userId = result.rows[0].id;

    await dbRun(
      'INSERT INTO vaults (user_id, encrypted_data, version) VALUES ($1, $2, 1)',
      [userId, '']
    );

    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email, userId });
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

    const user = await dbGet('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) {
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
app.get('/api/vault', auth, async (req, res) => {
  try {
    const vault = await dbGet(
      'SELECT encrypted_data, version, updated_at FROM vaults WHERE user_id = $1',
      [req.userId]
    );
    if (!vault) {
      return res.status(404).json({ error: '保险箱不存在' });
    }
    res.json({
      encrypted: vault.encrypted_data,
      version: vault.version,
      updatedAt: vault.updated_at
    });
  } catch (e) {
    console.error('Vault load error:', e);
    res.status(500).json({ error: '加载保险箱失败' });
  }
});

// Update vault data
app.put('/api/vault', auth, async (req, res) => {
  try {
    const encrypted = req.body.encrypted;
    const clientVersion = req.body.clientVersion;

    if (encrypted === undefined) {
      return res.status(400).json({ error: '缺少加密数据' });
    }
    if (typeof encrypted !== 'string' || encrypted.length > 10 * 1024 * 1024) {
      return res.status(400).json({ error: '数据格式错误' });
    }

    if (clientVersion !== undefined) {
      const vault = await dbGet(
        'SELECT version FROM vaults WHERE user_id = $1',
        [req.userId]
      );
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

    await dbRun(
      "UPDATE vaults SET encrypted_data = $1, version = version + 1, updated_at = NOW() WHERE user_id = $2",
      [encrypted, req.userId]
    );
    const vault = await dbGet(
      'SELECT version FROM vaults WHERE user_id = $1',
      [req.userId]
    );
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
  // Test database connection
  try {
    const result = await dbQuery('SELECT NOW()');
    console.log(`✓ PostgreSQL 连接成功 (${result.rows[0].now})`);
  } catch (e) {
    console.error('✖ 无法连接 PostgreSQL:', e.message);
    process.exit(1);
  }

  // Initialize tables
  await dbInit();

  if (IS_PROD) {
    app.listen(PORT, '0.0.0.0', () => {
      console.log('');
      console.log('  🔐  密码保险箱服务器已启动 (HTTP → Render HTTPS)');
      console.log(`  📍  端口: ${PORT}`);
      console.log(`  🗄️  数据库: PostgreSQL (外部)`);
      console.log(`  🛡️  Helmet 安全头已启用`);
      console.log(`  🚦  登录限速: 每15分钟最多10次尝试`);
      console.log(`  🔑  JWT 密钥: 已从环境变量读取`);
      console.log('');
    });
  } else {
    const certPaths = ensureCert();
    const httpsOptions = {
      key: fs.readFileSync(certPaths.key),
      cert: fs.readFileSync(certPaths.cert),
    };
    https.createServer(httpsOptions, app).listen(PORT, () => {
      console.log('');
      console.log('  🔐  密码保险箱服务器已启动 (HTTPS)');
      console.log(`  📍  https://localhost:${PORT}`);
      console.log(`  🗄️  数据库: PostgreSQL (外部)`);
      console.log(`  🛡️  Helmet 安全头已启用`);
      console.log(`  🚦  登录限速: 每15分钟最多10次尝试`);
      console.log(`  🔑  JWT 密钥: 已从环境变量读取`);
      console.log('');
      console.log('  ⚠️  自签名证书，首次访问会有安全提示，点"继续"即可');
      console.log('');
    });
  }
}

start();

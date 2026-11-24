'use strict';
/** Funções de segurança: senhas, tokens, limites de taxa, validação e cabeçalhos. */
const crypto = require('node:crypto');

// ---------- Senhas (scrypt com sal aleatório) ----------
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, n, saltHex, hashHex] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const got = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), expected.length, { N: Number(n), r: SCRYPT.r, p: SCRYPT.p });
    return crypto.timingSafeEqual(expected, got);
  } catch {
    return false;
  }
}

// Hash fictício usado quando o usuário não existe (evita descobrir usuários pelo tempo de resposta)
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

function passwordProblems(pw) {
  const p = String(pw || '');
  const issues = [];
  if (p.length < 10) issues.push('mínimo de 10 caracteres');
  if (!/[a-z]/.test(p) || !/[A-Z]/.test(p)) issues.push('letras maiúsculas e minúsculas');
  if (!/\d/.test(p)) issues.push('pelo menos um número');
  return issues;
}

// ---------- Tokens ----------
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ''));
  const B = Buffer.from(String(b || ''));
  return A.length === B.length && A.length > 0 && crypto.timingSafeEqual(A, B);
}

// ---------- Limite de requisições (memória) ----------
class RateLimiter {
  constructor({ windowMs, max }) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map();
    this.timer = setInterval(() => this.cleanup(), Math.min(windowMs, 60_000));
    this.timer.unref();
  }
  /** Retorna true se a requisição deve ser BLOQUEADA */
  hit(key) {
    const now = Date.now();
    let e = this.hits.get(key);
    if (!e || e.reset <= now) e = { count: 0, reset: now + this.windowMs };
    e.count++;
    this.hits.set(key, e);
    return e.count > this.max;
  }
  isBlocked(key) {
    const e = this.hits.get(key);
    return !!e && e.reset > Date.now() && e.count >= this.max;
  }
  reset(key) { this.hits.delete(key); }
  retryAfter(key) {
    const e = this.hits.get(key);
    return e ? Math.max(1, Math.ceil((e.reset - Date.now()) / 1000)) : 1;
  }
  cleanup() {
    const now = Date.now();
    for (const [k, e] of this.hits) if (e.reset <= now) this.hits.delete(k);
  }
}

// ---------- Validação ----------
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

function cleanText(v, max, { multiline = false } = {}) {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string' && typeof v !== 'number') throw new ValidationError('Valor inválido.');
  let s = String(v).replace(CONTROL_CHARS, '');
  if (!multiline) s = s.replace(/[\r\n\t]+/g, ' ');
  s = s.trim();
  if (s.length > max) throw new ValidationError(`Texto muito longo (máximo ${max} caracteres).`);
  return s;
}

function isEmail(s) {
  return typeof s === 'string' && s.length <= 254 && /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']{2,}$/.test(s);
}

/** Aceita apenas URLs http(s) — bloqueia javascript:, data:, etc. Também aceita caminhos locais /uploads/... */
function safeUrl(v, { allowLocalUploads = false } = {}) {
  const s = cleanText(v, 500);
  if (!s) return '';
  if (allowLocalUploads && /^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(s)) return s;
  let u;
  try { u = new URL(s); } catch { throw new ValidationError('URL inválida. Use um endereço começando com https://'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ValidationError('Apenas links http:// ou https:// são permitidos.');
  if (u.username || u.password) throw new ValidationError('URL não pode conter usuário/senha.');
  return u.toString();
}

function toInt(v, min, max, def = 0) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

const toBool = (v) => (v === true || v === 1 || v === '1' || v === 'true' || v === 'on' ? 1 : 0);

class ValidationError extends Error {
  constructor(msg) { super(msg); this.status = 400; this.expose = true; }
}

// ---------- Cabeçalhos de segurança ----------
function securityHeaders({ https = false } = {}) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://api.github.com",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'"
  ];
  if (https) csp.push('upgrade-insecure-requests');
  const h = {
    'Content-Security-Policy': csp.join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none'
  };
  if (https) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  return h;
}

// ---------- Imagens (upload) ----------
function detectImage(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  if (buf.toString('ascii', 0, 4) === 'GIF8') return 'gif';
  return null;
}

module.exports = {
  hashPassword, verifyPassword, DUMMY_HASH, passwordProblems,
  randomToken, sha256, safeEqual, RateLimiter,
  cleanText, isEmail, safeUrl, toInt, toBool, ValidationError,
  securityHeaders, detectImage
};

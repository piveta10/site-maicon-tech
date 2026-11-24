'use strict';
/**
 * Aplicação HTTP (sem frameworks).
 *  - API pública:   GET /api/site, POST /api/contato
 *  - API admin:     /api/admin/*  (sessão + CSRF)
 *  - Imagens:       GET /uploads/<arquivo>  (guardadas no banco de dados)
 *  - Arquivos:      /public  (apenas no servidor local; na Vercel quem serve é a CDN)
 *
 * Funciona igual no servidor local (server.js) e na Vercel (api/index.js).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createDb, migrate, DEFAULT_SETTINGS } = require('./db');
const S = require('./security');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2', '.xml': 'application/xml; charset=utf-8', '.webmanifest': 'application/manifest+json'
};
const IMG_MIME = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' };

const ICONS = ['code', 'cloud', 'shield', 'headset', 'network', 'bot', 'brain', 'workflow', 'chart', 'sparkles', 'mobile', 'database'];
const URL_SETTINGS = ['github', 'linkedin', 'youtube', 'instagram'];
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 horas
const COOKIE = 'mt_sess';
const UPLOAD_RE = /^\/uploads\/([a-f0-9]{32}\.(png|jpg|webp|gif))$/;

class HttpError extends Error {
  constructor(status, msg, headers) { super(msg); this.status = status; this.expose = true; this.headers = headers; }
}

/**
 * Limite de tentativas guardado no BANCO (funciona mesmo com várias instâncias
 * serverless na Vercel). Usado no login e no formulário de contato.
 */
class DbRateLimiter {
  constructor(db, name, { windowMs, max }) { this.db = db; this.name = name; this.windowMs = windowMs; this.max = max; }
  k(key) { return `${this.name}:${S.sha256(key).slice(0, 32)}`; }
  /** Conta uma tentativa. Retorna true se passou do limite. */
  async hit(key) {
    const now = Date.now();
    const [r] = await this.db.query(
      `INSERT INTO rate_limits (key, count, reset_at) VALUES ($1, 1, $2)
       ON CONFLICT (key) DO UPDATE SET
         count = CASE WHEN rate_limits.reset_at <= $3 THEN 1 ELSE rate_limits.count + 1 END,
         reset_at = CASE WHEN rate_limits.reset_at <= $3 THEN $2 ELSE rate_limits.reset_at END
       RETURNING count, reset_at`,
      [this.k(key), now + this.windowMs, now]
    );
    return Number(r.count) > this.max;
  }
  async state(key) {
    const [r] = await this.db.query('SELECT count, reset_at FROM rate_limits WHERE key = $1', [this.k(key)]);
    return r && Number(r.reset_at) > Date.now() ? { count: Number(r.count), reset: Number(r.reset_at) } : null;
  }
  async isBlocked(key) { const s = await this.state(key); return !!s && s.count >= this.max; }
  async retryAfter(key) { const s = await this.state(key); return s ? Math.max(1, Math.ceil((s.reset - Date.now()) / 1000)) : 1; }
  async reset(key) { await this.db.query('DELETE FROM rate_limits WHERE key = $1 RETURNING key', [this.k(key)]); }
}

function createApp(opts = {}) {
  const root = opts.root || path.join(__dirname, '..');
  const publicDir = path.join(root, 'public');
  const serveStatic = opts.serveStatic !== false;
  const https = !!opts.https;
  const trustProxy = !!opts.trustProxy;
  const log = opts.log || ((...a) => console.log(...a));

  const db = opts.db || createDb({ url: opts.databaseUrl, file: opts.dbFile });
  const headers = S.securityHeaders({ https });

  const limits = {
    login: new DbRateLimiter(db, 'login', { windowMs: 15 * 60_000, max: 5 }),        // 5 falhas / 15 min por IP
    loginUser: new DbRateLimiter(db, 'loginuser', { windowMs: 15 * 60_000, max: 10 }), // 10 falhas / 15 min por usuário
    contact: new DbRateLimiter(db, 'contact', { windowMs: 60 * 60_000, max: 5 }),      // 5 mensagens / hora por IP
    api: new S.RateLimiter({ windowMs: 60_000, max: opts.apiMax || 240 })             // geral, por instância
  };

  // ---------------- Inicialização (tabelas + primeiro admin) ----------------
  let readyPromise = null;
  const result = { created: null };
  function ready() {
    if (!readyPromise) {
      readyPromise = (async () => {
        await migrate(db);
        const [{ n }] = await db.query('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM admins');
        if (Number(n) === 0 && opts.adminPassword) {
          if (S.passwordProblems(opts.adminPassword).length) {
            log('⚠  ADMIN_PASSWORD fraca: use 10+ caracteres com maiúsculas, minúsculas e números. Administrador NÃO criado.');
          } else {
            const user = String(opts.adminUser || 'admin').toLowerCase();
            await db.query('INSERT INTO admins (username, pass_hash, created_at) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING RETURNING id',
              [user, S.hashPassword(opts.adminPassword), Date.now()]);
            result.created = user;
          }
        } else if (Number(n) === 0) {
          log('⚠  Nenhum administrador cadastrado. Defina ADMIN_PASSWORD nas variáveis de ambiente.');
        }
        await db.query('DELETE FROM rate_limits WHERE reset_at < $1 RETURNING key', [Date.now()]);
        await db.query('DELETE FROM sessions WHERE expires_at < $1 RETURNING token_hash', [Date.now()]);
      })().catch((e) => { readyPromise = null; throw e; });
    }
    return readyPromise;
  }

  // ---------------- Helpers ----------------
  const clientIp = (req) => {
    if (trustProxy) {
      const real = String(req.headers['x-real-ip'] || '').trim();
      if (real) return real;
      const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (xf) return xf;
    }
    return (req.socket && req.socket.remoteAddress) || 'desconhecido';
  };

  function send(res, status, body, extra = {}) {
    const isBuf = Buffer.isBuffer(body);
    const payload = isBuf || typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, {
      ...headers,
      'Content-Type': extra['Content-Type'] || 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extra
    });
    res.end(payload);
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const len = Number(req.headers['content-length'] || 0);
      if (len > limit) return reject(new HttpError(413, 'Conteúdo muito grande.'));
      const chunks = []; let size = 0; let done = false;
      req.on('data', (c) => {
        if (done) return;
        size += c.length;
        if (size > limit) { done = true; reject(new HttpError(413, 'Conteúdo muito grande.')); return; }
        chunks.push(c);
      });
      req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
      req.on('error', (e) => { if (!done) { done = true; reject(e); } });
    });
  }

  async function readJson(req) {
    const ct = String(req.headers['content-type'] || '').toLowerCase();
    if (!ct.startsWith('application/json')) throw new HttpError(415, 'Envie os dados como JSON.');
    const buf = await readBody(req, 100 * 1024);
    try {
      const obj = JSON.parse(buf.toString('utf8') || '{}');
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error();
      return obj;
    } catch { throw new HttpError(400, 'JSON inválido.'); }
  }

  function parseCookies(req) {
    const out = {};
    String(req.headers.cookie || '').split(';').forEach((p) => {
      const i = p.indexOf('=');
      if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
    return out;
  }

  const cookieStr = (val, maxAgeSec) =>
    `${COOKIE}=${val}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${https ? '; Secure' : ''}`;

  async function getSession(req) {
    const tok = parseCookies(req)[COOKIE];
    if (!tok || tok.length > 100) return null;
    const [row] = await db.query(
      'SELECT s.token_hash, s.csrf, s.expires_at, a.id AS admin_id, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = $1',
      [S.sha256(tok)]
    );
    if (!row) return null;
    if (Number(row.expires_at) < Date.now()) {
      await db.query('DELETE FROM sessions WHERE token_hash = $1 RETURNING token_hash', [row.token_hash]);
      return null;
    }
    return row;
  }

  /** Bloqueia requisições vindas de outros sites (defesa extra contra CSRF). */
  function checkOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return;
    let host;
    try { host = new URL(origin).host; } catch { throw new HttpError(403, 'Origem inválida.'); }
    const expected = trustProxy ? (req.headers['x-forwarded-host'] || req.headers.host) : req.headers.host;
    if (host !== expected) throw new HttpError(403, 'Origem não permitida.');
  }

  async function requireAdmin(req, { mutating }) {
    const sess = await getSession(req);
    if (!sess) throw new HttpError(401, 'Faça login para continuar.');
    if (mutating) {
      checkOrigin(req);
      if (!S.safeEqual(req.headers['x-csrf-token'], sess.csrf)) throw new HttpError(403, 'Token de segurança (CSRF) inválido. Recarregue a página.');
    }
    return sess;
  }

  const audit = (adminId, action, detail = '') =>
    db.query('INSERT INTO audit_log (admin_id, action, detail, created_at) VALUES ($1, $2, $3, $4) RETURNING id',
      [adminId, action, String(detail).slice(0, 300), Date.now()]);

  // ---------------- Leitura do conteúdo ----------------
  async function getSettings() {
    const out = {};
    for (const r of await db.query('SELECT key, value FROM settings')) if (!r.key.startsWith('_')) out[r.key] = r.value;
    return out;
  }

  async function getContent({ includeInactive = false } = {}) {
    const w = includeInactive ? '' : 'WHERE active = 1';
    const [settings, services, projects, testimonials] = await Promise.all([
      getSettings(),
      db.query(`SELECT * FROM services ${w} ORDER BY sort_order, id`),
      db.query(`SELECT * FROM projects ${w} ORDER BY sort_order, id`),
      db.query(`SELECT * FROM testimonials ${w} ORDER BY sort_order, id`)
    ]);
    return { settings, services, projects, testimonials };
  }

  // ---------------- Validação de entidades ----------------
  const ENTITIES = {
    services: {
      fields: ['icon', 'title', 'description', 'category', 'sort_order', 'active'],
      clean(b) {
        const title = S.cleanText(b.title, 120);
        if (!title) throw new S.ValidationError('Informe o título do serviço.');
        return {
          icon: ICONS.includes(b.icon) ? b.icon : 'code',
          title,
          description: S.cleanText(b.description, 600, { multiline: true }),
          category: b.category === 'ia' ? 'ia' : 'ti',
          sort_order: S.toInt(b.sort_order, -9999, 9999, 0),
          active: b.active === undefined ? 1 : S.toBool(b.active)
        };
      }
    },
    projects: {
      fields: ['title', 'description', 'tags', 'image_url', 'link_url', 'repo_url', 'is_ai', 'sort_order', 'active'],
      clean(b) {
        const title = S.cleanText(b.title, 150);
        if (!title) throw new S.ValidationError('Informe o título do projeto.');
        return {
          title,
          description: S.cleanText(b.description, 1000, { multiline: true }),
          tags: S.cleanText(b.tags, 200),
          image_url: S.safeUrl(b.image_url, { allowLocalUploads: true }),
          link_url: S.safeUrl(b.link_url),
          repo_url: S.safeUrl(b.repo_url),
          is_ai: S.toBool(b.is_ai),
          sort_order: S.toInt(b.sort_order, -9999, 9999, 0),
          active: b.active === undefined ? 1 : S.toBool(b.active)
        };
      }
    },
    testimonials: {
      fields: ['name', 'role', 'text', 'rating', 'sort_order', 'active'],
      clean(b) {
        const name = S.cleanText(b.name, 100);
        const text = S.cleanText(b.text, 600, { multiline: true });
        if (!name || !text) throw new S.ValidationError('Informe nome e depoimento.');
        return {
          name, text,
          role: S.cleanText(b.role, 100),
          rating: S.toInt(b.rating, 1, 5, 5),
          sort_order: S.toInt(b.sort_order, -9999, 9999, 0),
          active: b.active === undefined ? 1 : S.toBool(b.active)
        };
      }
    }
  };

  function cleanSetting(key, value) {
    if (URL_SETTINGS.includes(key)) return S.safeUrl(value);
    if (key === 'email') {
      const e = S.cleanText(value, 254);
      if (e && !S.isEmail(e)) throw new S.ValidationError('E-mail inválido.');
      return e;
    }
    if (key === 'whatsapp') {
      const d = String(value || '').replace(/\D/g, '');
      if (d && (d.length < 10 || d.length > 15)) throw new S.ValidationError('WhatsApp inválido. Use DDI + DDD + número, ex.: 5547999999999');
      return d;
    }
    if (key === 'github_usuario') {
      const u = S.cleanText(value, 39);
      if (u && !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(u)) throw new S.ValidationError('Usuário do GitHub inválido.');
      return u;
    }
    if (key === 'mostrar_repos_github') return S.toBool(value) ? '1' : '0';
    return S.cleanText(value, 3000, { multiline: true });
  }

  // ---------------- Rotas da API ----------------
  async function handleApi(req, res, url) {
    const ip = clientIp(req);
    if (limits.api.hit(ip)) throw new HttpError(429, 'Muitas requisições. Aguarde um instante.', { 'Retry-After': String(limits.api.retryAfter(ip)) });

    const p = url.pathname;
    const m = req.method;

    // ---- Público ----
    if (p === '/api/site' && m === 'GET') return send(res, 200, await getContent(), { 'Cache-Control': 'no-cache' });

    if (p === '/api/contato' && m === 'POST') {
      checkOrigin(req);
      const b = await readJson(req);
      if (b.website) return send(res, 200, { ok: true }); // honeypot: robôs preenchem campo oculto
      if (await limits.contact.hit(ip)) throw new HttpError(429, 'Você enviou muitas mensagens. Tente novamente mais tarde ou chame no WhatsApp.');
      const name = S.cleanText(b.name, 100);
      const email = S.cleanText(b.email, 254);
      const phone = S.cleanText(b.phone, 30);
      const subject = S.cleanText(b.subject, 150);
      const message = S.cleanText(b.message, 3000, { multiline: true });
      if (name.length < 2) throw new S.ValidationError('Informe seu nome.');
      if (!S.isEmail(email)) throw new S.ValidationError('Informe um e-mail válido.');
      if (phone && !/^[\d\s()+-]{8,30}$/.test(phone)) throw new S.ValidationError('Telefone inválido.');
      if (message.length < 10) throw new S.ValidationError('A mensagem deve ter pelo menos 10 caracteres.');
      await db.query('INSERT INTO messages (name, email, phone, subject, message, ip_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
        [name, email, phone, subject, message, S.sha256(ip).slice(0, 16), Date.now()]);
      return send(res, 201, { ok: true, mensagem: 'Mensagem enviada! Retornarei em breve.' });
    }

    // ---- Autenticação ----
    if (p === '/api/admin/login' && m === 'POST') {
      checkOrigin(req);
      if (await limits.login.isBlocked(ip)) {
        throw new HttpError(429, 'Muitas tentativas de login. Aguarde alguns minutos.', { 'Retry-After': String(await limits.login.retryAfter(ip)) });
      }
      const b = await readJson(req);
      const username = S.cleanText(b.username, 60).toLowerCase();
      const password = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
      if (await limits.loginUser.isBlocked(username)) throw new HttpError(429, 'Conta temporariamente bloqueada por excesso de tentativas.');
      const [admin] = await db.query('SELECT * FROM admins WHERE username = $1', [username]);
      const ok = S.verifyPassword(password, admin ? admin.pass_hash : S.DUMMY_HASH) && !!admin;
      if (!ok) {
        await limits.login.hit(ip);
        await limits.loginUser.hit(username);
        throw new HttpError(401, 'Usuário ou senha incorretos.');
      }
      await limits.login.reset(ip); await limits.loginUser.reset(username);
      const token = S.randomToken(32);
      const csrf = S.randomToken(24);
      await db.query('INSERT INTO sessions (token_hash, admin_id, csrf, expires_at) VALUES ($1, $2, $3, $4) RETURNING token_hash',
        [S.sha256(token), admin.id, csrf, Date.now() + SESSION_TTL_MS]);
      await audit(admin.id, 'login', S.sha256(ip).slice(0, 12));
      return send(res, 200, { ok: true, username: admin.username, csrf }, { 'Set-Cookie': cookieStr(token, SESSION_TTL_MS / 1000) });
    }

    if (p === '/api/admin/logout' && m === 'POST') {
      const sess = await requireAdmin(req, { mutating: true });
      await db.query('DELETE FROM sessions WHERE token_hash = $1 RETURNING token_hash', [sess.token_hash]);
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookieStr('', 0) });
    }

    if (p === '/api/admin/me' && m === 'GET') {
      const sess = await requireAdmin(req, { mutating: false });
      return send(res, 200, { username: sess.username, csrf: sess.csrf });
    }

    if (!p.startsWith('/api/admin/')) throw new HttpError(404, 'Não encontrado.');

    // ---- Área administrativa (todas exigem login) ----
    const mutating = m !== 'GET';
    const sess = await requireAdmin(req, { mutating });

    if (p === '/api/admin/data' && m === 'GET') {
      const [[{ n }], content] = await Promise.all([
        db.query('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM messages WHERE is_read = 0'),
        getContent({ includeInactive: true })
      ]);
      return send(res, 200, { ...content, icons: ICONS, unread: Number(n) });
    }

    if (p === '/api/admin/settings' && m === 'PUT') {
      const b = await readJson(req);
      const changes = {};
      for (const key of Object.keys(b)) {
        if (!Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key)) continue; // ignora chaves desconhecidas
        changes[key] = cleanSetting(key, b[key]); // valida TUDO antes de gravar qualquer coisa
      }
      for (const [k, v] of Object.entries(changes)) {
        await db.query('UPDATE settings SET value = $1 WHERE key = $2 RETURNING key', [v, k]);
      }
      await audit(sess.admin_id, 'settings', Object.keys(changes).join(','));
      return send(res, 200, { ok: true, settings: await getSettings() });
    }

    // CRUD: /api/admin/(services|projects|testimonials)[/:id]
    let mm = p.match(/^\/api\/admin\/(services|projects|testimonials)(?:\/(\d{1,9}))?$/);
    if (mm) {
      const [, table, idStr] = mm;
      const ent = ENTITIES[table];
      const id = idStr ? Number(idStr) : null;
      const cols = ent.fields;
      if (m === 'POST' && !id) {
        const data = ent.clean(await readJson(req));
        const [row] = await db.query(`INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map((_, i) => '$' + (i + 1)).join(', ')}) RETURNING *`, cols.map((c) => data[c]));
        await audit(sess.admin_id, `${table}.create`, row.id);
        return send(res, 201, row);
      }
      if (m === 'PUT' && id) {
        const data = ent.clean(await readJson(req));
        const [row] = await db.query(`UPDATE ${table} SET ${cols.map((c, i) => `${c} = $${i + 1}`).join(', ')} WHERE id = $${cols.length + 1} RETURNING *`, [...cols.map((c) => data[c]), id]);
        if (!row) throw new HttpError(404, 'Item não encontrado.');
        await audit(sess.admin_id, `${table}.update`, id);
        return send(res, 200, row);
      }
      if (m === 'DELETE' && id) {
        const r = await db.query(`DELETE FROM ${table} WHERE id = $1 RETURNING id`, [id]);
        if (!r.length) throw new HttpError(404, 'Item não encontrado.');
        await audit(sess.admin_id, `${table}.delete`, id);
        return send(res, 200, { ok: true });
      }
      throw new HttpError(405, 'Método não permitido.');
    }

    // Mensagens recebidas pelo formulário
    if (p === '/api/admin/messages' && m === 'GET') {
      return send(res, 200, await db.query('SELECT id, name, email, phone, subject, message, is_read, created_at FROM messages ORDER BY id DESC LIMIT 500'));
    }
    mm = p.match(/^\/api\/admin\/messages\/(\d{1,9})$/);
    if (mm) {
      const id = Number(mm[1]);
      if (m === 'PATCH') {
        const b = await readJson(req);
        const r = await db.query('UPDATE messages SET is_read = $1 WHERE id = $2 RETURNING id', [S.toBool(b.is_read), id]);
        if (!r.length) throw new HttpError(404, 'Mensagem não encontrada.');
        return send(res, 200, { ok: true });
      }
      if (m === 'DELETE') {
        const r = await db.query('DELETE FROM messages WHERE id = $1 RETURNING id', [id]);
        if (!r.length) throw new HttpError(404, 'Mensagem não encontrada.');
        await audit(sess.admin_id, 'messages.delete', id);
        return send(res, 200, { ok: true });
      }
      throw new HttpError(405, 'Método não permitido.');
    }

    // Upload de imagem (corpo binário). Valida o conteúdo real do arquivo e guarda no banco.
    if (p === '/api/admin/upload' && m === 'POST') {
      const ct = String(req.headers['content-type'] || '').toLowerCase();
      if (!/^image\/(png|jpeg|webp|gif)$/.test(ct)) throw new HttpError(415, 'Envie uma imagem PNG, JPG, WEBP ou GIF.');
      const buf = await readBody(req, 3 * 1024 * 1024);
      const kind = S.detectImage(buf);
      if (!kind) throw new HttpError(415, 'Arquivo não é uma imagem válida.');
      const name = `${crypto.randomBytes(16).toString('hex')}.${kind}`;
      await db.query('INSERT INTO uploads (id, mime, data_b64, size, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [name, IMG_MIME[kind], buf.toString('base64'), buf.length, Date.now()]);
      await audit(sess.admin_id, 'upload', name);
      return send(res, 201, { url: `/uploads/${name}` });
    }

    if (p === '/api/admin/password' && m === 'POST') {
      const b = await readJson(req);
      const [admin] = await db.query('SELECT * FROM admins WHERE id = $1', [sess.admin_id]);
      if (!S.verifyPassword(String(b.current || ''), admin.pass_hash)) throw new HttpError(400, 'Senha atual incorreta.');
      const probs = S.passwordProblems(b.new);
      if (probs.length) throw new S.ValidationError('A nova senha precisa de: ' + probs.join(', ') + '.');
      await db.query('UPDATE admins SET pass_hash = $1 WHERE id = $2 RETURNING id', [S.hashPassword(b.new), admin.id]);
      // encerra todas as outras sessões
      await db.query('DELETE FROM sessions WHERE admin_id = $1 AND token_hash <> $2 RETURNING token_hash', [admin.id, sess.token_hash]);
      await audit(admin.id, 'password.change');
      return send(res, 200, { ok: true });
    }

    if (p === '/api/admin/audit' && m === 'GET') {
      return send(res, 200, await db.query('SELECT action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 100'));
    }

    throw new HttpError(404, 'Não encontrado.');
  }

  // ---------------- Imagens enviadas (do banco) ----------------
  async function serveUpload(req, res, id) {
    const [row] = await db.query('SELECT mime, data_b64 FROM uploads WHERE id = $1', [id]);
    if (!row) throw new HttpError(404, 'Não encontrado.');
    const buf = Buffer.from(row.data_b64, 'base64');
    res.writeHead(200, { ...headers, 'Content-Type': row.mime, 'Content-Length': buf.length, 'Cache-Control': 'public, max-age=31536000, immutable' });
    res.end(req.method === 'HEAD' ? undefined : buf);
  }

  // ---------------- Arquivos estáticos (servidor local) ----------------
  function serveFile(req, res, baseDir, relPath) {
    if (relPath.includes('\0')) throw new HttpError(400, 'Caminho inválido.');
    const full = path.resolve(baseDir, '.' + path.posix.normalize('/' + relPath));
    if (full !== baseDir && !full.startsWith(baseDir + path.sep)) throw new HttpError(403, 'Acesso negado.');
    let st;
    try { st = fs.statSync(full); } catch { throw new HttpError(404, 'Página não encontrada.'); }
    if (st.isDirectory()) return serveFile(req, res, baseDir, path.posix.join(relPath, 'index.html'));
    const ext = path.extname(full).toLowerCase();
    const type = MIME[ext];
    if (!type || path.basename(full).startsWith('.')) throw new HttpError(404, 'Página não encontrada.');
    const etag = `W/"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
    const h = { ...headers, 'Content-Type': type, 'Cache-Control': 'no-cache', ETag: etag };
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, h); return res.end(); }
    h['Content-Length'] = st.size;
    res.writeHead(200, h);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(full).pipe(res);
  }

  // ---------------- Handler principal ----------------
  async function handler(req, res) {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
      let pathname;
      try { pathname = decodeURIComponent(url.pathname); } catch { throw new HttpError(400, 'Caminho inválido.'); }

      if (url.pathname.startsWith('/api/')) { await ready(); return await handleApi(req, res, url); }

      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Método não permitido.');
      if (pathname.startsWith('/uploads/')) {
        const mu = pathname.match(UPLOAD_RE);
        if (!mu) throw new HttpError(404, 'Não encontrado.');
        await ready();
        return await serveUpload(req, res, mu[1]);
      }
      if (!serveStatic) throw new HttpError(404, 'Não encontrado.');
      if (pathname === '/admin') { res.writeHead(301, { ...headers, Location: '/admin/' }); return res.end(); }
      return serveFile(req, res, publicDir, pathname);
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) log('[erro]', err && err.stack ? err.stack : err);
      const msg = err.expose ? err.message : 'Erro interno. Tente novamente.';
      if (serveStatic && url && !url.pathname.startsWith('/api/') && status === 404 && (req.headers.accept || '').includes('text/html')) {
        try { return send(res, 404, fs.readFileSync(path.join(publicDir, '404.html')), { 'Content-Type': 'text/html; charset=utf-8' }); } catch { /* sem 404.html */ }
      }
      if (!res.headersSent) send(res, status, { erro: msg }, err.headers || {});
      else res.end();
    }
  }

  return { handler, db, limits, ready, result };
}

module.exports = { createApp };

'use strict';
/**
 * Aplicação HTTP (sem dependências externas).
 *  - API pública:   GET /api/site, POST /api/contato
 *  - API admin:     /api/admin/*  (sessão + CSRF)
 *  - Arquivos:      /public  e  /uploads
 */
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { openDb, DEFAULT_SETTINGS } = require('./db');
const S = require('./security');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2', '.xml': 'application/xml; charset=utf-8', '.webmanifest': 'application/manifest+json'
};

const ICONS = ['code', 'cloud', 'shield', 'headset', 'network', 'bot', 'brain', 'workflow', 'chart', 'sparkles', 'mobile', 'database'];
const URL_SETTINGS = ['github', 'linkedin', 'youtube', 'instagram'];
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 horas
const COOKIE = 'mt_sess';

class HttpError extends Error {
  constructor(status, msg, headers) { super(msg); this.status = status; this.expose = true; this.headers = headers; }
}

function createApp(opts = {}) {
  const root = opts.root || path.join(__dirname, '..');
  const publicDir = path.join(root, 'public');
  const uploadsDir = opts.uploadsDir || path.join(root, 'data', 'uploads');
  const dbFile = opts.dbFile || path.join(root, 'data', 'site.db');
  const https = !!opts.https;
  const trustProxy = !!opts.trustProxy;
  const log = opts.log || ((...a) => console.log(...a));
  fs.mkdirSync(uploadsDir, { recursive: true });

  const db = openDb(dbFile);
  const headers = S.securityHeaders({ https });

  const limits = {
    login: new S.RateLimiter({ windowMs: 15 * 60_000, max: 5 }),       // 5 falhas / 15 min por IP
    loginUser: new S.RateLimiter({ windowMs: 15 * 60_000, max: 10 }),  // 10 falhas / 15 min por usuário
    contact: new S.RateLimiter({ windowMs: 60 * 60_000, max: 5 }),     // 5 mensagens / hora por IP
    api: new S.RateLimiter({ windowMs: 60_000, max: opts.apiMax || 240 }) // 240 req/min por IP (geral)
  };

  // ---------------- Helpers ----------------
  const clientIp = (req) => {
    if (trustProxy) {
      const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (xf) return xf;
    }
    return req.socket.remoteAddress || 'desconhecido';
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
      const chunks = []; let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) { reject(new HttpError(413, 'Conteúdo muito grande.')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
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

  function getSession(req) {
    const tok = parseCookies(req)[COOKIE];
    if (!tok || tok.length > 100) return null;
    const row = db.prepare(
      'SELECT s.token_hash, s.csrf, s.expires_at, a.id AS admin_id, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ?'
    ).get(S.sha256(tok));
    if (!row) return null;
    if (row.expires_at < Date.now()) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
      return null;
    }
    return row;
  }

  /** Bloqueia requisições vindas de outros sites (defesa extra contra CSRF). */
  function checkOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return; // navegadores sempre enviam Origin em POST/PUT/DELETE via fetch
    let host;
    try { host = new URL(origin).host; } catch { throw new HttpError(403, 'Origem inválida.'); }
    const expected = trustProxy ? (req.headers['x-forwarded-host'] || req.headers.host) : req.headers.host;
    if (host !== expected) throw new HttpError(403, 'Origem não permitida.');
  }

  function requireAdmin(req, { mutating }) {
    const sess = getSession(req);
    if (!sess) throw new HttpError(401, 'Faça login para continuar.');
    if (mutating) {
      checkOrigin(req);
      if (!S.safeEqual(req.headers['x-csrf-token'], sess.csrf)) throw new HttpError(403, 'Token de segurança (CSRF) inválido. Recarregue a página.');
    }
    return sess;
  }

  const audit = (adminId, action, detail = '') =>
    db.prepare('INSERT INTO audit_log (admin_id, action, detail) VALUES (?, ?, ?)').run(adminId, action, String(detail).slice(0, 300));

  // ---------------- Leitura do conteúdo ----------------
  function getSettings() {
    const out = {};
    for (const r of db.prepare('SELECT key, value FROM settings').all()) out[r.key] = r.value;
    return out;
  }

  function getContent({ includeInactive = false } = {}) {
    const w = includeInactive ? '' : 'WHERE active = 1';
    return {
      settings: getSettings(),
      services: db.prepare(`SELECT * FROM services ${w} ORDER BY sort_order, id`).all(),
      projects: db.prepare(`SELECT * FROM projects ${w} ORDER BY sort_order, id`).all(),
      testimonials: db.prepare(`SELECT * FROM testimonials ${w} ORDER BY sort_order, id`).all()
    };
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
    if (p === '/api/site' && m === 'GET') return send(res, 200, getContent());

    if (p === '/api/contato' && m === 'POST') {
      checkOrigin(req);
      const b = await readJson(req);
      if (b.website) return send(res, 200, { ok: true }); // honeypot: robôs preenchem campo oculto
      if (limits.contact.hit(ip)) throw new HttpError(429, 'Você enviou muitas mensagens. Tente novamente mais tarde ou chame no WhatsApp.');
      const name = S.cleanText(b.name, 100);
      const email = S.cleanText(b.email, 254);
      const phone = S.cleanText(b.phone, 30);
      const subject = S.cleanText(b.subject, 150);
      const message = S.cleanText(b.message, 3000, { multiline: true });
      if (name.length < 2) throw new S.ValidationError('Informe seu nome.');
      if (!S.isEmail(email)) throw new S.ValidationError('Informe um e-mail válido.');
      if (phone && !/^[\d\s()+-]{8,30}$/.test(phone)) throw new S.ValidationError('Telefone inválido.');
      if (message.length < 10) throw new S.ValidationError('A mensagem deve ter pelo menos 10 caracteres.');
      db.prepare('INSERT INTO messages (name, email, phone, subject, message, ip_hash) VALUES (?, ?, ?, ?, ?, ?)')
        .run(name, email, phone, subject, message, S.sha256(ip).slice(0, 16));
      return send(res, 201, { ok: true, mensagem: 'Mensagem enviada! Retornarei em breve.' });
    }

    // ---- Autenticação ----
    if (p === '/api/admin/login' && m === 'POST') {
      checkOrigin(req);
      if (limits.login.isBlocked(ip)) {
        throw new HttpError(429, 'Muitas tentativas de login. Aguarde alguns minutos.', { 'Retry-After': String(limits.login.retryAfter(ip)) });
      }
      const b = await readJson(req);
      const username = S.cleanText(b.username, 60).toLowerCase();
      const password = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
      if (limits.loginUser.isBlocked(username)) throw new HttpError(429, 'Conta temporariamente bloqueada por excesso de tentativas.');
      const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
      const ok = S.verifyPassword(password, admin ? admin.pass_hash : S.DUMMY_HASH) && !!admin;
      if (!ok) {
        limits.login.hit(ip);
        limits.loginUser.hit(username);
        throw new HttpError(401, 'Usuário ou senha incorretos.');
      }
      limits.login.reset(ip); limits.loginUser.reset(username);
      const token = S.randomToken(32);
      const csrf = S.randomToken(24);
      db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
      db.prepare('INSERT INTO sessions (token_hash, admin_id, csrf, expires_at) VALUES (?, ?, ?, ?)')
        .run(S.sha256(token), admin.id, csrf, Date.now() + SESSION_TTL_MS);
      audit(admin.id, 'login', S.sha256(ip).slice(0, 12));
      return send(res, 200, { ok: true, username: admin.username, csrf }, { 'Set-Cookie': cookieStr(token, SESSION_TTL_MS / 1000) });
    }

    if (p === '/api/admin/logout' && m === 'POST') {
      const sess = requireAdmin(req, { mutating: true });
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sess.token_hash);
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookieStr('', 0) });
    }

    if (p === '/api/admin/me' && m === 'GET') {
      const sess = requireAdmin(req, { mutating: false });
      return send(res, 200, { username: sess.username, csrf: sess.csrf });
    }

    if (!p.startsWith('/api/admin/')) throw new HttpError(404, 'Não encontrado.');

    // ---- Área administrativa (todas exigem login) ----
    const mutating = m !== 'GET';
    const sess = requireAdmin(req, { mutating });

    if (p === '/api/admin/data' && m === 'GET') {
      const unread = db.prepare('SELECT COUNT(*) AS n FROM messages WHERE is_read = 0').get().n;
      return send(res, 200, { ...getContent({ includeInactive: true }), icons: ICONS, unread });
    }

    if (p === '/api/admin/settings' && m === 'PUT') {
      const b = await readJson(req);
      const upd = db.prepare('UPDATE settings SET value = ? WHERE key = ?');
      const changes = {};
      for (const key of Object.keys(b)) {
        if (!Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key)) continue; // ignora chaves desconhecidas
        changes[key] = cleanSetting(key, b[key]);
      }
      db.exec('BEGIN');
      try { for (const [k, v] of Object.entries(changes)) upd.run(v, k); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
      audit(sess.admin_id, 'settings', Object.keys(changes).join(','));
      return send(res, 200, { ok: true, settings: getSettings() });
    }

    // CRUD: /api/admin/(services|projects|testimonials)[/:id]
    let mm = p.match(/^\/api\/admin\/(services|projects|testimonials)(?:\/(\d{1,9}))?$/);
    if (mm) {
      const [, table, idStr] = mm;
      const ent = ENTITIES[table];
      const id = idStr ? Number(idStr) : null;
      if (m === 'POST' && !id) {
        const data = ent.clean(await readJson(req));
        const cols = ent.fields;
        const r = db.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...cols.map((c) => data[c]));
        audit(sess.admin_id, `${table}.create`, r.lastInsertRowid);
        return send(res, 201, db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(r.lastInsertRowid));
      }
      if (m === 'PUT' && id) {
        const data = ent.clean(await readJson(req));
        const cols = ent.fields;
        const r = db.prepare(`UPDATE ${table} SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(...cols.map((c) => data[c]), id);
        if (!r.changes) throw new HttpError(404, 'Item não encontrado.');
        audit(sess.admin_id, `${table}.update`, id);
        return send(res, 200, db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id));
      }
      if (m === 'DELETE' && id) {
        const r = db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
        if (!r.changes) throw new HttpError(404, 'Item não encontrado.');
        audit(sess.admin_id, `${table}.delete`, id);
        return send(res, 200, { ok: true });
      }
      throw new HttpError(405, 'Método não permitido.');
    }

    // Mensagens recebidas pelo formulário
    if (p === '/api/admin/messages' && m === 'GET') {
      return send(res, 200, db.prepare('SELECT id, name, email, phone, subject, message, is_read, created_at FROM messages ORDER BY id DESC LIMIT 500').all());
    }
    mm = p.match(/^\/api\/admin\/messages\/(\d{1,9})$/);
    if (mm) {
      const id = Number(mm[1]);
      if (m === 'PATCH') {
        const b = await readJson(req);
        const r = db.prepare('UPDATE messages SET is_read = ? WHERE id = ?').run(S.toBool(b.is_read), id);
        if (!r.changes) throw new HttpError(404, 'Mensagem não encontrada.');
        return send(res, 200, { ok: true });
      }
      if (m === 'DELETE') {
        const r = db.prepare('DELETE FROM messages WHERE id = ?').run(id);
        if (!r.changes) throw new HttpError(404, 'Mensagem não encontrada.');
        audit(sess.admin_id, 'messages.delete', id);
        return send(res, 200, { ok: true });
      }
      throw new HttpError(405, 'Método não permitido.');
    }

    // Upload de imagem (corpo binário). Valida o conteúdo real do arquivo, não só a extensão.
    if (p === '/api/admin/upload' && m === 'POST') {
      const ct = String(req.headers['content-type'] || '').toLowerCase();
      if (!/^image\/(png|jpeg|webp|gif)$/.test(ct)) throw new HttpError(415, 'Envie uma imagem PNG, JPG, WEBP ou GIF.');
      const buf = await readBody(req, 3 * 1024 * 1024);
      const kind = S.detectImage(buf);
      if (!kind) throw new HttpError(415, 'Arquivo não é uma imagem válida.');
      const name = `${crypto.randomBytes(16).toString('hex')}.${kind}`;
      fs.writeFileSync(path.join(uploadsDir, name), buf, { flag: 'wx' });
      audit(sess.admin_id, 'upload', name);
      return send(res, 201, { url: `/uploads/${name}` });
    }

    if (p === '/api/admin/password' && m === 'POST') {
      const b = await readJson(req);
      const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(sess.admin_id);
      if (!S.verifyPassword(String(b.current || ''), admin.pass_hash)) throw new HttpError(400, 'Senha atual incorreta.');
      const probs = S.passwordProblems(b.new);
      if (probs.length) throw new S.ValidationError('A nova senha precisa de: ' + probs.join(', ') + '.');
      db.prepare('UPDATE admins SET pass_hash = ? WHERE id = ?').run(S.hashPassword(b.new), admin.id);
      // encerra todas as outras sessões
      db.prepare('DELETE FROM sessions WHERE admin_id = ? AND token_hash <> ?').run(admin.id, sess.token_hash);
      audit(admin.id, 'password.change');
      return send(res, 200, { ok: true });
    }

    if (p === '/api/admin/audit' && m === 'GET') {
      return send(res, 200, db.prepare('SELECT action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 100').all());
    }

    throw new HttpError(404, 'Não encontrado.');
  }

  // ---------------- Arquivos estáticos ----------------
  function serveFile(req, res, baseDir, relPath, { cache = 'no-cache' } = {}) {
    if (relPath.includes('\0')) throw new HttpError(400, 'Caminho inválido.');
    const full = path.resolve(baseDir, '.' + path.posix.normalize('/' + relPath));
    if (full !== baseDir && !full.startsWith(baseDir + path.sep)) throw new HttpError(403, 'Acesso negado.');
    let st;
    try { st = fs.statSync(full); } catch { throw new HttpError(404, 'Página não encontrada.'); }
    if (st.isDirectory()) return serveFile(req, res, baseDir, path.posix.join(relPath, 'index.html'), { cache });
    const ext = path.extname(full).toLowerCase();
    const type = MIME[ext];
    if (!type || path.basename(full).startsWith('.')) throw new HttpError(404, 'Página não encontrada.');
    const etag = `W/"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
    const h = { ...headers, 'Content-Type': type, 'Cache-Control': cache, ETag: etag };
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
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Método não permitido.');
      let pathname;
      try { pathname = decodeURIComponent(url.pathname); } catch { throw new HttpError(400, 'Caminho inválido.'); }
      if (pathname.startsWith('/uploads/')) {
        if (!/^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(pathname)) throw new HttpError(404, 'Não encontrado.');
        return serveFile(req, res, uploadsDir, pathname.slice('/uploads'.length), { cache: 'public, max-age=604800' });
      }
      if (pathname === '/admin') { res.writeHead(301, { ...headers, Location: '/admin/' }); return res.end(); }
      return serveFile(req, res, publicDir, pathname);
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) log('[erro]', err && err.stack ? err.stack : err);
      const msg = err.expose ? err.message : 'Erro interno. Tente novamente.';
      if (url && !url.pathname.startsWith('/api/') && status === 404 && (req.headers.accept || '').includes('text/html')) {
        try { return send(res, 404, fs.readFileSync(path.join(publicDir, '404.html')), { 'Content-Type': 'text/html; charset=utf-8' }); } catch { /* sem 404.html */ }
      }
      if (!res.headersSent) send(res, status, { erro: msg }, err.headers || {});
      else res.end();
    }
  }

  return { handler, db, limits };
}

module.exports = { createApp };

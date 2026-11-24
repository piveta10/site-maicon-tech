'use strict';
/**
 * Testes de segurança automatizados.
 * Rodar:  npm test
 *
 * Cada grupo sobe um servidor isolado (porta aleatória + banco temporário).
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp } = require('../src/app');
const { createTestDb } = require('./helpers/test-db');
const S = require('../src/security');

const ADMIN = { username: 'admin', password: 'SenhaForte123' };
const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

/** Primeira linha de uma consulta */
const one = async (s, sql, params = []) => (await s.app.db.query(sql, params))[0];

async function startServer(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mt-test-'));
  const tdb = createTestDb(dir);
  const app = createApp({ db: tdb.db, log: () => {}, adminUser: ADMIN.username, adminPassword: ADMIN.password, ...opts });
  await app.ready();
  const server = http.createServer(app.handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    app, base, dir,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(async () => { await tdb.drop(); fs.rmSync(dir, { recursive: true, force: true }); r(); }); })
  };
}

async function req(base, method, p, { json, body, headers = {}, cookie } = {}) {
  const h = { ...headers };
  if (json !== undefined) { h['Content-Type'] = h['Content-Type'] || 'application/json'; body = JSON.stringify(json); }
  if (cookie) h.Cookie = cookie;
  const r = await fetch(base + p, { method, headers: h, body, redirect: 'manual' });
  const text = await r.text();
  let data = null; try { data = JSON.parse(text); } catch { /* não-JSON */ }
  return { status: r.status, headers: r.headers, text, data };
}

/** Requisição "crua" (sem normalização de URL pelo fetch) — para testar path traversal */
function rawGet(base, rawPath) {
  const { port } = new URL(base);
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(`GET ${rawPath} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`));
    let out = ''; s.on('data', (d) => { out += d; }); s.on('end', () => resolve(out)); s.on('error', reject);
  });
}

async function login(base) {
  const r = await req(base, 'POST', '/api/admin/login', { json: ADMIN });
  assert.equal(r.status, 200, 'login deveria funcionar');
  const cookie = r.headers.get('set-cookie').split(';')[0];
  return { cookie, csrf: r.data.csrf, setCookie: r.headers.get('set-cookie') };
}

// =========================================================
describe('1. Cabeçalhos de segurança', () => {
  let s; before(async () => { s = await startServer(); }); after(() => s.close());

  test('HTML e API enviam CSP, anti-clickjacking, nosniff e afins', async () => {
    for (const p of ['/', '/api/site', '/admin/']) {
      const r = await req(s.base, 'GET', p);
      assert.equal(r.status, 200, p);
      const csp = r.headers.get('content-security-policy');
      assert.match(csp, /default-src 'self'/);
      assert.match(csp, /script-src 'self'(;|$)/, 'scripts inline devem ser proibidos');
      assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.equal(r.headers.get('x-frame-options'), 'DENY');
      assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
      assert.ok(r.headers.get('referrer-policy'));
      assert.ok(r.headers.get('permissions-policy'));
      assert.equal(r.headers.get('x-powered-by'), null, 'não deve revelar tecnologia do servidor');
    }
  });

  test('sem CORS liberado para outros sites', async () => {
    const r = await req(s.base, 'GET', '/api/site', { headers: { Origin: 'https://site-malicioso.com' } });
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  });

  test('HSTS e cookie Secure quando HTTPS=1', async () => {
    const h = await startServer({ https: true });
    try {
      const r = await req(h.base, 'GET', '/');
      assert.match(r.headers.get('strict-transport-security'), /max-age=\d+/);
      const l = await login(h.base);
      assert.match(l.setCookie, /;\s*Secure/);
    } finally { await h.close(); }
  });
});

// =========================================================
describe('2. Acesso a arquivos (path traversal)', () => {
  let s; before(async () => { s = await startServer(); }); after(() => s.close());

  const attacks = [
    '/../server.js', '/../../etc/passwd', '/%2e%2e/server.js', '/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/..%2fsrc%2fapp.js', '/..%5csrc%5capp.js', '/css/..%2f..%2fserver.js', '/%00', '/index.html%00.js',
    '/../data/site.db', '/../.env', '/.env', '/../package.json', '/uploads/../../server.js',
    '/uploads/..%2f..%2fserver.js', '/uploads/qualquer.html', '/src/app.js', '/data/site.db', '/%c0%ae%c0%ae/server.js'
  ];
  for (const a of attacks) {
    test(`bloqueia ${a}`, async () => {
      const out = await rawGet(s.base, a);
      const status = Number(out.split(' ')[1]);
      assert.ok(status >= 400 || status === 200, `status inesperado ${status}`);
      assert.doesNotMatch(out, /createApp|require\(|root:x:0|SQLite format|"scripts"|ADMIN_PASSWORD/, `vazou conteúdo em ${a}`);
      if (status === 200) assert.match(out, /<!DOCTYPE html>/, 'só pode devolver a página do site');
    });
  }
});

// =========================================================
describe('3. Autenticação do painel', () => {
  let s; before(async () => { s = await startServer(); }); after(() => s.close());

  const protectedRoutes = [
    ['GET', '/api/admin/data'], ['GET', '/api/admin/messages'], ['GET', '/api/admin/audit'], ['GET', '/api/admin/me'],
    ['PUT', '/api/admin/settings'], ['POST', '/api/admin/projects'], ['PUT', '/api/admin/projects/1'],
    ['DELETE', '/api/admin/projects/1'], ['DELETE', '/api/admin/messages/1'], ['POST', '/api/admin/upload'], ['POST', '/api/admin/password']
  ];
  for (const [m, p] of protectedRoutes) {
    test(`${m} ${p} exige login`, async () => {
      const r = await req(s.base, m, p, m === 'GET' ? {} : { json: {} });
      assert.equal(r.status, 401);
    });
  }

  test('cookie de sessão falsificado é rejeitado', async () => {
    const r = await req(s.base, 'GET', '/api/admin/data', { cookie: 'mt_sess=' + 'A'.repeat(43) });
    assert.equal(r.status, 401);
  });

  test('injeção de SQL no login não funciona', async () => {
    for (const username of ["admin' --", "' OR '1'='1", "admin'/*", '" OR 1=1 --']) {
      const r = await req(s.base, 'POST', '/api/admin/login', { json: { username, password: "' OR '1'='1" } });
      assert.equal(r.status, 401, username);
    }
  });

  test('cookie de sessão é HttpOnly e SameSite=Strict; senha não volta na resposta', async () => {
    await s.app.limits.login.reset('127.0.0.1');
    const l = await login(s.base);
    assert.match(l.setCookie, /HttpOnly/);
    assert.match(l.setCookie, /SameSite=Strict/);
    const r = await req(s.base, 'GET', '/api/admin/data', { cookie: l.cookie });
    assert.equal(r.status, 200);
    assert.doesNotMatch(r.text, /pass_hash|scrypt\$/);
  });

  test('senhas ficam com hash scrypt no banco (nunca em texto)', async () => {
    const row = await one(s, 'SELECT pass_hash FROM admins');
    assert.match(row.pass_hash, /^scrypt\$/);
    assert.ok(!row.pass_hash.includes(ADMIN.password));
  });

  test('tokens de sessão são guardados como hash no banco', async () => {
    const l = await login(s.base);
    const token = l.cookie.split('=')[1];
    const raw = Number((await one(s, 'SELECT CAST(COUNT(*) AS INTEGER) AS n FROM sessions WHERE token_hash = $1', [token])).n);
    assert.equal(raw, 0, 'token não pode estar em texto puro');
  });

  test('logout invalida a sessão', async () => {
    const l = await login(s.base);
    const out = await req(s.base, 'POST', '/api/admin/logout', { cookie: l.cookie, json: {}, headers: { 'X-CSRF-Token': l.csrf } });
    assert.equal(out.status, 200);
    const r = await req(s.base, 'GET', '/api/admin/data', { cookie: l.cookie });
    assert.equal(r.status, 401);
  });

  test('sessão expirada é rejeitada', async () => {
    const l = await login(s.base);
    await s.app.db.query('UPDATE sessions SET expires_at = 1 RETURNING token_hash');
    const r = await req(s.base, 'GET', '/api/admin/data', { cookie: l.cookie });
    assert.equal(r.status, 401);
  });

  test('força bruta: bloqueia após 5 tentativas erradas', async () => {
    await s.app.limits.login.reset('127.0.0.1');
    await s.app.limits.loginUser.reset('admin');
    let last;
    for (let i = 0; i < 6; i++) last = await req(s.base, 'POST', '/api/admin/login', { json: { username: 'admin', password: 'errada' + i } });
    assert.equal(last.status, 429);
    // mesmo com a senha certa continua bloqueado
    const r = await req(s.base, 'POST', '/api/admin/login', { json: ADMIN });
    assert.equal(r.status, 429);
    assert.ok(r.headers.get('retry-after'));
  });

  test('mensagem de erro não revela se o usuário existe', async () => {
    const h = await startServer();
    try {
      const a = await req(h.base, 'POST', '/api/admin/login', { json: { username: 'admin', password: 'x' } });
      const b = await req(h.base, 'POST', '/api/admin/login', { json: { username: 'naoexiste', password: 'x' } });
      assert.equal(a.status, b.status);
      assert.equal(a.data.erro, b.data.erro);
    } finally { await h.close(); }
  });
});

// =========================================================
describe('4. CSRF (requisições forjadas de outros sites)', () => {
  let s, l; before(async () => { s = await startServer(); l = await login(s.base); }); after(() => s.close());

  test('sem token CSRF → 403', async () => {
    const r = await req(s.base, 'PUT', '/api/admin/settings', { cookie: l.cookie, json: { nome: 'Hacker' } });
    assert.equal(r.status, 403);
  });
  test('token CSRF errado → 403', async () => {
    const r = await req(s.base, 'PUT', '/api/admin/settings', { cookie: l.cookie, json: { nome: 'Hacker' }, headers: { 'X-CSRF-Token': 'x'.repeat(32) } });
    assert.equal(r.status, 403);
  });
  test('origem de outro site → 403 (mesmo com token)', async () => {
    const r = await req(s.base, 'PUT', '/api/admin/settings', { cookie: l.cookie, json: { nome: 'Hacker' }, headers: { 'X-CSRF-Token': l.csrf, Origin: 'https://site-malicioso.com' } });
    assert.equal(r.status, 403);
  });
  test('formulário HTML de outro site (form-urlencoded) é recusado', async () => {
    const r = await req(s.base, 'PUT', '/api/admin/settings', { cookie: l.cookie, body: 'nome=Hacker', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': l.csrf } });
    assert.equal(r.status, 415);
  });
  test('com token e origem corretos → 200', async () => {
    const r = await req(s.base, 'PUT', '/api/admin/settings', { cookie: l.cookie, json: { nome: 'Maicon Piveta' }, headers: { 'X-CSRF-Token': l.csrf, Origin: s.base } });
    assert.equal(r.status, 200);
  });
  test('nada foi alterado pelas tentativas de ataque', async () => {
    const v = (await one(s, "SELECT value FROM settings WHERE key = 'nome'")).value;
    assert.equal(v, 'Maicon Piveta');
  });
});

// =========================================================
describe('5. Validação de dados, XSS e links maliciosos', () => {
  let s, l, H;
  before(async () => { s = await startServer(); l = await login(s.base); H = { 'X-CSRF-Token': l.csrf }; });
  after(() => s.close());
  const adm = (m, p, json) => req(s.base, m, p, { cookie: l.cookie, json, headers: H });

  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox', 'file:///etc/passwd', '//evil.com', 'https://user:pass@evil.com']) {
    test(`link de projeto recusado: ${bad}`, async () => {
      const r = await adm('POST', '/api/admin/projects', { title: 'X', link_url: bad });
      assert.equal(r.status, 400);
    });
  }

  test('links em redes sociais também são validados', async () => {
    const r = await adm('PUT', '/api/admin/settings', { github: 'javascript:alert(1)' });
    assert.equal(r.status, 400);
    const r2 = await adm('PUT', '/api/admin/settings', { email: '"><script>alert(1)</script>' });
    assert.equal(r2.status, 400);
    const r3 = await adm('PUT', '/api/admin/settings', { whatsapp: '123' });
    assert.equal(r3.status, 400);
  });

  test('chaves de configuração desconhecidas são ignoradas', async () => {
    const r = await adm('PUT', '/api/admin/settings', { '__proto__': 'x', 'chave_inventada': 'x', constructor: 'x' });
    assert.equal(r.status, 200);
    const n = Number((await one(s, "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM settings WHERE key IN ('chave_inventada','__proto__','constructor')")).n);
    assert.equal(n, 0);
  });

  test('XSS armazenado: conteúdo HTML é salvo como texto e servido como JSON', async () => {
    const payload = '<img src=x onerror=alert(1)><script>alert(1)</script>';
    const r = await adm('POST', '/api/admin/projects', { title: payload, description: payload });
    assert.equal(r.status, 201);
    const site = await req(s.base, 'GET', '/api/site');
    assert.match(site.headers.get('content-type'), /application\/json/);
    assert.ok(site.data.projects.some((p) => p.title === payload), 'deve vir como texto puro');
  });

  test('o front-end nunca insere dados com innerHTML (análise do código)', () => {
    for (const f of ['public/js/main.js', 'public/admin/admin.js']) {
      const code = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
      const uses = code.split('\n').filter((ln) => !/^\s*(\/\/|\*|\/\*)/.test(ln) && /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(ln));
      for (const ln of uses) assert.match(ln, /ICONS\[name\]/, `uso perigoso em ${f}: ${ln.trim()}`);
    }
  });

  test('nenhum script/estilo inline no HTML (compatível com CSP rígida)', () => {
    for (const f of ['public/index.html', 'public/admin/index.html', 'public/404.html']) {
      const html = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
      assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, `script inline em ${f}`);
      assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `evento inline (onclick...) em ${f}`);
      assert.doesNotMatch(html, /\sstyle\s*=/i, `style inline em ${f}`);
    }
  });

  test('campos obrigatórios e tamanhos máximos', async () => {
    assert.equal((await adm('POST', '/api/admin/services', { title: '' })).status, 400);
    assert.equal((await adm('POST', '/api/admin/services', { title: 'a'.repeat(5000) })).status, 400);
    assert.equal((await adm('POST', '/api/admin/testimonials', { name: 'Só nome' })).status, 400);
  });

  test('ícone fora da lista vira o padrão', async () => {
    const r = await adm('POST', '/api/admin/services', { title: 'T', icon: '"><svg onload=alert(1)>' });
    assert.equal(r.status, 201);
    assert.equal(r.data.icon, 'code');
  });

  test('IDs inválidos e injeção na URL não funcionam', async () => {
    assert.equal((await adm('DELETE', '/api/admin/projects/1%20OR%201=1')).status, 404);
    assert.equal((await adm('DELETE', '/api/admin/projects/999999')).status, 404);
    assert.equal((await adm('DELETE', "/api/admin/users")).status, 404);
    const n = Number((await one(s, 'SELECT CAST(COUNT(*) AS INTEGER) AS n FROM projects')).n);
    assert.ok(n > 0, 'projetos não podem ter sido apagados');
  });

  test('JSON inválido, tipo errado e corpo gigante são recusados', async () => {
    assert.equal((await req(s.base, 'POST', '/api/contato', { body: '{quebrado', headers: { 'Content-Type': 'application/json' } })).status, 400);
    assert.equal((await req(s.base, 'POST', '/api/contato', { body: '[1,2]', headers: { 'Content-Type': 'application/json' } })).status, 400);
    assert.equal((await req(s.base, 'POST', '/api/contato', { body: 'a=1', headers: { 'Content-Type': 'text/plain' } })).status, 415);
    const big = JSON.stringify({ name: 'x', message: 'a'.repeat(200 * 1024) });
    assert.equal((await req(s.base, 'POST', '/api/contato', { body: big, headers: { 'Content-Type': 'application/json' } })).status, 413);
  });

  test('senha fraca é recusada na troca de senha', async () => {
    const r = await adm('POST', '/api/admin/password', { current: ADMIN.password, new: '123' });
    assert.equal(r.status, 400);
    const r2 = await adm('POST', '/api/admin/password', { current: 'errada', new: 'NovaSenhaForte9' });
    assert.equal(r2.status, 400);
  });

  test('erros internos não expõem detalhes técnicos', async () => {
    const r = await req(s.base, 'GET', '/api/nao-existe');
    assert.equal(r.status, 404);
    assert.doesNotMatch(r.text, /at .*\.js:\d+|Error:|stack/i);
  });
});

// =========================================================
describe('6. Upload de imagens', () => {
  let s, l, H;
  before(async () => { s = await startServer(); l = await login(s.base); H = { 'X-CSRF-Token': l.csrf }; });
  after(() => s.close());
  const up = (body, type) => req(s.base, 'POST', '/api/admin/upload', { cookie: l.cookie, body, headers: { ...H, 'Content-Type': type } });

  test('HTML disfarçado de imagem é recusado', async () => {
    assert.equal((await up(Buffer.from('<html><script>alert(1)</script></html>'.padEnd(64)), 'image/png')).status, 415);
  });
  test('SVG (pode conter script) é recusado', async () => {
    assert.equal((await up(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'), 'image/svg+xml')).status, 415);
  });
  test('arquivo acima de 3 MB é recusado', async () => {
    const big = Buffer.concat([PNG_1PX, Buffer.alloc(3.5 * 1024 * 1024)]);
    assert.equal((await up(big, 'image/png')).status, 413);
  });
  test('PNG válido é aceito, com nome aleatório e servido com tipo correto', async () => {
    const r = await up(PNG_1PX, 'image/png');
    assert.equal(r.status, 201);
    assert.match(r.data.url, /^\/uploads\/[a-f0-9]{32}\.png$/);
    const g = await fetch(s.base + r.data.url);
    assert.equal(g.status, 200);
    assert.equal(g.headers.get('content-type'), 'image/png');
    assert.equal(g.headers.get('x-content-type-options'), 'nosniff');
  });
  test('upload sem login é recusado', async () => {
    const r = await req(s.base, 'POST', '/api/admin/upload', { body: PNG_1PX, headers: { 'Content-Type': 'image/png' } });
    assert.equal(r.status, 401);
  });
});

// =========================================================
describe('7. Formulário de contato (anti-spam)', () => {
  let s; before(async () => { s = await startServer(); }); after(() => s.close());
  const send = (json) => req(s.base, 'POST', '/api/contato', { json });

  test('valida e-mail, nome e mensagem', async () => {
    assert.equal((await send({ name: 'Ana', email: 'invalido', message: 'Olá, tudo bem com você?' })).status, 400);
    assert.equal((await send({ name: '', email: 'a@b.com', message: 'Olá, tudo bem com você?' })).status, 400);
    assert.equal((await send({ name: 'Ana', email: 'a@b.com', message: 'curta' })).status, 400);
    assert.equal((await send({ name: { $ne: 1 }, email: 'a@b.com', message: 'Olá, tudo bem com você?' })).status, 400);
  });

  test('robôs que preenchem o campo oculto são descartados silenciosamente', async () => {
    const r = await send({ name: 'Bot', email: 'bot@spam.com', message: 'Compre agora!!!!!!', website: 'http://spam' });
    assert.equal(r.status, 200);
    assert.equal(Number((await one(s, "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM messages WHERE name = 'Bot'")).n), 0);
  });

  test('mensagem válida é salva no banco; IP guardado apenas como hash (LGPD)', async () => {
    const r = await send({ name: 'Ana', email: 'ana@exemplo.com', phone: '(47) 99999-0000', message: '<script>alert(1)</script> quero um chatbot' });
    assert.equal(r.status, 201);
    const row = await one(s, "SELECT * FROM messages WHERE name = 'Ana'");
    assert.ok(row);
    assert.ok(!row.ip_hash.includes('127.0.0.1'));
  });

  test('limite de 5 mensagens por hora por IP', async () => {
    let last;
    for (let i = 0; i < 6; i++) last = await send({ name: 'Ana', email: 'ana@exemplo.com', message: 'Mensagem de teste número ' + i });
    assert.equal(last.status, 429);
  });

  test('mensagens não são visíveis publicamente', async () => {
    const r = await req(s.base, 'GET', '/api/site');
    assert.doesNotMatch(r.text, /ana@exemplo\.com/);
  });
});

// =========================================================
describe('8. Proteções gerais do servidor', () => {
  let s; before(async () => { s = await startServer({ apiMax: 30 }); }); after(() => s.close());

  test('métodos não permitidos em arquivos estáticos', async () => {
    for (const m of ['POST', 'PUT', 'DELETE', 'PATCH']) assert.equal((await req(s.base, m, '/index.html')).status, 405);
  });

  test('limite geral de requisições na API (anti-abuso)', async () => {
    let last;
    for (let i = 0; i < 35; i++) last = await req(s.base, 'GET', '/api/site');
    assert.equal(last.status, 429);
  });

  test('página 404 amigável', async () => {
    const r = await req(s.base, 'GET', '/pagina-que-nao-existe', { headers: { Accept: 'text/html' } });
    assert.equal(r.status, 404);
    assert.match(r.text, /Página não encontrada/);
  });
});

// =========================================================
describe('9. Configuração para a Vercel', () => {
  test('vercel.json aplica os mesmos cabeçalhos de segurança às páginas estáticas', () => {
    const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
    const all = cfg.headers.find((h) => h.source === '/(.*)');
    assert.ok(all, 'regra de cabeçalhos para todas as páginas');
    const got = Object.fromEntries(all.headers.map((h) => [h.key, h.value]));
    assert.deepEqual(got, S.securityHeaders({ https: true }));
    const adm = cfg.headers.find((h) => h.source === '/admin/(.*)');
    assert.ok(adm.headers.some((h) => h.key === 'X-Robots-Tag'));
  });

  test('vercel.json envia /api e /uploads para a função e publica só a pasta public', () => {
    const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
    assert.equal(cfg.outputDirectory, 'public');
    const dests = cfg.rewrites.map((r) => `${r.source}->${r.destination}`);
    assert.ok(dests.includes('/api/:path*->/api'));
    assert.ok(dests.includes('/uploads/:path*->/api'));
  });

  test('arquivos sensíveis não ficam na pasta pública', () => {
    const pub = path.join(__dirname, '..', 'public');
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [e.name]));
    const files = walk(pub);
    assert.ok(!files.some((f) => /^\.env|\.db$|\.sqlite$|server\.js$|package\.json$/.test(f)), files.join(','));
  });

  test('.gitignore protege .env, banco local e node_modules', () => {
    const gi = fs.readFileSync(path.join(__dirname, '..', '.gitignore'), 'utf8');
    for (const x of ['.env', 'data/', 'node_modules/']) assert.ok(gi.split(/\r?\n/).includes(x), x);
  });

  test('função da Vercel responde com erro amigável se DATABASE_URL faltar', async () => {
    const saved = process.env.DATABASE_URL; delete process.env.DATABASE_URL;
    delete require.cache[require.resolve('../api/index.js')];
    const fn = require('../api/index.js');
    const server = http.createServer(fn);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const r = await fetch(`http://127.0.0.1:${server.address().port}/api/site`);
      assert.equal(r.status, 500);
      const j = await r.json();
      assert.match(j.erro, /variáveis de ambiente/);
      assert.doesNotMatch(JSON.stringify(j), /DATABASE_URL|postgres:\/\//);
    } finally {
      server.close();
      if (saved !== undefined) process.env.DATABASE_URL = saved;
    }
  });

  test('no modo Vercel (serveStatic=false) o servidor não expõe arquivos do projeto', async () => {
    const v = await startServer({ serveStatic: false, trustProxy: true, https: true });
    try {
      for (const p of ['/', '/index.html', '/../server.js', '/src/app.js', '/package.json']) {
        const out = await rawGet(v.base, p);
        assert.match(out, /^HTTP\/1\.1 404/, p);
      }
      const r = await req(v.base, 'GET', '/api/site');
      assert.equal(r.status, 200);
    } finally { await v.close(); }
  });

  test('atrás do proxy da Vercel, o limite de login usa o IP real do visitante', async () => {
    const v = await startServer({ serveStatic: false, trustProxy: true });
    try {
      let last;
      for (let i = 0; i < 6; i++) last = await req(v.base, 'POST', '/api/admin/login', { json: { username: 'x', password: 'y' }, headers: { 'X-Real-IP': '203.0.113.9' } });
      assert.equal(last.status, 429);
      // outro visitante não é afetado
      const other = await req(v.base, 'POST', '/api/admin/login', { json: ADMIN, headers: { 'X-Real-IP': '198.51.100.7' } });
      assert.equal(other.status, 200);
    } finally { await v.close(); }
  });

  test('limites de tentativa ficam no banco (valem entre instâncias serverless)', async () => {
    const tdbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mt-test-'));
    const tdb = createTestDb(tdbDir);
    try {
      const a = createApp({ db: tdb.db, log: () => {} });
      const b = createApp({ db: tdb.db, log: () => {} }); // simula 2ª instância
      await a.ready(); await b.ready();
      for (let i = 0; i < 5; i++) await a.limits.login.hit('1.2.3.4');
      assert.equal(await b.limits.login.isBlocked('1.2.3.4'), true);
    } finally { await tdb.drop(); fs.rmSync(tdbDir, { recursive: true, force: true }); }
  });
});

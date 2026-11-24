'use strict';
/**
 * MaiconTech — servidor do site.
 * Iniciar:  npm start   (ou: node server.js)
 * Configuração: arquivo .env (veja .env.example)
 */
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');

// Carrega variáveis do arquivo .env (sem dependências)
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

const { createApp } = require('./src/app');
const S = require('./src/security');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const app = createApp({
  dbFile: process.env.DB_FILE || path.join(__dirname, 'data', 'site.db'),
  https: process.env.HTTPS === '1',
  trustProxy: process.env.TRUST_PROXY === '1'
});

// Cria o primeiro administrador, se ainda não existir
const count = app.db.prepare('SELECT COUNT(*) AS n FROM admins').get().n;
if (count === 0) {
  const user = (process.env.ADMIN_USER || 'admin').toLowerCase();
  let pass = process.env.ADMIN_PASSWORD;
  let generated = false;
  if (!pass || S.passwordProblems(pass).length) {
    if (pass) console.warn('⚠  ADMIN_PASSWORD do .env é fraca — gerando uma senha forte automaticamente.');
    pass = S.randomToken(12) + 'Aa1';
    generated = true;
  }
  app.db.prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)').run(user, S.hashPassword(pass));
  console.log('\n==============================================');
  console.log(' Administrador criado!');
  console.log(`   Usuário: ${user}`);
  if (generated) console.log(`   Senha:   ${pass}`);
  else console.log('   Senha:   (a definida em ADMIN_PASSWORD no .env)');
  console.log(' Guarde esta senha. Troque-a no painel em /admin');
  console.log('==============================================\n');
}

const server = http.createServer(app.handler);
// Proteções contra conexões lentas/abusivas
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 60;

server.listen(PORT, HOST, () => {
  console.log(`✔ MaiconTech rodando em http://localhost:${PORT}`);
  console.log(`  Painel administrativo: http://localhost:${PORT}/admin`);
});

const shutdown = () => { server.close(() => { app.db.close(); process.exit(0); }); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

'use strict';
/**
 * Vivix — servidor LOCAL (para testar no seu computador).
 * Na Vercel, quem roda é o arquivo api/index.js.
 *
 * Iniciar:  node server.js   (ou: npm.cmd start no PowerShell)
 * Configuração: arquivo .env (veja .env.example)
 *  - Com DATABASE_URL  -> usa o banco Neon (o mesmo da Vercel)
 *  - Sem DATABASE_URL  -> usa um banco SQLite local em data/site.db
 */
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
require('./src/env').loadEnv(path.join(__dirname, '.env'));

const { createApp } = require('./src/app');
const S = require('./src/security');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';

let adminPassword = process.env.ADMIN_PASSWORD;
let generated = false;
if (!adminPassword) { adminPassword = S.randomToken(12) + 'Aa1'; generated = true; }

const app = createApp({
  databaseUrl: process.env.DATABASE_URL || '',
  dbFile: process.env.DB_FILE || path.join(__dirname, 'data', 'site.db'),
  https: process.env.HTTPS === '1',
  trustProxy: process.env.TRUST_PROXY === '1',
  adminUser: process.env.ADMIN_USER || 'admin',
  adminPassword
});

app.ready().then(() => {
  if (app.result.created) {
    console.log('\n==============================================');
    console.log(' Administrador criado!');
    console.log(`   Usuário: ${app.result.created}`);
    console.log(generated ? `   Senha:   ${adminPassword}` : '   Senha:   (a definida em ADMIN_PASSWORD no .env)');
    console.log(' Guarde esta senha. Troque-a no painel em /admin');
    console.log('==============================================\n');
  }
  const server = http.createServer(app.handler);
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 60;
  server.listen(PORT, HOST, () => {
    const banco = process.env.DATABASE_URL ? 'Neon Postgres' : 'SQLite local (data/site.db)';
    console.log(`✔ Vivix rodando em http://localhost:${PORT}`);
    console.log(`  Painel administrativo: http://localhost:${PORT}/admin`);
    console.log(`  Banco de dados: ${banco}`);
  });
  const shutdown = () => server.close(() => { app.db.close().finally(() => process.exit(0)); });
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}).catch((e) => {
  console.error('✖ Não foi possível conectar ao banco de dados:', e.message);
  if (!fs.existsSync(path.join(__dirname, 'node_modules')) && process.env.DATABASE_URL) {
    console.error('  Rode primeiro:  npm.cmd install');
  }
  process.exit(1);
});

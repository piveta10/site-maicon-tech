'use strict';
/**
 * Cria as tabelas e o conteúdo inicial no banco (Neon ou SQLite local).
 * Não é obrigatório: o site faz isso sozinho no primeiro acesso.
 * Uso: npm.cmd run db:setup
 */
const path = require('node:path');
require('../src/env').loadEnv(path.join(__dirname, '..', '.env'));
const { createDb, migrate } = require('../src/db');

(async () => {
  const db = createDb({ file: process.env.DB_FILE || path.join(__dirname, '..', 'data', 'site.db') });
  const did = await migrate(db);
  console.log(did ? '✔ Tabelas criadas/atualizadas.' : '✔ Banco já estava pronto.');
  console.log('Banco usado: ' + (db.dialect === 'postgres' ? 'Neon Postgres' : 'SQLite local'));
  await db.close();
})().catch((e) => { console.error('Erro:', e.message); process.exit(1); });

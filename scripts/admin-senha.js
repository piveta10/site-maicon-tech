'use strict';
/**
 * Redefine (ou cria) a senha de um administrador.
 * Funciona com o banco Neon (se DATABASE_URL estiver no .env) ou com o SQLite local.
 *
 * Uso:  npm.cmd run admin:senha -- <usuario> <nova-senha>
 * Ex.:  npm.cmd run admin:senha -- admin MinhaSenhaForte123
 */
const path = require('node:path');
require('../src/env').loadEnv(path.join(__dirname, '..', '.env'));
const { createDb, migrate } = require('../src/db');
const S = require('../src/security');

(async () => {
  const [user, pass] = process.argv.slice(2);
  if (!user || !pass) {
    console.log('Uso: npm.cmd run admin:senha -- <usuario> <nova-senha>');
    process.exit(1);
  }
  const probs = S.passwordProblems(pass);
  if (probs.length) {
    console.error('Senha fraca. Precisa de: ' + probs.join(', '));
    process.exit(1);
  }
  const db = createDb({ file: process.env.DB_FILE || path.join(__dirname, '..', 'data', 'site.db') });
  await migrate(db);
  const u = user.toLowerCase();
  const [exists] = await db.query('SELECT id FROM admins WHERE username = $1', [u]);
  if (exists) {
    await db.query('UPDATE admins SET pass_hash = $1 WHERE id = $2 RETURNING id', [S.hashPassword(pass), exists.id]);
    await db.query('DELETE FROM sessions WHERE admin_id = $1 RETURNING token_hash', [exists.id]);
    await db.query("DELETE FROM rate_limits WHERE key LIKE 'login%' RETURNING key");
    console.log(`Senha do usuário "${u}" atualizada. Sessões antigas encerradas e bloqueios de login liberados.`);
  } else {
    await db.query('INSERT INTO admins (username, pass_hash, created_at) VALUES ($1, $2, $3) RETURNING id', [u, S.hashPassword(pass), Date.now()]);
    console.log(`Administrador "${u}" criado.`);
  }
  console.log('Banco usado: ' + (db.dialect === 'postgres' ? 'Neon Postgres' : 'SQLite local'));
  await db.close();
})().catch((e) => { console.error('Erro:', e.message); process.exit(1); });

'use strict';
/**
 * Redefine (ou cria) a senha de um administrador.
 * Uso:  npm run admin:senha -- <usuario> <nova-senha>
 * Ex.:  npm run admin:senha -- admin MinhaSenhaForte123
 */
const path = require('node:path');
const { openDb } = require('../src/db');
const S = require('../src/security');

const [user, pass] = process.argv.slice(2);
if (!user || !pass) {
  console.log('Uso: npm run admin:senha -- <usuario> <nova-senha>');
  process.exit(1);
}
const probs = S.passwordProblems(pass);
if (probs.length) {
  console.error('Senha fraca. Precisa de: ' + probs.join(', '));
  process.exit(1);
}
const db = openDb(process.env.DB_FILE || path.join(__dirname, '..', 'data', 'site.db'));
const u = user.toLowerCase();
const exists = db.prepare('SELECT id FROM admins WHERE username = ?').get(u);
if (exists) {
  db.prepare('UPDATE admins SET pass_hash = ? WHERE id = ?').run(S.hashPassword(pass), exists.id);
  db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(exists.id);
  console.log(`Senha do usuário "${u}" atualizada. Sessões antigas encerradas.`);
} else {
  db.prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)').run(u, S.hashPassword(pass));
  console.log(`Administrador "${u}" criado.`);
}
db.close();

'use strict';
/**
 * Banco usado nos testes.
 *  - Padrão: SQLite temporário (não precisa de nada instalado).
 *  - TEST_DB=pg: Postgres REAL (mesmo motor do Neon), via o programa `psql`.
 *      Variáveis opcionais: PGHOST, PGUSER, PGPORT (as mesmas do psql).
 *      Ex.: TEST_DB=pg PGHOST=/tmp/pg PGUSER=postgres npm test
 */
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { createDb } = require('../../src/db');

function psql(dbname, sql) {
  const r = spawnSync('psql', ['-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-d', dbname], { input: sql, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error((r.stderr || 'erro no psql').trim());
  return r.stdout;
}

/** Converte um valor em literal SQL seguro (dollar-quoting com marcador aleatório). */
function literal(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('número inválido'); return String(v); }
  const s = String(v);
  let tag;
  do { tag = '$q' + crypto.randomBytes(4).toString('hex') + '$'; } while (s.includes(tag));
  return tag + s + tag;
}

/** Adaptador Postgres com a mesma interface do adaptador Neon (query -> linhas). */
function psqlAdapter(dbname) {
  return {
    dialect: 'postgres',
    async query(text, params = []) {
      const sql = text.replace(/\$(\d+)/g, (_, n) => {
        const i = Number(n) - 1;
        if (i >= params.length) throw new Error(`parâmetro $${n} ausente`);
        return literal(params[i]);
      });
      if (/^\s*(CREATE|ALTER|DROP)\b/i.test(sql)) { psql(dbname, sql + ';'); return []; }
      if (/^\s*(INSERT|UPDATE|DELETE)\b/i.test(sql) && !/\bRETURNING\b/i.test(sql)) { psql(dbname, sql + ';'); return []; }
      const out = psql(dbname, `WITH q AS (${sql}) SELECT coalesce(json_agg(q), '[]') FROM q;`).trim();
      return JSON.parse(out || '[]');
    },
    async exec(multi) {
      // igual ao adaptador Neon: um comando por vez
      for (const stmt of multi.split(';').map((s) => s.trim()).filter(Boolean)) psql(dbname, stmt + ';');
    },
    async close() {}
  };
}

function createTestDb(dir) {
  if (process.env.TEST_DB === 'pg') {
    const name = 'mt_test_' + crypto.randomBytes(6).toString('hex');
    psql('postgres', `CREATE DATABASE ${name};`);
    return {
      db: psqlAdapter(name),
      drop: async () => { psql('postgres', `DROP DATABASE IF EXISTS ${name} WITH (FORCE);`); }
    };
  }
  const db = createDb({ url: '', file: path.join(dir, 'test.db') });
  return { db, drop: () => db.close() };
}

module.exports = { createTestDb };

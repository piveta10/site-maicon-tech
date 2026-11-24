'use strict';
/**
 * Banco de dados.
 *  - Produção (Vercel): Neon Postgres, via variável DATABASE_URL.
 *  - Desenvolvimento sem DATABASE_URL: SQLite local (data/site.db), nativo do Node.
 *
 * Todas as consultas usam parâmetros ($1, $2...), o que impede injeção de SQL.
 * Interface comum dos dois bancos:
 *   await db.query(sql, params)  -> array de linhas
 *   await db.exec(sqlMultiplo)   -> executa comandos de criação de tabelas
 */
const fs = require('node:fs');
const path = require('node:path');

// ---------------------------------------------------------------
// Estrutura das tabelas (uma versão para cada banco)
// ---------------------------------------------------------------
function schema(dialect) {
  const pg = dialect === 'postgres';
  const ID = pg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT';
  const BIG = pg ? 'BIGINT' : 'INTEGER';
  return `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS services (
  id          ${ID},
  icon        TEXT NOT NULL DEFAULT 'code',
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT 'ti',
  sort_order  INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS projects (
  id          ${ID},
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  tags        TEXT NOT NULL DEFAULT '',
  image_url   TEXT NOT NULL DEFAULT '',
  link_url    TEXT NOT NULL DEFAULT '',
  repo_url    TEXT NOT NULL DEFAULT '',
  is_ai       INTEGER NOT NULL DEFAULT 0,
  sort_order  INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS testimonials (
  id         ${ID},
  name       TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT '',
  text       TEXT NOT NULL,
  rating     INTEGER NOT NULL DEFAULT 5,
  sort_order INTEGER NOT NULL DEFAULT 0,
  active     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS messages (
  id         ${ID},
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  phone      TEXT NOT NULL DEFAULT '',
  subject    TEXT NOT NULL DEFAULT '',
  message    TEXT NOT NULL,
  ip_hash    TEXT NOT NULL DEFAULT '',
  is_read    INTEGER NOT NULL DEFAULT 0,
  created_at ${BIG} NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
  id         ${ID},
  username   TEXT NOT NULL UNIQUE,
  pass_hash  TEXT NOT NULL,
  created_at ${BIG} NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  expires_at ${BIG} NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id         ${ID},
  admin_id   INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  created_at ${BIG} NOT NULL
);
CREATE TABLE IF NOT EXISTS uploads (
  id         TEXT PRIMARY KEY,
  mime       TEXT NOT NULL,
  data_b64   TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at ${BIG} NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
  key      TEXT PRIMARY KEY,
  count    INTEGER NOT NULL,
  reset_at ${BIG} NOT NULL
);
`;
}

// ---------------------------------------------------------------
// Conteúdo inicial — tudo pode ser alterado depois pelo painel /admin
// ---------------------------------------------------------------
const DEFAULT_SETTINGS = {
  marca: 'MaiconTech',
  marca_slogan: 'Soluções em Tecnologia & IA',
  nome: 'Maicon Piveta',
  cargo: 'Desenvolvedor, Especialista em TI & Soluções com IA',
  hero_saudacao: 'Olá, eu sou',
  hero_texto: 'Transformo ideias em soluções digitais com Inteligência Artificial, tecnologia, performance e inovação.',
  servicos_titulo: 'Soluções em TI e IA',
  servicos_subtitulo: 'para impulsionar seu projeto.',
  servicos_texto: 'Da ideia à implementação: automação com IA, sistemas sob medida, nuvem e segurança, com foco em qualidade e resultado.',
  ia_titulo: 'Inteligência Artificial aplicada ao seu negócio',
  ia_texto: 'A IA deixou de ser futuro: hoje ela atende clientes, organiza dados, gera documentos e automatiza tarefas repetitivas. Eu integro modelos de linguagem (ChatGPT, Claude, Gemini e modelos open-source) aos seus sistemas, com segurança e custo sob controle.',
  sobre_titulo: 'Tecnologia como meio para evoluir.',
  sobre_texto: 'Sou apaixonado por tecnologia e estou sempre em busca de aprender, criar e entregar o meu melhor em cada projeto. Ajudo pessoas e empresas a resolverem desafios, otimizarem processos e alcançarem seus objetivos com TI e Inteligência Artificial.',
  sobre_destaques: 'Compromisso com a qualidade\nSoluções sob medida com IA\nSegurança em primeiro lugar\nSuporte contínuo',
  contato_titulo: 'Vamos conversar?',
  contato_texto: 'Estou pronto para transformar sua ideia em realidade. Me chame no WhatsApp ou envie uma mensagem pelo formulário.',
  whatsapp: '5547996838633',
  whatsapp_mensagem: 'Olá Maicon! Vim pelo site e gostaria de conversar sobre um projeto.',
  email: '',
  github: 'https://github.com/piveta10',
  github_usuario: 'piveta10',
  linkedin: '',
  youtube: '',
  instagram: '',
  mostrar_repos_github: '1',
  rodape_texto: 'Todos os direitos reservados.'
};

const DEFAULT_SERVICES = [
  ['bot', 'Agentes e Chatbots com IA', 'Atendimento 24h no WhatsApp, site e sistemas internos com assistentes inteligentes treinados com os dados do seu negócio.', 'ia'],
  ['workflow', 'Automação com IA', 'Automatize tarefas repetitivas: leitura de documentos, planilhas, e-mails, relatórios e integrações entre sistemas.', 'ia'],
  ['brain', 'Integração de LLMs', 'Conecto ChatGPT, Claude, Gemini e modelos open-source às suas aplicações, com segurança, controle de custos e privacidade.', 'ia'],
  ['chart', 'Dados e Análise com IA', 'Dashboards, análise preditiva e extração de insights a partir dos dados que sua empresa já possui.', 'ia'],
  ['code', 'Desenvolvimento Web e Sistemas', 'Sites, sistemas web e aplicações sob medida, rápidos, responsivos e fáceis de manter.', 'ti'],
  ['cloud', 'Infraestrutura em Nuvem', 'Migração, hospedagem, escalabilidade e performance na nuvem.', 'ti'],
  ['shield', 'Segurança da Informação', 'Testes de segurança, boas práticas e proteção de dados para o seu negócio (LGPD).', 'ti'],
  ['headset', 'Suporte Técnico', 'Atendimento ágil e especializado, presencial ou remoto.', 'ti'],
  ['network', 'Redes e Infraestrutura', 'Projetos, configuração e manutenção de redes e servidores.', 'ti']
];

const DEFAULT_PROJECTS = [
  // [title, description, tags, link_url, repo_url, is_ai, active]
  ['Sistema de Ordem de Serviço', 'Sistema web para cadastro e acompanhamento de ordens de serviço.', 'Web, HTML', 'https://github.com/piveta10/ordem-serv', 'https://github.com/piveta10/ordem-serv', 0, 1],
  // Modelos (ocultos) — edite no painel, coloque o link real e ative.
  ['Assistente Virtual com IA (modelo)', 'Chatbot com IA para atendimento automático no WhatsApp. Edite este projeto no painel e ative-o.', 'IA, Chatbot, WhatsApp', '', '', 1, 0],
  ['Automação de Documentos com IA (modelo)', 'Leitura e classificação automática de documentos e notas com IA. Edite e ative no painel.', 'IA, Automação, OCR', '', '', 1, 0],
  ['Dashboard Inteligente (modelo)', 'Painel de indicadores com análise e resumos gerados por IA. Edite e ative no painel.', 'IA, Dados, Dashboard', '', '', 1, 0]
];

// ---------------------------------------------------------------
// Adaptadores
// ---------------------------------------------------------------

/** Neon Postgres (produção / Vercel). Usa HTTP — ideal para funções serverless. */
function neonAdapter(url) {
  let sqlPromise;
  const getSql = () => (sqlPromise ||= import('@neondatabase/serverless').then(({ neon }) => neon(url)));
  return {
    dialect: 'postgres',
    async query(text, params = []) {
      const sql = await getSql();
      return sql.query(text, params);
    },
    async exec(multi) {
      const sql = await getSql();
      for (const stmt of multi.split(';').map((s) => s.trim()).filter(Boolean)) await sql.query(stmt, []);
    },
    async close() {}
  };
}

/** SQLite local (desenvolvimento e testes). Converte $1 -> ?1. */
function sqliteAdapter(file) {
  const origEmit = process.emitWarning;
  process.emitWarning = function (w, ...a) {
    if (String(w && w.message ? w.message : w).includes('SQLite')) return;
    return origEmit.call(process, w, ...a);
  };
  const { DatabaseSync } = require('node:sqlite');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  const cache = new Map();
  return {
    dialect: 'sqlite',
    async query(text, params = []) {
      let st = cache.get(text);
      if (!st) { st = db.prepare(text.replace(/\$(\d+)/g, '?$1')); cache.set(text, st); }
      return st.all(...params);
    },
    async exec(multi) { db.exec(multi); },
    async close() { db.close(); }
  };
}

function createDb(opts = {}) {
  const url = opts.url !== undefined ? opts.url : process.env.DATABASE_URL;
  if (opts.adapter) return opts.adapter;
  if (url && /^postgres(ql)?:\/\//.test(url)) return neonAdapter(url);
  return sqliteAdapter(opts.file || path.join(__dirname, '..', 'data', 'site.db'));
}

const SCHEMA_VERSION = 'v1-' + Object.keys(DEFAULT_SETTINGS).length;

/** Insere várias linhas com um só comando (menos idas ao banco). */
function multiInsert(table, cols, rows, suffix = '') {
  const params = [];
  const values = rows.map((r) => '(' + r.map((v) => { params.push(v); return '$' + params.length; }).join(', ') + ')');
  return [`INSERT INTO ${table} (${cols.join(', ')}) VALUES ${values.join(', ')} ${suffix}`, params];
}

/**
 * Cria as tabelas (se não existirem) e o conteúdo inicial. Seguro rodar várias vezes.
 * Só faz o trabalho pesado uma vez: guarda a versão em settings._schema.
 */
async function migrate(db) {
  try {
    const r = await db.query("SELECT value FROM settings WHERE key = '_schema'");
    if (r[0] && r[0].value === SCHEMA_VERSION) return false;
  } catch { /* tabelas ainda não existem */ }

  await db.exec(schema(db.dialect));
  await db.query(...multiInsert('settings', ['key', 'value'], Object.entries(DEFAULT_SETTINGS), 'ON CONFLICT (key) DO NOTHING'));

  const [{ n: ns }] = await db.query('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM services');
  if (Number(ns) === 0) {
    await db.query(...multiInsert('services', ['icon', 'title', 'description', 'category', 'sort_order'], DEFAULT_SERVICES.map((s, i) => [...s, i])));
  }
  const [{ n: np }] = await db.query('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM projects');
  if (Number(np) === 0) {
    await db.query(...multiInsert('projects', ['title', 'description', 'tags', 'link_url', 'repo_url', 'is_ai', 'active', 'sort_order'], DEFAULT_PROJECTS.map((p, i) => [...p, i])));
  }
  await db.query("INSERT INTO settings (key, value) VALUES ('_schema', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [SCHEMA_VERSION]);
  return true;
}

module.exports = { createDb, migrate, schema, DEFAULT_SETTINGS };

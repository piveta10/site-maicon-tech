'use strict';
/**
 * Banco de dados (SQLite nativo do Node — node:sqlite).
 * Todas as consultas usam "prepared statements" (parâmetros ?), o que
 * impede injeção de SQL.
 */
const fs = require('node:fs');
const path = require('node:path');

// Silencia o aviso "ExperimentalWarning" do SQLite nativo.
const origEmit = process.emitWarning;
process.emitWarning = function (w, ...a) {
  if (String(w && w.message ? w.message : w).includes('SQLite')) return;
  return origEmit.call(process, w, ...a);
};
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS services (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  icon        TEXT NOT NULL DEFAULT 'code',
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT 'ti',
  sort_order  INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS projects (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
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
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT '',
  text       TEXT NOT NULL,
  rating     INTEGER NOT NULL DEFAULT 5,
  sort_order INTEGER NOT NULL DEFAULT 0,
  active     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  phone      TEXT NOT NULL DEFAULT '',
  subject    TEXT NOT NULL DEFAULT '',
  message    TEXT NOT NULL,
  ip_hash    TEXT NOT NULL DEFAULT '',
  is_read    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admins (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT NOT NULL UNIQUE,
  pass_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id   INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

/** Conteúdo inicial — tudo pode ser alterado depois pelo painel /admin */
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
  // Modelos (inativos) — edite no painel, coloque o link real e ative.
  ['Assistente Virtual com IA (modelo)', 'Chatbot com IA para atendimento automático no WhatsApp. Edite este projeto no painel e ative-o.', 'IA, Chatbot, WhatsApp', '', '', 1, 0],
  ['Automação de Documentos com IA (modelo)', 'Leitura e classificação automática de documentos e notas com IA. Edite e ative no painel.', 'IA, Automação, OCR', '', '', 1, 0],
  ['Dashboard Inteligente (modelo)', 'Painel de indicadores com análise e resumos gerados por IA. Edite e ative no painel.', 'IA, Dados, Dashboard', '', '', 1, 0]
];

function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  seed(db);
  return db;
}

function seed(db) {
  const insSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) insSetting.run(k, v);

  if (db.prepare('SELECT COUNT(*) AS n FROM services').get().n === 0) {
    const ins = db.prepare('INSERT INTO services (icon, title, description, category, sort_order) VALUES (?, ?, ?, ?, ?)');
    DEFAULT_SERVICES.forEach((s, i) => ins.run(s[0], s[1], s[2], s[3], i));
  }
  if (db.prepare('SELECT COUNT(*) AS n FROM projects').get().n === 0) {
    const ins = db.prepare('INSERT INTO projects (title, description, tags, link_url, repo_url, is_ai, active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    DEFAULT_PROJECTS.forEach((p, i) => ins.run(...p, i));
  }
}

module.exports = { openDb, DEFAULT_SETTINGS };

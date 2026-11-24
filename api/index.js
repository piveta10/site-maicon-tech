'use strict';
/**
 * Função serverless da Vercel.
 * Atende /api/* e /uploads/* (veja vercel.json). As páginas, CSS, JS e imagens
 * da pasta public/ são servidos direto pela CDN da Vercel.
 *
 * Variáveis de ambiente necessárias (Vercel → Settings → Environment Variables):
 *   DATABASE_URL    – string de conexão do Neon (criada automaticamente pela integração Neon)
 *   ADMIN_PASSWORD  – senha do primeiro administrador (10+ caracteres, maiúsc., minúsc. e número)
 *   ADMIN_USER      – opcional (padrão: admin)
 */
const { createApp } = require('../src/app');

let app;
function getApp() {
  if (!app) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL não configurada na Vercel.');
    app = createApp({
      databaseUrl: process.env.DATABASE_URL,
      serveStatic: false,
      https: true,
      trustProxy: true,
      adminUser: process.env.ADMIN_USER || 'admin',
      adminPassword: process.env.ADMIN_PASSWORD
    });
  }
  return app;
}

module.exports = async (req, res) => {
  try {
    await getApp().handler(req, res);
  } catch (e) {
    console.error('[erro]', e);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ erro: 'Servidor não configurado. Verifique as variáveis de ambiente.' }));
    }
  }
};

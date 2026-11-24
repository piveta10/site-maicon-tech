# MaiconTech — Site de Tecnologia e IA

Site profissional de **Maicon Piveta** com foco em Inteligência Artificial, painel administrativo para editar tudo, banco de dados **Neon (Postgres)** e hospedagem na **Vercel**.

- **Tudo editável** pelo painel `/admin`: textos, contatos, WhatsApp, e-mail, redes sociais, serviços, projetos (com link e imagem), depoimentos e mensagens.
- **Banco de dados**: Neon Postgres em produção. Para testar no seu computador sem configurar nada, o site usa automaticamente um SQLite local.
- **Imagens enviadas** pelo painel ficam guardadas no próprio banco (não precisa de outro serviço).
- **88 testes de segurança** automatizados.

---

## 1. Publicar: GitHub → Neon → Vercel

### Passo 1 — Enviar para o GitHub
Crie um repositório vazio chamado `maicontech` em https://github.com/new e, no **PowerShell**, dentro da pasta do projeto:

```powershell
git init
git add .
git commit -m "Site MaiconTech"
git branch -M main
git remote add origin https://github.com/piveta10/maicontech.git
git push -u origin main
```

> O `.gitignore` já impede que `.env` (senhas), `data/` (banco local) e `node_modules/` sejam enviados.

### Passo 2 — Importar na Vercel
1. Entre em https://vercel.com com sua conta do GitHub → **Add New… → Project**.
2. Escolha o repositório `maicontech` → **Import**.
3. Em *Framework Preset* deixe **Other**. Não mude mais nada (o `vercel.json` já configura tudo).
4. Em **Environment Variables** adicione:

   | Nome | Valor |
   |---|---|
   | `ADMIN_PASSWORD` | sua senha do painel (10+ caracteres, com maiúscula, minúscula e número) |
   | `ADMIN_USER` | `admin` (opcional) |

5. Clique em **Deploy**. (O site ainda vai dar erro na API até o passo 3 — é normal.)

### Passo 3 — Criar o banco Neon e conectar
1. No projeto da Vercel: aba **Storage → Create Database → Neon** (Serverless Postgres) → região mais próxima (ex.: *São Paulo* se disponível, ou *Washington D.C.*) → **Create** → **Connect** ao projeto.
   A Vercel cria sozinha a variável **`DATABASE_URL`**.
   > Alternativa: crie o banco em https://neon.com, copie a *Connection string* (começa com `postgresql://`) e cadastre na Vercel como `DATABASE_URL`.
2. Vá em **Deployments → ⋯ → Redeploy** para o site pegar as variáveis novas.

### Passo 4 — Pronto!
- Site: `https://seu-projeto.vercel.app`
- Painel: `https://seu-projeto.vercel.app/admin` (usuário `admin` + a senha do `ADMIN_PASSWORD`)

No primeiro acesso o site cria sozinho as tabelas, o conteúdo inicial e o administrador.
Depois de entrar, você pode trocar a senha em **Painel → Segurança** (a variável `ADMIN_PASSWORD` só é usada para criar o primeiro admin).

A cada `git push` na branch `main`, a Vercel publica a nova versão automaticamente.

---

## 2. Testar no seu computador

Requisito: **Node.js 22.13+** (você já tem). Use o **PowerShell** ou o Prompt de Comando, na pasta do projeto.

```powershell
copy .env.example .env
notepad .env          # preencha ADMIN_PASSWORD (e DATABASE_URL se quiser usar o Neon)
npm.cmd install       # só necessário se usar o Neon localmente
node server.js
```

Abra http://localhost:3000 e http://localhost:3000/admin.

- **Sem `DATABASE_URL`** → usa um banco SQLite local em `data/site.db` (ótimo para testes; não vai para o GitHub).
- **Com `DATABASE_URL`** → usa o mesmo banco Neon do site publicado (cuidado: as alterações aparecem no site real).

> No PowerShell use `npm.cmd` em vez de `npm` (o Windows bloqueia o `npm` por padrão), ou rode `node server.js` direto.

Comandos úteis:

```powershell
npm.cmd test                                        # testes de segurança
npm.cmd run admin:senha -- admin NovaSenha123        # redefine a senha (no banco do .env)
npm.cmd run db:setup                                 # cria as tabelas manualmente (opcional)
```

Esqueceu a senha do site publicado? Coloque a `DATABASE_URL` do Neon no seu `.env`, rode `npm.cmd install` e depois `npm.cmd run admin:senha -- admin NovaSenha123`.

---

## 3. Primeiros passos no painel

1. **Conteúdo do site → Contato**: preencha seu **e-mail** (está vazio de propósito). Redes sociais vazias não aparecem.
2. **Projetos**: há 1 projeto real (Ordem de Serviço) e 3 **modelos de projetos com IA ocultos**. Edite, coloque o **link do trabalho**, envie uma imagem e marque *Visível no site*.
3. **Depoimentos**: a seção só aparece quando houver ao menos um visível. Use apenas depoimentos reais.
4. Os **repositórios públicos do GitHub** aparecem automaticamente na seção Projetos.
5. **Mensagens**: contatos do formulário, com atalho para responder por e-mail ou WhatsApp.

---

## 4. Segurança

```powershell
npm.cmd test
```

**88 testes automatizados**, executados tanto em SQLite quanto em **Postgres real** (mesmo motor do Neon):

| Área | O que é testado |
|---|---|
| Cabeçalhos | CSP rígida (sem scripts inline), anti-clickjacking, nosniff, HSTS; o `vercel.json` aplica exatamente os mesmos cabeçalhos às páginas |
| Path traversal | 19 tentativas de ler arquivos do servidor (`../`, `%2e`, `%c0%ae`, null byte, `.env`, banco…) |
| Autenticação | todas as rotas do painel exigem login; SQL injection no login; senhas com hash **scrypt**; sessões guardadas como hash; cookie `HttpOnly` + `Secure` + `SameSite=Strict`; logout e expiração |
| Força bruta | bloqueio após 5 tentativas em 15 min por IP (IP real do visitante na Vercel) e 10 por usuário — **guardado no banco**, vale para todas as instâncias da Vercel |
| CSRF | exige token + mesma origem; recusa formulários de outros sites |
| XSS | conteúdo com `<script>` é salvo e exibido como texto; nada de `innerHTML` com dados |
| Links | `javascript:`, `data:`, `file:`, `//`… recusados |
| Upload | apenas PNG/JPG/WEBP/GIF verificados pelo conteúdo real; SVG/HTML recusados; máx. 3 MB |
| Contato | validação, campo anti-robô, 5 mensagens/hora por IP, IP salvo só como hash (LGPD) |
| Vercel | função não expõe arquivos do projeto; erro amigável sem vazar a `DATABASE_URL`; `.gitignore` protege segredos |

Para rodar os testes em Postgres: `TEST_DB=pg` com o `psql` instalado (variáveis `PGHOST`, `PGUSER`).

---

## 5. Estrutura

```
api/index.js           → função serverless da Vercel (atende /api e /uploads)
vercel.json            → configuração da Vercel (pasta pública, rotas, cabeçalhos)
server.js              → servidor local para testes
src/app.js             → rotas, API, segurança das requisições
src/db.js              → tabelas, conteúdo inicial, conexão Neon/SQLite
src/security.js        → senhas, tokens, validação, cabeçalhos
src/env.js             → leitura do arquivo .env
scripts/               → admin:senha e db:setup
public/                → site (index.html, css, js, img) — servido pela CDN da Vercel
public/admin/          → painel administrativo
tests/                 → testes de segurança
```

### Como ampliar
- **Novo serviço / projeto**: pelo painel, sem tocar em código.
- **Novo ícone**: adicione o desenho em `ICONS` (public/js/main.js), o nome na lista `ICONS` em `src/app.js` e o rótulo em `ICON_LABELS` (public/admin/admin.js).
- **Novo campo de texto**: adicione a chave em `DEFAULT_SETTINGS` (src/db.js), o campo em `SETTINGS_GROUPS` (admin.js) e um elemento com `data-s="sua_chave"` no `index.html`. O banco é atualizado sozinho no próximo acesso.
- **Cores**: variáveis no topo de `public/css/style.css`.
- **Domínio próprio** (ex.: maicontech.com.br): Vercel → Settings → Domains.

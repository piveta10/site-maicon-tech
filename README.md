# MaiconTech — Site de Tecnologia e IA

Site profissional de **Maicon Piveta** com foco em Inteligência Artificial, painel administrativo para editar tudo, banco de dados e testes de segurança automatizados.

- **Sem dependências externas**: usa apenas recursos nativos do Node.js (servidor HTTP, SQLite e criptografia). Não é preciso rodar `npm install`.
- **Tudo editável** pelo painel `/admin`: textos, contatos, WhatsApp, e-mail, redes sociais, serviços, projetos (com link e imagem), depoimentos.
- **Banco de dados SQLite** em `data/site.db` (criado automaticamente).

---

## 1. Requisitos

- **Node.js 22.13 ou mais novo** (recomendado: versão LTS mais recente em https://nodejs.org).
  Para conferir: `node --version`

## 2. Como rodar

```bash
# dentro da pasta do projeto
copy .env.example .env      # Windows  (Linux/Mac: cp .env.example .env)
# edite o .env e defina ADMIN_PASSWORD (mín. 10 caracteres, maiúscula, minúscula e número)

npm start
```

Abra:
- Site: http://localhost:3000
- Painel: http://localhost:3000/admin  (usuário `admin` e a senha do `.env`)

> Se você não definir `ADMIN_PASSWORD`, uma senha forte é gerada e mostrada **uma única vez** no terminal na primeira execução.

Esqueceu a senha?

```bash
npm run admin:senha -- admin NovaSenhaForte123
```

## 3. Primeiros passos no painel

1. **Conteúdo do site → Contato**: preencha seu **e-mail** (está vazio de propósito) e, se quiser, LinkedIn/Instagram/YouTube. Campos vazios não aparecem no site.
2. **Projetos**: há 1 projeto real (Ordem de Serviço, do seu GitHub) e 3 **modelos de projetos com IA ocultos**. Edite, coloque o **link do trabalho** e a imagem, e marque *Visível no site*.
3. **Depoimentos**: a seção só aparece quando houver ao menos um depoimento visível. Use apenas depoimentos reais.
4. Os **repositórios públicos do GitHub** (github.com/piveta10) aparecem automaticamente na seção Projetos (pode desligar no painel).
5. **Mensagens**: tudo que for enviado pelo formulário de contato fica salvo aqui, com atalho para responder por e-mail ou WhatsApp.

## 4. Testes de segurança

```bash
npm test
```

São **80 testes automatizados**, cobrindo:

| Área | O que é testado |
|---|---|
| Cabeçalhos | CSP rígida (sem scripts inline), anti-clickjacking, nosniff, Referrer/Permissions-Policy, HSTS em HTTPS, sem CORS aberto |
| Path traversal | 19 tentativas de ler arquivos do servidor (`../server.js`, `.env`, banco, `/etc/passwd`, codificações `%2e`, `%c0%ae`, null byte…) |
| Autenticação | todas as rotas do painel exigem login; cookie falsificado/expirado; logout; SQL injection no login; senhas com hash **scrypt**; tokens guardados como hash; cookie `HttpOnly` + `SameSite=Strict`; mensagem de erro igual para usuário inexistente |
| Força bruta | bloqueio após 5 tentativas erradas em 15 min (por IP) e 10 por usuário |
| CSRF | exige token CSRF + mesma origem; rejeita formulários de outros sites |
| XSS | conteúdo com `<script>` é salvo e exibido como texto; análise do código garante que dados nunca são inseridos como HTML; nenhum script/estilo inline |
| Links maliciosos | `javascript:`, `data:`, `vbscript:`, `file:`, `//`, URLs com usuário:senha são recusados |
| Upload | apenas PNG/JPG/WEBP/GIF verificados pelo conteúdo real; SVG e HTML disfarçado recusados; limite 3 MB; nome aleatório |
| Formulário de contato | validação, campo anti-robô (honeypot), limite de 5 mensagens/hora por IP, IP salvo apenas como hash (LGPD) |
| Servidor | limite geral de requisições, limite de tamanho do corpo, timeouts contra conexões lentas, erros sem detalhes técnicos |

## 5. Estrutura

```
server.js              → inicia o servidor (lê o .env)
src/app.js             → rotas, API, arquivos estáticos
src/db.js              → tabelas e conteúdo inicial do banco
src/security.js        → senhas, tokens, validação, cabeçalhos
scripts/admin-senha.js → redefinir senha do admin
public/                → site (index.html, css, js, img)
public/admin/          → painel administrativo
tests/security.test.js → testes de segurança
data/                  → banco de dados e imagens enviadas (criado sozinho; faça backup!)
```

### Como ampliar

- **Novo serviço / projeto**: pelo painel, sem tocar em código.
- **Novo ícone**: adicione o desenho em `ICONS` (public/js/main.js), o nome na lista `ICONS` em `src/app.js` e o rótulo em `ICON_LABELS` (public/admin/admin.js).
- **Novo campo de texto**: adicione a chave em `DEFAULT_SETTINGS` (src/db.js), o campo em `SETTINGS_GROUPS` (admin.js) e um elemento com `data-s="sua_chave"` no `index.html`.
- **Cores**: variáveis no topo de `public/css/style.css`.

## 6. Publicar na internet

Funciona em qualquer hospedagem que rode Node.js (VPS, Render, Railway, Fly.io, Hostinger VPS…):

1. Envie a pasta (sem `data/` e sem `.env`), crie o `.env` no servidor.
2. Use **HTTPS** e coloque `HTTPS=1` no `.env`.
3. Se estiver atrás de proxy (Nginx, Cloudflare, Render), use `TRUST_PROXY=1`.
4. O disco precisa ser **persistente** (a pasta `data/` guarda o banco e as imagens).
5. Faça backup periódico da pasta `data/`.

/* =========================================================
   Vivix — Painel administrativo
   Para adicionar novos campos/configurações: edite SETTINGS_GROUPS
   ou ENTITY_FORMS abaixo (e a lista DEFAULT_SETTINGS em src/db.js).
   ========================================================= */
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  function el(tag, attrs = {}, children = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'value') n.value = v;
      else if (k === 'checked') n.checked = !!v;
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of [].concat(children)) if (c !== null && c !== undefined && c !== false) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  }

  // ---------------- Definições de formulários ----------------
  const SETTINGS_GROUPS = [
    { title: 'Identidade', fields: [
      ['marca', 'Nome da marca'], ['marca_slogan', 'Slogan da marca'],
      ['nome', 'Seu nome (aparece em "Sobre")'], ['cargo', 'Cargo / especialidade (aparece em "Sobre")']
    ] },
    { title: 'Início (topo do site)', fields: [
      ['hero_selo', 'Selo acima do título'], ['hero_titulo', 'Título principal (a última palavra fica em destaque)'],
      ['hero_texto', 'Texto de apresentação', 'textarea']
    ] },
    { title: 'Seção de serviços', fields: [
      ['servicos_titulo', 'Título'], ['servicos_subtitulo', 'Subtítulo'], ['servicos_texto', 'Texto lateral', 'textarea']
    ] },
    { title: 'Seção de Inteligência Artificial', fields: [
      ['ia_titulo', 'Título'], ['ia_texto', 'Texto', 'textarea']
    ] },
    { title: 'Sobre', fields: [
      ['sobre_titulo', 'Título (a última palavra fica em azul)'], ['sobre_texto', 'Texto', 'textarea'],
      ['sobre_destaques', 'Destaques (um por linha)', 'textarea']
    ] },
    { title: 'Contato', fields: [
      ['contato_titulo', 'Título'], ['contato_texto', 'Texto', 'textarea'],
      ['whatsapp', 'WhatsApp (DDI + DDD + número, só números)', 'text', '5547996838633'],
      ['whatsapp_mensagem', 'Mensagem automática do WhatsApp'],
      ['email', 'E-mail de contato', 'email', 'seu@email.com']
    ] },
    { title: 'Redes sociais', fields: [
      ['github', 'Link do GitHub', 'url', 'https://github.com/...'],
      ['github_usuario', 'Usuário do GitHub (para listar repositórios)'],
      ['mostrar_repos_github', 'Mostrar meus repositórios do GitHub automaticamente no site', 'checkbox'],
      ['linkedin', 'Link do LinkedIn', 'url', 'https://linkedin.com/in/...'],
      ['instagram', 'Link do Instagram', 'url', 'https://instagram.com/...'],
      ['youtube', 'Link do YouTube', 'url', 'https://youtube.com/@...']
    ] },
    { title: 'Rodapé', fields: [['rodape_texto', 'Texto do rodapé']] }
  ];

  const ICON_LABELS = {
    code: 'Código', cloud: 'Nuvem', shield: 'Segurança', headset: 'Suporte', network: 'Redes', bot: 'Robô / Chatbot',
    brain: 'Cérebro / IA', workflow: 'Automação', chart: 'Gráfico / Dados', sparkles: 'Brilho / IA generativa', mobile: 'Celular / App', database: 'Banco de dados'
  };

  const ENTITY_FORMS = {
    services: {
      title: 'Serviços', singular: 'serviço', desc: 'Cards exibidos na seção "Meus serviços".',
      fields: [
        { k: 'title', label: 'Título*', max: 120 },
        { k: 'description', label: 'Descrição', type: 'textarea', max: 600 },
        { k: 'icon', label: 'Ícone', type: 'select', options: () => state.icons.map((i) => [i, ICON_LABELS[i] || i]) },
        { k: 'category', label: 'Categoria', type: 'select', options: () => [['ia', 'Inteligência Artificial'], ['ti', 'TI & Desenvolvimento']] },
        { k: 'sort_order', label: 'Ordem (menor aparece primeiro)', type: 'number' },
        { k: 'active', label: 'Visível no site', type: 'checkbox', def: 1 }
      ],
      line: (x) => [x.title, x.description, x.category === 'ia' ? 'IA' : 'TI']
    },
    projects: {
      title: 'Projetos', singular: 'projeto', desc: 'Portfólio. O link leva o visitante ao trabalho feito.',
      fields: [
        { k: 'title', label: 'Título*', max: 150 },
        { k: 'description', label: 'Descrição', type: 'textarea', max: 1000 },
        { k: 'tags', label: 'Tags (separadas por vírgula)', placeholder: 'IA, Web, Python', max: 200 },
        { k: 'link_url', label: 'Link do projeto (site, demo ou vídeo)', type: 'url', placeholder: 'https://...' },
        { k: 'repo_url', label: 'Link do código (GitHub)', type: 'url', placeholder: 'https://github.com/piveta10/...' },
        { k: 'image_url', label: 'Imagem de capa', type: 'image' },
        { k: 'is_ai', label: 'Projeto com Inteligência Artificial (mostra selo "IA")', type: 'checkbox' },
        { k: 'sort_order', label: 'Ordem', type: 'number' },
        { k: 'active', label: 'Visível no site', type: 'checkbox', def: 1 }
      ],
      line: (x) => [x.title, x.link_url || x.repo_url || 'sem link', x.is_ai ? 'IA' : '']
    },
    testimonials: {
      title: 'Depoimentos', singular: 'depoimento', desc: 'Só aparecem no site quando houver pelo menos um visível. Use apenas depoimentos reais de clientes.',
      fields: [
        { k: 'name', label: 'Nome do cliente*', max: 100 },
        { k: 'role', label: 'Cargo / empresa', max: 100 },
        { k: 'text', label: 'Depoimento*', type: 'textarea', max: 600 },
        { k: 'rating', label: 'Estrelas (1 a 5)', type: 'select', options: () => [5, 4, 3, 2, 1].map((n) => [n, '★'.repeat(n)]) },
        { k: 'sort_order', label: 'Ordem', type: 'number' },
        { k: 'active', label: 'Visível no site', type: 'checkbox', def: 1 }
      ],
      line: (x) => [x.name, x.text, '★'.repeat(x.rating)]
    }
  };

  // ---------------- Estado e API ----------------
  const state = { csrf: '', data: null, icons: [], view: 'settings' };

  async function api(path, { method = 'GET', body, raw, type } = {}) {
    const headers = {};
    if (method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
    let payload;
    if (raw) { payload = raw; headers['Content-Type'] = type; }
    else if (body !== undefined) { payload = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    const r = await fetch(path, { method, headers, body: payload, credentials: 'same-origin' });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && path !== '/api/admin/login') { showLogin(); throw new Error('Sessão expirada. Faça login novamente.'); }
    if (!r.ok) throw new Error(j.erro || `Erro ${r.status}`);
    return j;
  }

  let toastT;
  function toast(msg, err = false) {
    const t = $('#toast');
    t.textContent = msg; t.className = 'toast is-on' + (err ? ' err' : '');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('is-on'), 3200);
  }

  // ---------------- Login ----------------
  function showLogin() { $('#appView').hidden = true; $('#loginView').hidden = false; $('#loginForm [name=username]').focus(); }

  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target; const btn = $('button', f);
    $('#loginErr').textContent = ''; btn.disabled = true;
    try {
      const j = await api('/api/admin/login', { method: 'POST', body: { username: f.username.value, password: f.password.value } });
      state.csrf = j.csrf; f.reset();
      await enterApp(j.username);
    } catch (err) { $('#loginErr').textContent = err.message; }
    finally { btn.disabled = false; }
  });

  $('#logoutBtn').addEventListener('click', async () => {
    try { await api('/api/admin/logout', { method: 'POST', body: {} }); } catch { /* ignora */ }
    state.csrf = ''; showLogin();
  });

  async function enterApp(username) {
    $('#whoami').textContent = 'Conectado como ' + username;
    $('#loginView').hidden = true; $('#appView').hidden = false;
    await reload();
    render();
  }

  async function reload() {
    state.data = await api('/api/admin/data');
    state.icons = state.data.icons;
    const u = $('#unread');
    u.hidden = !state.data.unread; u.textContent = state.data.unread;
  }

  // ---------------- Navegação ----------------
  $$('#sideNav button').forEach((b) => b.addEventListener('click', () => {
    state.view = b.dataset.view;
    $$('#sideNav button').forEach((x) => x.classList.toggle('is-active', x === b));
    render();
  }));

  function render() {
    const main = $('#main');
    const v = state.view;
    if (v === 'settings') main.replaceChildren(viewSettings());
    else if (ENTITY_FORMS[v]) main.replaceChildren(viewEntity(v));
    else if (v === 'messages') { main.replaceChildren(el('p', { class: 'muted', text: 'Carregando…' })); viewMessages().then((n) => main.replaceChildren(n)).catch((e) => toast(e.message, true)); }
    else if (v === 'security') { main.replaceChildren(viewSecurity()); }
  }

  const head = (title, desc, action) => el('div', { class: 'page-head' }, [el('div', {}, [el('h1', { text: title }), desc ? el('p', { text: desc }) : null]), action || null]);

  // ---------------- Configurações ----------------
  function viewSettings() {
    const s = state.data.settings;
    const form = el('form', { novalidate: true });
    for (const g of SETTINGS_GROUPS) {
      const grid = el('div', { class: 'grid2' });
      for (const [key, label, type = 'text', ph] of g.fields) {
        let input;
        if (type === 'textarea') input = el('textarea', { name: key, value: s[key] || '', rows: key === 'sobre_destaques' ? 5 : 3 });
        else if (type === 'checkbox') { grid.append(el('label', { class: 'check full' }, [el('input', { type: 'checkbox', name: key, checked: s[key] === '1' }), label])); continue; }
        else input = el('input', { name: key, type, value: s[key] || '', placeholder: ph });
        grid.append(el('label', { class: type === 'textarea' ? 'full' : '' }, [label, input]));
      }
      form.append(el('section', { class: 'group' }, [el('h3', { text: g.title }), grid]));
    }
    const save = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Salvar alterações' });
    form.append(el('div', { class: 'sticky-save' }, [save]));
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); save.disabled = true;
      const body = {};
      for (const n of $$('input, textarea', form)) body[n.name] = n.type === 'checkbox' ? (n.checked ? '1' : '0') : n.value;
      try {
        const j = await api('/api/admin/settings', { method: 'PUT', body });
        state.data.settings = j.settings; toast('Conteúdo salvo! ✅');
      } catch (err) { toast(err.message, true); }
      finally { save.disabled = false; }
    });
    return el('div', {}, [head('Conteúdo do site', 'Edite os textos, contatos e redes sociais exibidos no site.'), form]);
  }

  // ---------------- Listas (serviços, projetos, depoimentos) ----------------
  function viewEntity(table) {
    const def = ENTITY_FORMS[table];
    const items = state.data[table];
    const add = el('button', { class: 'btn btn--primary', text: `+ Novo ${def.singular}`, onclick: () => openEditor(table, null) });
    const list = el('div', { class: 'list' });
    if (!items.length) list.append(el('p', { class: 'muted', text: 'Nenhum item cadastrado ainda.' }));
    for (const it of items) {
      const [title, sub, tag] = def.line(it);
      list.append(el('div', { class: 'row' + (it.active ? '' : ' is-off') }, [
        table === 'projects' && it.image_url ? el('img', { class: 'thumb', src: it.image_url, alt: '' }) : null,
        el('div', { class: 'row__main' }, [
          el('b', {}, [title, tag ? el('span', { class: 'tag', text: tag }) : null, it.active ? null : el('span', { class: 'tag tag--off', text: 'oculto' })]),
          el('span', { text: sub || '' })
        ]),
        el('div', { class: 'row__actions' }, [
          el('button', { class: 'btn btn--ghost btn--sm', text: 'Editar', onclick: () => openEditor(table, it) }),
          el('button', { class: 'btn btn--danger btn--sm', text: 'Excluir', onclick: () => removeItem(table, it) })
        ])
      ]));
    }
    return el('div', {}, [head(def.title, def.desc, add), list]);
  }

  async function removeItem(table, it) {
    const name = it.title || it.name;
    if (!confirm(`Excluir "${name}"? Esta ação não pode ser desfeita.`)) return;
    try { await api(`/api/admin/${table}/${it.id}`, { method: 'DELETE' }); await reload(); render(); toast('Item excluído.'); }
    catch (e) { toast(e.message, true); }
  }

  // ---------------- Editor (modal) ----------------
  const modal = $('#modal');
  let current = null;
  $('#modalClose').addEventListener('click', () => modal.close());
  $('#modalCancel').addEventListener('click', () => modal.close());

  function openEditor(table, item) {
    const def = ENTITY_FORMS[table];
    current = { table, item };
    $('#modalTitle').textContent = (item ? 'Editar ' : 'Novo ') + def.singular;
    $('#modalErr').textContent = '';
    const body = $('#modalBody');
    body.replaceChildren();
    for (const f of def.fields) {
      const val = item ? item[f.k] : (f.def ?? '');
      if (f.type === 'checkbox') { body.append(el('label', { class: 'check' }, [el('input', { type: 'checkbox', name: f.k, checked: !!Number(val) }), f.label])); continue; }
      let input;
      if (f.type === 'textarea') input = el('textarea', { name: f.k, value: val || '', maxlength: f.max });
      else if (f.type === 'select') input = el('select', { name: f.k }, f.options().map(([v, l]) => el('option', { value: v, text: l, selected: String(v) === String(val) })));
      else if (f.type === 'image') {
        const url = el('input', { name: f.k, type: 'text', value: val || '', placeholder: 'https://... ou envie um arquivo' });
        const prev = el('img', { alt: '', hidden: !val, src: val || undefined });
        const file = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif', hidden: true });
        const btn = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', text: 'Enviar imagem', onclick: () => file.click() });
        url.addEventListener('input', () => { prev.hidden = !url.value; if (url.value) prev.src = url.value; });
        file.addEventListener('change', async () => {
          const fl = file.files[0]; if (!fl) return;
          if (fl.size > 3 * 1024 * 1024) return toast('Imagem muito grande (máx. 3 MB).', true);
          btn.disabled = true; btn.textContent = 'Enviando…';
          try {
            const j = await api('/api/admin/upload', { method: 'POST', raw: fl, type: fl.type });
            url.value = j.url; prev.src = j.url; prev.hidden = false; toast('Imagem enviada.');
          } catch (e) { toast(e.message, true); }
          finally { btn.disabled = false; btn.textContent = 'Enviar imagem'; file.value = ''; }
        });
        body.append(el('label', {}, [f.label, url, el('div', { class: 'upload' }, [btn, file, prev]), el('span', { class: 'hint', text: 'PNG, JPG, WEBP ou GIF até 3 MB. Proporção ideal 16:10.' })]));
        continue;
      } else input = el('input', { name: f.k, type: f.type || 'text', value: val ?? '', placeholder: f.placeholder, maxlength: f.max });
      body.append(el('label', {}, [f.label, input]));
    }
    modal.showModal();
    const first = $('input, textarea, select', body); if (first) first.focus();
  }

  $('#modalForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const { table, item } = current;
    const data = {};
    for (const n of $$('#modalBody [name]')) data[n.name] = n.type === 'checkbox' ? (n.checked ? 1 : 0) : n.value;
    const btn = $('#modalForm button[type=submit]'); btn.disabled = true;
    try {
      await api(item ? `/api/admin/${table}/${item.id}` : `/api/admin/${table}`, { method: item ? 'PUT' : 'POST', body: data });
      modal.close(); await reload(); render(); toast('Salvo! ✅');
    } catch (err) { $('#modalErr').textContent = err.message; }
    finally { btn.disabled = false; }
  });

  // ---------------- Mensagens ----------------
  async function viewMessages() {
    const msgs = await api('/api/admin/messages');
    const list = el('div', { class: 'list' });
    if (!msgs.length) list.append(el('p', { class: 'muted', text: 'Nenhuma mensagem recebida ainda.' }));
    for (const m of msgs) {
      const date = new Date(Number(m.created_at)).toLocaleString('pt-BR');
      const reply = 'mailto:' + encodeURIComponent(m.email).replace('%40', '@') + '?subject=' + encodeURIComponent('Re: ' + (m.subject || 'Contato pelo site'));
      const phoneDigits = (m.phone || '').replace(/\D/g, '');
      list.append(el('article', { class: 'msg' + (m.is_read ? '' : ' is-new') }, [
        el('header', {}, [
          el('div', {}, [el('b', { text: m.name }), m.is_read ? null : el('span', { class: 'tag', text: 'nova' }), el('div', { class: 'meta', text: `${m.email}${m.phone ? ' · ' + m.phone : ''}` })]),
          el('span', { class: 'meta', text: date })
        ]),
        m.subject ? el('div', { class: 'meta', text: 'Assunto: ' + m.subject }) : null,
        el('pre', { text: m.message }),
        el('div', { class: 'row__actions' }, [
          /^[^\s@]+@[^\s@]+$/.test(m.email) ? el('a', { class: 'btn btn--ghost btn--sm', href: reply, text: 'Responder por e-mail' }) : null,
          phoneDigits.length >= 10 ? el('a', { class: 'btn btn--ghost btn--sm', href: 'https://wa.me/' + (phoneDigits.length <= 11 ? '55' + phoneDigits : phoneDigits), target: '_blank', rel: 'noopener noreferrer', text: 'WhatsApp' }) : null,
          el('button', { class: 'btn btn--ghost btn--sm', text: m.is_read ? 'Marcar como não lida' : 'Marcar como lida', onclick: async () => {
            try { await api(`/api/admin/messages/${m.id}`, { method: 'PATCH', body: { is_read: m.is_read ? 0 : 1 } }); await reload(); render(); } catch (e) { toast(e.message, true); }
          } }),
          el('button', { class: 'btn btn--danger btn--sm', text: 'Excluir', onclick: async () => {
            if (!confirm('Excluir esta mensagem permanentemente?')) return;
            try { await api(`/api/admin/messages/${m.id}`, { method: 'DELETE' }); await reload(); render(); } catch (e) { toast(e.message, true); }
          } })
        ])
      ]));
    }
    return el('div', {}, [head('Mensagens', 'Contatos enviados pelo formulário do site.'), list]);
  }

  // ---------------- Segurança ----------------
  function viewSecurity() {
    const form = el('form', { class: 'group' }, [
      el('h3', { text: 'Trocar senha' }),
      el('div', { class: 'grid2' }, [
        el('label', { class: 'full' }, ['Senha atual', el('input', { type: 'password', name: 'current', autocomplete: 'current-password', required: true })]),
        el('label', {}, ['Nova senha', el('input', { type: 'password', name: 'new', autocomplete: 'new-password', required: true, minlength: 10 })]),
        el('label', {}, ['Repita a nova senha', el('input', { type: 'password', name: 'confirm', autocomplete: 'new-password', required: true })])
      ]),
      el('p', { class: 'hint', text: 'Mínimo de 10 caracteres, com letras maiúsculas, minúsculas e números.' }),
      el('button', { class: 'btn btn--primary', type: 'submit', text: 'Alterar senha' })
    ]);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (form.new.value !== form.confirm.value) return toast('As senhas não conferem.', true);
      try { await api('/api/admin/password', { method: 'POST', body: { current: form.current.value, new: form.new.value } }); form.reset(); toast('Senha alterada! Outras sessões foram encerradas.'); }
      catch (err) { toast(err.message, true); }
    });
    const logBox = el('section', { class: 'group' }, [el('h3', { text: 'Registro de atividades (últimas 100)' }), el('p', { class: 'muted', text: 'Carregando…' })]);
    api('/api/admin/audit').then((rows) => {
      const t = el('table', {}, [el('tr', {}, [el('th', { text: 'Data' }), el('th', { text: 'Ação' }), el('th', { text: 'Detalhe' })]),
        ...rows.map((r) => el('tr', {}, [el('td', { text: new Date(Number(r.created_at)).toLocaleString('pt-BR') }), el('td', { text: r.action }), el('td', { text: r.detail })]))]);
      logBox.replaceChildren(logBox.firstChild, t);
    }).catch((e) => toast(e.message, true));
    return el('div', {}, [head('Segurança', 'Senha de acesso e histórico de alterações no painel.'), form, logBox]);
  }

  // ---------------- Início ----------------
  (async () => {
    try {
      const me = await api('/api/admin/me');
      state.csrf = me.csrf;
      await enterApp(me.username);
    } catch { showLogin(); }
  })();
})();

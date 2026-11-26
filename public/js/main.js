/* =========================================================
   Vivix — script do site público
   Todo o conteúdo vem do banco de dados via /api/site e é
   inserido apenas com textContent (nunca como HTML), o que
   impede ataques de XSS.
   ========================================================= */
(() => {
  'use strict';

  // Ícones (SVG fixos, não vêm do banco)
  const ICONS = {
    code: '<path d="M8 6 2 12l6 6M16 6l6 6-6 6M14 4l-4 16"/>',
    cloud: '<path d="M7 18h10.5a4.5 4.5 0 0 0 .6-8.96A6 6 0 0 0 6.3 10.1 4 4 0 0 0 7 18Z"/>',
    shield: '<path d="M12 2.5 4 5.5v6c0 5 3.4 9.2 8 10.5 4.6-1.3 8-5.5 8-10.5v-6l-8-3Z"/><rect x="9" y="11" width="6" height="5" rx="1"/><path d="M10 11V9.5a2 2 0 0 1 4 0V11"/>',
    headset: '<path d="M4 14v-2a8 8 0 0 1 16 0v2"/><rect x="2.5" y="13" width="4" height="6" rx="1.5"/><rect x="17.5" y="13" width="4" height="6" rx="1.5"/><path d="M19.5 19c0 1.5-2 2.5-5 2.5"/>',
    network: '<rect x="3" y="3" width="18" height="12" rx="2"/><path d="M8 21h8M12 15v6"/>',
    bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4M9 4h6"/><circle cx="9" cy="14" r="1.3"/><circle cx="15" cy="14" r="1.3"/><path d="M2 13v3M22 13v3"/>',
    brain: '<path d="M9 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 1 5 3 3 0 0 0 4 3h0V3Z"/><path d="M15 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-1 5 3 3 0 0 1-4 3h0V3Z"/><path d="M9 9H7M9 14H6.5M15 9h2M15 14h2.5"/>',
    workflow: '<rect x="3" y="3" width="7" height="6" rx="1.5"/><rect x="14" y="15" width="7" height="6" rx="1.5"/><path d="M6.5 9v4a2 2 0 0 0 2 2H14"/><path d="m18 3 3 3-3 3M14 6h7"/>',
    chart: '<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 6-7"/><circle cx="20" cy="7" r="1"/>',
    sparkles: '<path d="M12 3l1.8 4.7L18.5 9.5 13.8 11.3 12 16l-1.8-4.7L5.5 9.5l4.7-1.8L12 3Z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15Z"/>',
    mobile: '<rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M11 18h2"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'
  };

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  /** Cria elementos de forma segura: el('a', {href, class}, ['texto', outroEl]) */
  function el(tag, attrs = {}, children = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of [].concat(children)) if (c !== null && c !== undefined) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  }

  function icon(name, cls) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.6');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    if (cls) svg.setAttribute('class', cls);
    svg.innerHTML = ICONS[name] || ICONS.code; // apenas SVG constante deste arquivo
    return svg;
  }

  function useIcon(id, cls = 'i') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', cls);
    svg.setAttribute('aria-hidden', 'true');
    const u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    u.setAttribute('href', '#' + id);
    svg.append(u);
    return svg;
  }

  /** Só aceita links http(s) ou imagens enviadas ao próprio site */
  function safeHref(u) {
    if (!u) return '';
    if (/^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(u)) return u;
    try {
      const p = new URL(u);
      return p.protocol === 'https:' || p.protocol === 'http:' ? p.href : '';
    } catch { return ''; }
  }

  const ext = (href, text, cls, kids) =>
    el('a', { href, class: cls, target: '_blank', rel: 'noopener noreferrer' }, kids || [text]);

  /** Coloca a última palavra em destaque azul */
  function accentLast(node, text) {
    const parts = String(text).trim().split(/\s+/);
    const last = parts.pop();
    node.replaceChildren(parts.length ? parts.join(' ') + ' ' : '', el('span', { class: 'accent', text: last }));
  }

  // ---------------- Renderização ----------------
  function applySettings(s) {
    $$('[data-s]').forEach((n) => {
      const v = s[n.dataset.s];
      if (typeof v === 'string' && v.trim()) n.textContent = v;
    });

    // Marca: "MaiconTech" -> Maicon + <b>Tech</b> ("Vivix" fica inteira)
    const brand = s.marca || 'Vivix';
    const m = brand.match(/^(.+?)([A-Z][a-z0-9]+)$/);
    $$('[data-brand]').forEach((n) => n.replaceChildren(m ? m[1] : brand, m ? el('b', { text: m[2] }) : ''));
    $$('[data-brand-plain]').forEach((n) => { n.textContent = brand; });

    if (s.hero_titulo) accentLast($('#heroTitle'), s.hero_titulo);
    document.title = `${brand} — ${s.marca_slogan || 'Tecnologia e Inteligência Artificial'}`;
    if (s.sobre_titulo) accentLast($('#aboutTitle'), s.sobre_titulo);

    // WhatsApp
    const wa = String(s.whatsapp || '').replace(/\D/g, '');
    const waUrl = wa ? `https://wa.me/${wa}${s.whatsapp_mensagem ? '?text=' + encodeURIComponent(s.whatsapp_mensagem) : ''}` : '';
    waLink = waUrl;
    $$('[data-wa]').forEach((a) => { if (waUrl) a.href = waUrl; else a.hidden = true; });

    // GitHub
    const gh = safeHref(s.github);
    $$('[data-github]').forEach((a) => { if (gh) a.href = gh; else a.hidden = true; });

    // Destaques do "Sobre"
    const hl = String(s.sobre_destaques || '').split('\n').map((x) => x.trim()).filter(Boolean);
    $('#aboutHighlights').replaceChildren(...hl.map((t) => el('li', { text: t })));

    // Lista de contatos + redes sociais
    const contacts = [];
    const socials = [];
    if (waUrl) {
      contacts.push(ext(waUrl, '', '', [useIcon('ico-wa'), el('span', {}, [el('small', { text: 'WhatsApp' }), formatPhone(wa)])]));
    }
    if (s.email) {
      const mail = 'mailto:' + encodeURIComponent(s.email).replace('%40', '@');
      contacts.push(el('a', { href: mail }, [useIcon('ico-mail'), el('span', {}, [el('small', { text: 'E-mail' }), s.email])]));
      socials.push(el('a', { href: mail, 'aria-label': 'E-mail' }, [useIcon('ico-mail', '')]));
    }
    if (gh) {
      contacts.push(ext(gh, '', '', [useIcon('ico-github'), el('span', {}, [el('small', { text: 'GitHub' }), gh.replace(/^https?:\/\/(www\.)?/, '')])]));
      socials.unshift(ext(gh, '', '', [useIcon('ico-github', '')]));
      socials[0].setAttribute('aria-label', 'GitHub');
    }
    for (const [key, id, label] of [['linkedin', 'ico-linkedin', 'LinkedIn'], ['instagram', 'ico-instagram', 'Instagram'], ['youtube', 'ico-youtube', 'YouTube']]) {
      const u = safeHref(s[key]);
      if (u) { const a = ext(u, '', '', [useIcon(id, '')]); a.setAttribute('aria-label', label); socials.push(a); }
    }
    if (waUrl) { const a = ext(waUrl, '', '', [useIcon('ico-wa', '')]); a.setAttribute('aria-label', 'WhatsApp'); socials.push(a); }
    $('#contactList').replaceChildren(...contacts.map((a) => el('li', {}, [a])));
    $('#socials').replaceChildren(...socials);

    if (s.mostrar_repos_github === '1' && s.github_usuario) loadRepos(s.github_usuario);
  }

  function formatPhone(d) {
    const m = d.match(/^55(\d{2})(\d{4,5})(\d{4})$/);
    return m ? `+55 (${m[1]}) ${m[2]}-${m[3]}` : '+' + d;
  }

  let allServices = [];
  function renderServices(filter = 'todos') {
    const list = allServices.filter((s) => filter === 'todos' || s.category === filter);
    const grid = $('#servicesGrid');
    if (!list.length) return grid.replaceChildren(el('p', { class: 'empty', text: 'Nenhum serviço nesta categoria.' }));
    grid.replaceChildren(...list.map((s) => el('article', { class: 'card' }, [
      s.category === 'ia' ? el('span', { class: 'badge', text: 'IA' }) : null,
      icon(s.icon, 'card__icon'),
      el('h3', { text: s.title }),
      el('p', { text: s.description })
    ])));
  }

  let waLink = '';
  function ctaCard() {
    return el('article', { class: 'project project--cta' }, [
      icon('sparkles', 'cta-ico'),
      el('h3', { text: 'Seu projeto pode ser o próximo' }),
      el('p', { text: 'Tem uma ideia com Inteligência Artificial ou precisa de um sistema sob medida? Vamos tirar do papel.' }),
      waLink ? ext(waLink, 'Conversar agora ›', 'btn btn--primary btn--sm') : el('a', { href: '#contato', class: 'btn btn--primary btn--sm', text: 'Conversar agora ›' })
    ]);
  }

  function renderProjects(projects) {
    const grid = $('#projectsGrid');
    grid.replaceChildren(...projects.map((p) => {
      const link = safeHref(p.link_url);
      const repo = safeHref(p.repo_url);
      const img = safeHref(p.image_url);
      const media = el('div', { class: 'project__img' }, [img ? el('img', { src: img, alt: p.title, loading: 'lazy' }) : icon(p.is_ai ? 'brain' : 'code')]);
      const tags = String(p.tags || '').split(',').map((t) => t.trim()).filter(Boolean);
      const links = [];
      if (link) links.push(ext(link, 'Ver projeto ›', 'link'));
      if (repo && repo !== link) links.push(ext(repo, '', 'link', [useIcon('ico-github'), 'Código']));
      return el('article', { class: 'project' }, [
        link ? ext(link, '', '', [media]) : media,
        el('div', { class: 'project__body' }, [
          el('div', { class: 'tags' }, [p.is_ai ? el('span', { text: '✦ IA' }) : null, ...tags.map((t) => el('span', { text: t }))]),
          el('h3', {}, [link ? ext(link, p.title) : p.title]),
          p.description ? el('p', { text: p.description }) : null,
          links.length ? el('div', { class: 'project__links' }, links) : null
        ])
      ]);
    }), ctaCard());
  }

  function renderTestimonials(list) {
    if (!list.length) return;
    $('#depoimentos').hidden = false;
    $('#testimonialsGrid').replaceChildren(...list.map((t) => el('figure', { class: 'testimonial' }, [
      el('blockquote', { text: `“${t.text}”` }),
      el('footer', {}, [
        el('div', {}, [el('b', { text: t.name }), t.role ? el('small', { text: t.role }) : null]),
        el('span', { class: 'stars', 'aria-label': `${t.rating} de 5 estrelas`, text: '★'.repeat(t.rating) })
      ])
    ])));
    observeReveal();
  }

  async function loadRepos(user) {
    if (!/^[A-Za-z0-9-]{1,39}$/.test(user)) return;
    const key = 'gh_repos_' + user;
    let repos = null;
    try { repos = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch { /* sem storage */ }
    if (!repos) {
      try {
        const r = await fetch(`https://api.github.com/users/${user}/repos?sort=updated&per_page=12`, { headers: { Accept: 'application/vnd.github+json' } });
        if (!r.ok) return;
        repos = (await r.json()).filter((x) => !x.fork).slice(0, 6)
          .map((x) => ({ name: x.name, description: x.description, html_url: x.html_url, language: x.language, stars: x.stargazers_count, updated: x.updated_at }));
        try { sessionStorage.setItem(key, JSON.stringify(repos)); } catch { /* ignora */ }
      } catch { return; }
    }
    if (!repos.length) return;
    $('#reposGrid').replaceChildren(...repos.map((r) => {
      const href = safeHref(r.html_url);
      if (!href || !href.startsWith('https://github.com/')) return null;
      const date = r.updated ? new Date(r.updated).toLocaleDateString('pt-BR') : '';
      return ext(href, '', 'repo', [
        el('b', { text: r.name }),
        el('p', { text: r.description || 'Sem descrição.' }),
        el('small', { text: [r.language, `★ ${r.stars || 0}`, date && `atualizado em ${date}`].filter(Boolean).join(' · ') })
      ]);
    }).filter(Boolean));
    $('#reposBlock').hidden = false;
  }

  // ---------------- Interações ----------------
  function setupTabs() {
    $$('.tab').forEach((b) => b.addEventListener('click', () => {
      $$('.tab').forEach((x) => { x.classList.toggle('is-active', x === b); x.setAttribute('aria-selected', String(x === b)); });
      renderServices(b.dataset.filter);
    }));
  }

  function setupMenu() {
    const btn = $('#menuBtn'); const nav = $('#nav');
    btn.addEventListener('click', () => {
      const open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      nav.classList.toggle('is-open', open);
    });
    $$('a', nav).forEach((a) => a.addEventListener('click', () => { btn.setAttribute('aria-expanded', 'false'); nav.classList.remove('is-open'); }));

    const header = $('.header');
    const onScroll = () => header.classList.toggle('is-scrolled', window.scrollY > 10);
    window.addEventListener('scroll', onScroll, { passive: true }); onScroll();

    const links = $$('.nav a');
    const sections = links.map((a) => $(a.getAttribute('href'))).filter(Boolean);
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) links.forEach((a) => a.classList.toggle('is-active', a.getAttribute('href') === '#' + e.target.id));
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    sections.forEach((s) => io.observe(s));
  }

  let revealIO;
  function observeReveal() {
    if (!('IntersectionObserver' in window)) { $$('.reveal').forEach((n) => n.classList.add('is-visible')); return; }
    revealIO = revealIO || new IntersectionObserver((entries) => entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add('is-visible'); revealIO.unobserve(e.target); }
    }), { threshold: 0.12 });
    $$('.reveal:not(.is-visible)').forEach((n) => revealIO.observe(n));
  }

  function setupChatDemo() {
    const msgs = $$('#chatDemo .msg');
    const io = new IntersectionObserver((entries) => {
      if (!entries[0].isIntersecting) return;
      io.disconnect();
      msgs.forEach((m, i) => setTimeout(() => m.classList.add('is-on'), 350 + i * 700));
    }, { threshold: 0.4 });
    io.observe($('#chatDemo'));
  }

  function setupForm() {
    const form = $('#contactForm');
    const status = $('#formStatus');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      status.className = 'form__status'; status.textContent = '';
      const data = Object.fromEntries(new FormData(form));
      if (!data.name || data.name.trim().length < 2) return showErr('Informe seu nome.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email || '')) return showErr('Informe um e-mail válido.');
      if (!data.message || data.message.trim().length < 10) return showErr('A mensagem deve ter pelo menos 10 caracteres.');
      const btn = $('button[type=submit]', form);
      btn.disabled = true;
      try {
        const r = await fetch('/api/contato', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.erro || 'Não foi possível enviar. Tente pelo WhatsApp.');
        form.reset();
        status.className = 'form__status ok';
        status.textContent = j.mensagem || 'Mensagem enviada!';
      } catch (e) { showErr(e.message); }
      finally { btn.disabled = false; }
    });
    function showErr(msg) { status.className = 'form__status err'; status.textContent = msg; }
  }

  // ---------------- Início ----------------
  async function init() {
    $('#year').textContent = new Date().getFullYear();
    setupMenu(); setupTabs(); setupForm(); setupChatDemo(); observeReveal();
    try {
      const r = await fetch('/api/site');
      if (!r.ok) throw new Error();
      const data = await r.json();
      applySettings(data.settings || {});
      allServices = data.services || [];
      renderServices();
      renderProjects(data.projects || []);
      renderTestimonials(data.testimonials || []);
    } catch {
      $('#servicesGrid').replaceChildren(el('p', { class: 'empty', text: 'Não foi possível carregar o conteúdo agora.' }));
    }
  }
  document.addEventListener('DOMContentLoaded', init);
})();

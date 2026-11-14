// App da carteira Krevo para navegador e celular (PWA). Usa a MESMA carteira leve da linha de
// comando (src/light/wallet.js): varredura local com view tags, provas de aceitação com PoW,
// anéis CLSAG, Bulletproofs e memos — tudo rodando aqui, em JavaScript puro.
// Chaves e frase ficam neste aparelho, cifradas com a sua senha (src/web/browser-wallet.js).
import './boot.js';
import { formatKRV, parseKRV } from '../params.js';
import { LightClient } from '../light/wallet.js';
import { createWallet, unlockWallet, storedWallets } from './browser-wallet.js';
import { generateMnemonic, normalizeMnemonic, mnemonicToEntropy } from '../wallet/bip39.js';
import { encodeQR, qrToSvg } from '../util/qrcode.js';
import { decodeAddress } from '../address.js';
import { buildPaymentURI, parsePaymentURI } from '../wallet/request.js';

const $app = document.getElementById('app');
const $toast = document.getElementById('toast');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = (grains) => formatKRV(grains).replace(' KRV', '');
const short = (s, a = 10, b = 6) => (s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s);
const $ = (sel) => $app.querySelector(sel);
const on = (sel, ev, fn) => { const el = $(sel); if (el) el.addEventListener(ev, fn); return el; };

const S = { w: null, tab: 'inicio', syncing: false, lastSync: 0, syncErr: null, timer: null, flow: null, recvKind: 's', from: 'auto', resolved: null };
let defaultServer = localStorage.getItem('krevo-servidor') ?? 'http://127.0.0.1:8090';

const ICONS = {
  home: '<path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  recv: '<path d="M12 4v13M6 11l6 6 6-6M5 20h14"/>',
  send: '<path d="M12 20V7M6 13l6-6 6 6M5 4h14"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5"/>',
  cam: '<path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>',
  inArrow: '<path d="M12 5v14M5 12l7 7 7-7"/>',
  outArrow: '<path d="M12 19V5M5 12l7-7 7 7"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]}</svg>`;
const qrSvg = (text) => qrToSvg(encodeQR(text, 'M'), { border: 2 }).replace(/^<\?xml[^>]*>\s*/, '');

let toastTimer;
function toast(msg, err = false) {
  $toast.textContent = msg;
  $toast.className = `toast show${err ? ' err' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $toast.className = 'toast'; }, err ? 6000 : 2600);
}
async function busy(btn, label, fn) {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span>${esc(label)}`;
  try { return await fn(); } catch (e) { toast(e.message, true); return undefined; } finally { btn.disabled = false; btn.innerHTML = old; }
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copiado'); } catch { toast('Não deu para copiar automaticamente; selecione o texto.', true); }
}
function modal(html, setup) {
  const m = document.createElement('div');
  m.className = 'modal';
  m.innerHTML = `<div class="sheet" role="dialog" aria-modal="true">${html}</div>`;
  document.body.appendChild(m);
  const close = () => m.remove();
  m.addEventListener('click', (e) => { if (e.target === m) close(); });
  setup?.(m, close);
  m.querySelector('input, button')?.focus();
  return close;
}

// ------------------------------------------------------------------ telas sem carteira aberta
function render() {
  if (!S.w) return S.flow ? renderFlow() : storedWallets().length ? renderUnlock() : renderWelcome();
  return renderMain();
}
const brand = '<div class="top"><div class="brand"><img src="/src/web/icon.svg" alt="">Krevo</div><div class="spacer"></div></div>';

function renderWelcome() {
  $app.className = 'app bare';
  $app.innerHTML = `${brand}
    <h1>Sua carteira, no seu aparelho.</h1>
    <p class="muted">Leve e privada: não precisa de nó próprio, e o servidor que você usar <b>nunca recebe suas chaves</b> — cada pagamento recebido é conferido com prova antes de contar no saldo.</p>
    <div class="card">
      <label for="srv">Servidor leve</label>
      <input id="srv" value="${esc(defaultServer)}" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <p class="hint">Qualquer servidor serve. Ele não consegue gastar, nem ver seu saldo privado.</p>
      <div class="stack">
        <button class="btn primary" id="b-new">Criar carteira nova</button>
        <button class="btn" id="b-restore">Restaurar com a frase de recuperação</button>
        ${storedWallets().length ? '<button class="btn" id="b-back">Voltar para as carteiras salvas</button>' : ''}
      </div>
    </div>`;
  const server = () => { defaultServer = $('#srv').value.trim().replace(/\/+$/, ''); localStorage.setItem('krevo-servidor', defaultServer); return defaultServer; };
  on('#b-new', 'click', (e) => busy(e.currentTarget, 'Conferindo o servidor…', async () => {
    const info = await new LightClient(server()).info();
    S.flow = { step: 'words', server: defaultServer, network: info.network, words: generateMnemonic(24).split(' ') };
    render();
  }));
  on('#b-restore', 'click', (e) => busy(e.currentTarget, 'Conferindo o servidor…', async () => {
    const info = await new LightClient(server()).info();
    S.flow = { step: 'restore', server: defaultServer, network: info.network };
    render();
  }));
  on('#b-back', 'click', () => { S.flow = null; renderUnlock(); });
}

function renderFlow() {
  const f = S.flow;
  $app.className = 'app bare';
  const back = '<button class="btn" id="f-back">Voltar</button>';
  if (f.step === 'words') {
    $app.innerHTML = `${brand}<h1>Frase de recuperação</h1>
      <p class="muted">Estas 24 palavras <b>são</b> a sua carteira. Anote em papel, na ordem, e guarde em lugar seguro. Quem tiver a frase controla o dinheiro — nunca tire foto, nunca digite em sites, nunca envie por mensagem.</p>
      <div class="card"><ol class="words blur" id="words">${f.words.map((w) => `<li>${esc(w)}</li>`).join('')}</ol>
      <div class="stack"><button class="btn" id="show">Mostrar as palavras</button>
      <button class="btn primary" id="next" disabled>Anotei em papel</button>${back}</div></div>`;
    on('#show', 'click', (e) => { $('#words').classList.remove('blur'); e.currentTarget.remove(); $('#next').disabled = false; });
    on('#next', 'click', () => { f.step = 'confirm'; f.ask = pick3(); render(); });
  } else if (f.step === 'confirm') {
    $app.innerHTML = `${brand}<h1>Confira a frase</h1><p class="muted">Digite estas palavras da sua anotação:</p>
      <div class="card">${f.ask.map((i) => `<label for="c${i}">Palavra nº ${i + 1}</label><input id="c${i}" autocomplete="off" autocapitalize="off" spellcheck="false">`).join('')}
      <div class="stack"><button class="btn primary" id="next">Continuar</button>${back}</div></div>`;
    on('#next', 'click', () => {
      const ok = f.ask.every((i) => $(`#c${i}`).value.trim().toLowerCase() === f.words[i]);
      if (!ok) return toast('Alguma palavra não confere. Olhe a anotação de novo.', true);
      f.step = 'password'; f.mnemonic = f.words.join(' '); render();
    });
  } else if (f.step === 'restore') {
    $app.innerHTML = `${brand}<h1>Restaurar</h1><p class="muted">Digite a frase de 12 ou 24 palavras, separadas por espaço.</p>
      <div class="card"><label for="ph">Frase de recuperação</label><textarea id="ph" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>
      <p class="hint" id="ph-hint"></p><div class="stack"><button class="btn primary" id="next">Continuar</button>${back}</div></div>`;
    on('#next', 'click', () => {
      try {
        const m = normalizeMnemonic($('#ph').value);
        mnemonicToEntropy(m);
        f.mnemonic = m; f.step = 'password'; render();
      } catch (e) { $('#ph-hint').className = 'hint err'; $('#ph-hint').textContent = e.message; }
    });
  } else if (f.step === 'password') {
    $app.innerHTML = `${brand}<h1>Senha deste aparelho</h1>
      <p class="muted">Ela cifra a carteira aqui no navegador. Se esquecer, é só restaurar com a frase.</p>
      <div class="card"><label for="p1">Senha (mínimo 8 caracteres)</label><input id="p1" type="password" autocomplete="new-password">
      <label for="p2">Repita a senha</label><input id="p2" type="password" autocomplete="new-password">
      <p class="hint">Rede: <b>${esc(f.network)}</b> · servidor ${esc(f.server)}</p>
      <div class="stack"><button class="btn primary" id="go">Criar carteira</button>${back}</div></div>`;
    on('#go', 'click', (e) => {
      const p1 = $('#p1').value, p2 = $('#p2').value;
      if (p1.length < 8) return toast('A senha precisa de pelo menos 8 caracteres.', true);
      if (p1 !== p2) return toast('As senhas não conferem.', true);
      return busy(e.currentTarget, 'Cifrando e criando…', async () => {
        S.w = await createWallet({ server: f.server, password: p1, mnemonic: f.mnemonic });
        S.flow = null; S.tab = 'inicio';
        startSync();
        render();
        toast('Carteira criada');
      });
    });
  }
  on('#f-back', 'click', () => { S.flow = null; render(); });
}
function pick3() {
  const s = new Set();
  while (s.size < 3) s.add(crypto.getRandomValues(new Uint32Array(1))[0] % 24);
  return [...s].sort((a, b) => a - b);
}

function renderUnlock() {
  const list = storedWallets();
  $app.className = 'app bare';
  $app.innerHTML = `${brand}<h1>Bem-vindo de volta</h1>
    <div class="card">
      ${list.length > 1 ? `<label for="net">Carteira</label><select id="net">${list.map((x) => `<option value="${esc(x.network)}">${esc(x.network)} · ${esc(x.server)}</option>`).join('')}</select>`
    : `<p class="muted small">Rede <b>${esc(list[0].network)}</b> · ${esc(list[0].server)}</p>`}
      <label for="pw">Senha</label><input id="pw" type="password" autocomplete="current-password">
      <div class="stack"><button class="btn primary" id="go">Abrir</button><button class="btn" id="other">Criar ou restaurar outra</button></div>
    </div>`;
  const go = (btn) => busy(btn, 'Abrindo…', async () => {
    const net = $('#net')?.value ?? list[0].network;
    S.w = await unlockWallet(net, $('#pw').value);
    S.tab = 'inicio';
    startSync();
    render();
  });
  on('#go', 'click', (e) => go(e.currentTarget));
  on('#pw', 'keydown', (e) => { if (e.key === 'Enter') go($('#go')); });
  on('#other', 'click', () => renderWelcome());
  $('#pw').focus();
}

// ------------------------------------------------------------------ sincronização
function startSync() {
  clearInterval(S.timer);
  S.timer = setInterval(() => { if (document.visibilityState === 'visible') syncNow(); }, 20_000);
  syncNow();
}
async function syncNow() {
  if (!S.w || S.syncing) return;
  S.syncing = true;
  paintStatus();
  try {
    await S.w.sync();
    S.lastSync = Date.now();
    S.syncErr = null;
  } catch (e) {
    S.syncErr = e.message;
  } finally {
    S.syncing = false;
    paintStatus();
    if (S.w && S.tab === 'inicio') paintHome();
  }
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') syncNow(); });

function statusChip() {
  if (S.syncing) return '<span class="chip"><span class="spin"></span>sincronizando</span>';
  if (S.syncErr) return `<span class="chip bad" title="${esc(S.syncErr)}"><span class="dot"></span>sem conexão</span>`;
  if (S.lastSync) return '<span class="chip good"><span class="dot"></span>atualizado</span>';
  return '<span class="chip">—</span>';
}
function paintStatus() { const el = document.getElementById('status'); if (el) el.innerHTML = statusChip(); }

// ------------------------------------------------------------------ carteira aberta
function renderMain() {
  $app.className = 'app';
  $app.innerHTML = `<div class="top"><div class="brand"><img src="/src/web/icon.svg" alt="">Krevo</div>
      <span class="chip">${esc(S.w.network)}</span><div class="spacer"></div><span id="status">${statusChip()}</span>
      <button class="iconbtn" id="refresh" aria-label="Atualizar">${icon('refresh')}</button>
      <button class="iconbtn" id="lock" aria-label="Bloquear">${icon('lock')}</button></div>
    <div id="view"></div>
    <nav class="nav" aria-label="Seções"><div class="inner">
      ${[['inicio', 'home', 'Início'], ['receber', 'recv', 'Receber'], ['enviar', 'send', 'Enviar'], ['ajustes', 'gear', 'Ajustes']]
    .map(([t, i, l]) => `<button data-tab="${t}" ${S.tab === t ? 'aria-current="page"' : ''}>${icon(i)}${l}</button>`).join('')}
    </div></nav>`;
  $app.querySelectorAll('.nav button').forEach((b) => b.addEventListener('click', () => { S.tab = b.dataset.tab; renderMain(); }));
  on('#refresh', 'click', () => syncNow());
  on('#lock', 'click', () => { clearInterval(S.timer); S.w = null; S.lastSync = 0; render(); });
  ({ inicio: paintHome, receber: paintReceive, enviar: paintSend, ajustes: paintSettings })[S.tab]();
}

function paintHome() {
  const view = document.getElementById('view');
  if (!view) return;
  const w = S.w, b = w.balance();
  const avail = b.shielded + b.transparent;
  const maturing = b.shieldedImmature + b.transparentImmature + b.shieldedPending + b.transparentPending;
  const fraud = Object.entries(w.fraudReports);
  const h = w.history();
  const mine = new Set(h.sent.map((s) => s.txid)); // saídas das minhas próprias transações = troco
  const received = [...h.received].reverse().map((r) => (mine.has(r.txid)
    ? `<div class="tx"><div class="ico">${icon('refresh')}</div><div class="main"><b>Troco</b><span>volta do seu envio${r.spent ? ' · já gasto' : ''}</span></div>
      <div class="amt">${esc(num(r.amount))}</div></div>`
    : `<div class="tx"><div class="ico">${icon('inArrow')}</div>
      <div class="main"><b>Recebido${r.coinbase ? ' (mineração)' : ''}</b><span>${r.memo ? `“${esc(r.memo)}”` : esc(r.subLabel)}${r.spent ? ' · já gasto' : ''}</span></div>
      <div class="amt in">+${esc(num(r.amount))}</div></div>`));
  const sent = h.sent.map((s) => `<div class="tx"><div class="ico">${icon('outArrow')}</div>
      <div class="main"><b>Enviado${s.name ? ` para @${esc(s.name)}` : ''}</b><span>${esc(new Date(s.time).toLocaleString('pt-BR'))} · ${esc(short(s.to, 12, 6))}${s.memo ? ` · “${esc(s.memo)}”` : ''}</span></div>
      <div class="amt">−${esc(num(s.amount))}</div></div>`);
  view.innerHTML = `<div class="card">
      <div class="balance-label">Saldo disponível</div>
      <div class="balance">${esc(num(avail))}<small>KRV</small></div>
      <div class="split"><div class="stat"><b>${esc(num(b.shielded))}</b><span>privado</span></div><div class="stat"><b>${esc(num(b.transparent))}</b><span>transparente</span></div></div>
      ${maturing > 0n ? `<div class="notice">Chegando: ${esc(formatKRV(maturing))} (aguardando confirmações)</div>` : ''}
      ${b.unverified > 0n ? `<div class="notice warn">Aguardando prova: ${esc(formatKRV(b.unverified))}. O servidor informou; a carteira só conta depois de conferir a prova (alguns segundos).</div>` : ''}
      ${fraud.map(([txid, why]) => `<div class="notice bad">O servidor enviou dados FALSOS sobre ${esc(short(txid, 10, 6))}: ${esc(why)}. Esse valor foi ignorado — considere trocar de servidor.</div>`).join('')}
      ${w.discrepancies.map((d) => `<div class="notice warn">Servidores divergem: ${esc(d)}</div>`).join('')}
      ${w.serverUrls.length > 1 && !w.discrepancies.length && S.lastSync ? '<p class="hint ok">2 servidores comparados: concordam.</p>' : ''}
    </div>
    <div class="row"><button class="btn primary" data-go="enviar">${icon('send')}Enviar</button><button class="btn" data-go="receber">${icon('recv')}Receber</button></div>
    <h2>Atividade</h2>
    <div class="card">${[...received, ...sent].join('') || '<div class="empty">Nada por aqui ainda. Toque em Receber para ver seu endereço.</div>'}</div>`;
  view.querySelectorAll('[data-go]').forEach((el) => el.addEventListener('click', () => { S.tab = el.dataset.go; renderMain(); }));
}

function paintReceive() {
  const w = S.w;
  const view = document.getElementById('view');
  const addr = S.recvKind === 's' ? w.sAddress : w.tAddress;
  view.innerHTML = `<div class="card">
      <div class="seg" role="group" aria-label="Tipo de endereço">
        <button data-k="s" aria-pressed="${S.recvKind === 's'}">Privado</button><button data-k="t" aria-pressed="${S.recvKind === 't'}">Transparente</button></div>
      <div class="qr" id="qr"></div>
      <div class="addr mono" id="addr">${esc(addr)}</div>
      <div class="row mt"><button class="btn" id="copy">Copiar</button>${navigator.share ? '<button class="btn" id="share">Compartilhar</button>' : ''}</div>
      <label for="ramt">Pedir um valor (opcional)</label><input id="ramt" inputmode="decimal" placeholder="0,00" autocomplete="off">
      <p class="hint">${S.recvKind === 's'
    ? 'Privado: o valor e quem recebe ficam ocultos na rede. Cada pagamento vai para um endereço de uso único.'
    : 'Transparente: valores visíveis na rede, como no Bitcoin. Prefira o privado.'}</p></div>`;
  let current = addr;
  const paint = () => {
    let uri = addr;
    const v = $('#ramt').value.trim();
    if (v) { try { uri = buildPaymentURI(w.params, { address: addr, amount: parseKRV(v) }); } catch { uri = addr; } }
    current = uri;
    $('#qr').innerHTML = qrSvg(uri);
    $('#addr').textContent = uri;
  };
  paint();
  view.querySelectorAll('.seg button').forEach((b) => b.addEventListener('click', () => { S.recvKind = b.dataset.k; paintReceive(); }));
  on('#ramt', 'input', paint);
  on('#copy', 'click', () => copy(current));
  on('#share', 'click', () => navigator.share({ title: 'Meu endereço Krevo', text: current }).catch(() => {}));
}

function paintSend() {
  const w = S.w;
  const view = document.getElementById('view');
  const canScan = 'BarcodeDetector' in window && !!navigator.mediaDevices?.getUserMedia;
  view.innerHTML = `<div class="card">
      <label for="to">Para</label>
      <div class="row"><input id="to" placeholder="krs1…, krv1… ou @nome" autocomplete="off" autocapitalize="off" spellcheck="false">
      ${canScan ? `<button class="iconbtn" id="scan" aria-label="Ler QR code">${icon('cam')}</button>` : ''}</div>
      <p class="hint" id="to-hint">Cole um endereço, um link krevo: ou um @nome.</p>
      <label for="amt">Valor (KRV)</label><input id="amt" inputmode="decimal" placeholder="0,00" autocomplete="off">
      <label for="memo">Mensagem (opcional)</label><input id="memo" maxlength="120" autocomplete="off" placeholder="só para endereço privado — cifrada">
      <label>Pagar com</label>
      <div class="seg" role="group" aria-label="Origem">${[['auto', 'Automático'], ['privado', 'Privado'], ['transparente', 'Transparente']]
    .map(([k, l]) => `<button data-from="${k}" aria-pressed="${S.from === k}">${l}</button>`).join('')}</div>
      <div class="stack mt"><button class="btn primary" id="review">Revisar</button></div></div>`;
  let seq = 0;
  const check = async () => {
    const raw = $('#to').value.trim(), hint = $('#to-hint'), my = ++seq;
    S.resolved = null;
    if (!raw) { hint.className = 'hint'; hint.textContent = 'Cole um endereço, um link krevo: ou um @nome.'; return; }
    if (raw.toLowerCase().startsWith('krevo:')) {
      try {
        const r = parsePaymentURI(w.params, raw);
        $('#to').value = r.address;
        if (r.amount) $('#amt').value = num(r.amount);
        if (r.memo) $('#memo').value = r.memo;
        return check();
      } catch (e) { hint.className = 'hint err'; hint.textContent = e.message; return; }
    }
    if (raw.startsWith('@')) {
      hint.className = 'hint'; hint.textContent = 'Procurando o nome…';
      try {
        const info = await w.resolveName(raw);
        if (my !== seq) return;
        if (info.status !== 'ativo') { hint.className = 'hint err'; hint.textContent = info.status === 'livre' ? 'Nome não registrado.' : 'Nome vencido (em carência).'; return; }
        S.resolved = { kind: info.targetType, address: info.target, name: info.name };
        hint.className = 'hint ok';
        hint.textContent = `@${info.name} → ${short(info.target, 14, 8)} (${info.targetType === 's' ? 'privado' : 'transparente'})`;
      } catch (e) { if (my === seq) { hint.className = 'hint err'; hint.textContent = e.message; } }
      return;
    }
    try {
      const a = decodeAddress(w.params, raw);
      S.resolved = { kind: a.type, address: raw };
      hint.className = 'hint ok';
      hint.textContent = { s: 'Endereço privado: valor e destinatário ocultos.', t: 'Endereço transparente: valor visível.', q: 'Endereço quântico (transparente).', m: 'Endereço de multiassinatura (transparente).' }[a.type] ?? 'Endereço válido.';
    } catch (e) { hint.className = 'hint err'; hint.textContent = e.message; }
  };
  let t;
  on('#to', 'input', () => { clearTimeout(t); t = setTimeout(check, 250); });
  view.querySelectorAll('[data-from]').forEach((b) => b.addEventListener('click', () => {
    S.from = b.dataset.from;
    view.querySelectorAll('[data-from]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  }));
  on('#scan', 'click', () => scanQr((text) => { $('#to').value = text; check(); }));
  on('#review', 'click', async () => {
    await check();
    const to = $('#to').value.trim(), memo = $('#memo').value.trim();
    if (!S.resolved) return toast('Confira o destino.', true);
    let amount;
    try { amount = parseKRV($('#amt').value); if (amount <= 0n) throw new Error(); } catch { return toast('Valor inválido.', true); }
    if (memo && S.resolved.kind !== 's') return toast('Mensagem só vai cifrada para endereço privado (krs1…).', true);
    const fromLabel = { auto: 'automático', privado: 'saldo privado', transparente: 'saldo transparente' }[S.from];
    modal(`<h1>Confirmar envio</h1>
      <div class="kv"><span>Para</span><span class="mono">${esc(S.resolved.name ? `@${S.resolved.name}` : short(to, 14, 8))}</span></div>
      ${S.resolved.name ? `<div class="kv"><span>Endereço</span><span class="mono">${esc(short(S.resolved.address, 14, 8))}</span></div>` : ''}
      <div class="kv"><span>Valor</span><span><b>${esc(formatKRV(amount))}</b></span></div>
      <div class="kv"><span>Origem</span><span>${esc(fromLabel)}</span></div>
      ${memo ? `<div class="kv"><span>Mensagem</span><span>${esc(memo)}</span></div>` : ''}
      <p class="hint">A taxa da rede é uma fração de centavo e é calculada na hora.</p>
      <div class="stack mt"><button class="btn primary" id="confirm">Enviar agora</button><button class="btn" id="cancel">Cancelar</button></div>`,
    (m, close) => {
      m.querySelector('#cancel').addEventListener('click', close);
      m.querySelector('#confirm').addEventListener('click', (e) => busy(e.currentTarget, S.from === 'transparente' ? 'Montando e assinando…' : 'Provando e assinando… (um gasto privado prova pertencer a TODAS as saídas da rede: leva alguns segundos)', async () => {
        const t0 = Date.now();
        const r = await w.send({ to, amount, from: S.from, memo: memo || undefined });
        close();
        const done = modal(`<h1>Enviado</h1><div class="kv"><span>Taxa</span><span>${esc(formatKRV(r.fee))}</span></div>
          <div class="kv"><span>Transação</span><span class="mono">${esc(short(r.txid, 12, 8))}</span></div>
          <p id="conf" class="hint"><span class="spin"></span> aguardando a rede…</p><div class="stack"><button class="btn primary" id="ok">Pronto</button></div>`,
        (m2, close2) => m2.querySelector('#ok').addEventListener('click', () => { close2(); S.tab = 'inicio'; renderMain(); }));
        try {
          await w.waitAccepted(r.txid, 60_000);
          const el = document.getElementById('conf');
          if (el) { el.className = 'hint ok'; el.textContent = `Confirmado pela rede em ${((Date.now() - t0) / 1000).toFixed(1).replace('.', ',')} s.`; }
        } catch { const el = document.getElementById('conf'); if (el) el.textContent = 'Ainda não confirmado; a carteira continua acompanhando.'; }
        void done;
        syncNow();
      }));
    });
  });
}

async function scanQr(onText) {
  let stream, stop = false;
  const close = modal('<h1>Ler QR code</h1><video class="cam" autoplay playsinline muted></video><div class="stack mt"><button class="btn" id="x">Fechar</button></div>',
    (m, closeFn) => m.querySelector('#x').addEventListener('click', closeFn));
  const finish = () => { stop = true; stream?.getTracks().forEach((t) => t.stop()); close(); };
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const video = document.querySelector('.modal video');
    video.srcObject = stream;
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    const loop = async () => {
      if (stop || !document.body.contains(video)) { stream.getTracks().forEach((t) => t.stop()); return; }
      try { const codes = await det.detect(video); if (codes[0]) { finish(); onText(codes[0].rawValue); return; } } catch { /* quadro ainda não pronto */ }
      requestAnimationFrame(loop);
    };
    loop();
  } catch (e) { finish(); toast(`Câmera indisponível: ${e.message}`, true); }
}

function paintSettings() {
  const w = S.w;
  const view = document.getElementById('view');
  const delegated = !!w.light.delegate;
  const [srv1, srv2 = ''] = w.serverUrl.split(',');
  view.innerHTML = `<h2>Servidor</h2><div class="card">
      <label for="srv">Servidor leve</label><input id="srv" value="${esc(srv1)}" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <label for="srv2">Segundo servidor (opcional)</label><input id="srv2" value="${esc(srv2)}" placeholder="de outra pessoa ou empresa" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <p class="hint">Com dois servidores de donos diferentes, a carteira compara as respostas: se um esconder um pagamento ou mostrar uma moeda que já foi gasta, o outro denuncia.</p>
      <div class="stack mt"><button class="btn" id="save-srv">Salvar servidores</button></div>
      <label>Como encontrar seus pagamentos</label>
      <div class="seg" role="group" aria-label="Varredura"><button data-scan="local" aria-pressed="${!delegated}">Neste aparelho</button><button data-scan="delegada" aria-pressed="${delegated}">Pelo servidor</button></div>
      <p class="hint">${delegated
    ? 'Pelo servidor: economiza bateria, mas ele recebe sua chave de visualização e vê o que você recebe (continua sem poder gastar).'
    : 'Neste aparelho (recomendado): o servidor não recebe nenhuma chave e não sabe quais pagamentos são seus.'}</p></div>
    <h2>Segurança</h2><div class="card stack">
      <button class="btn" id="phrase">Mostrar frase de recuperação</button>
      <button class="btn" id="viewkey">Copiar chave de visualização (só leitura)</button>
      <button class="btn danger" id="forget">Apagar a carteira deste aparelho</button></div>
    <h2>Sobre</h2><div class="card small muted">
      <p>Rede <b>${esc(w.network)}</b>. Carteira leve: a varredura acontece aqui, e cada valor recebido só conta depois de uma prova (Merkle + ${esc(String(w.proofDepth))} blocos com prova de trabalho por cima).</p>
      <p>Endereços quânticos (krq) e multiassinatura ficam na carteira de linha de comando.</p></div>`;
  on('#save-srv', 'click', (e) => busy(e.currentTarget, 'Conferindo…', async () => {
    const urls = [$('#srv').value, $('#srv2').value].map((u) => u.trim().replace(/\/+$/, '')).filter(Boolean);
    if (!urls.length) throw new Error('informe o servidor leve');
    if (urls.length === 2 && urls[0] === urls[1]) throw new Error('o segundo servidor precisa ser diferente do primeiro');
    for (const url of urls) {
      const info = await new LightClient(url).info();
      if (info.network !== w.network) throw new Error(`${url} é da rede ${info.network}`);
    }
    w.setServer(urls.join(','));
    toast(urls.length === 2 ? 'Servidores salvos: a carteira vai comparar os dois' : 'Servidor salvo');
    syncNow();
  }));
  view.querySelectorAll('[data-scan]').forEach((b) => b.addEventListener('click', () => { w.setDelegated(b.dataset.scan === 'delegada'); paintSettings(); syncNow(); }));
  on('#phrase', 'click', () => askPassword('Mostrar a frase', async (pw) => {
    const phrase = await w.revealMnemonic(pw); // decifrada agora; não fica guardada na memória
    modal(`<h1>Frase de recuperação</h1><p class="muted small">Não tire foto. Não mostre a ninguém.</p>
      <ol class="words">${phrase.split(' ').map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
      <div class="stack mt"><button class="btn" id="x">Fechar</button></div>`, (m, close) => m.querySelector('#x').addEventListener('click', close));
  }));
  on('#viewkey', 'click', () => copy(w.keys.viewKey(w.params)));
  on('#forget', 'click', () => modal(`<h1>Apagar deste aparelho?</h1>
      <p>O dinheiro não some — ele está na rede. Mas sem a frase de recuperação você <b>não</b> conseguirá abrir esta carteira de novo.</p>
      <div class="stack"><button class="btn danger" id="yes">Apagar</button><button class="btn" id="no">Cancelar</button></div>`, (m, close) => {
    m.querySelector('#no').addEventListener('click', close);
    m.querySelector('#yes').addEventListener('click', () => { w.forget(); close(); clearInterval(S.timer); S.w = null; render(); toast('Carteira apagada deste aparelho'); });
  }));
}

function askPassword(title, then) {
  modal(`<h1>${esc(title)}</h1><label for="ap">Senha</label><input id="ap" type="password" autocomplete="current-password">
    <div class="stack mt"><button class="btn primary" id="ok">Confirmar</button><button class="btn" id="no">Cancelar</button></div>`, (m, close) => {
    m.querySelector('#no').addEventListener('click', close);
    m.querySelector('#ok').addEventListener('click', (e) => busy(e.currentTarget, 'Conferindo…', async () => {
      const pw = m.querySelector('#ap').value;
      if (!(await S.w.checkPassword(pw))) throw new Error('senha incorreta');
      close();
      await then(pw);
    }));
  });
}

window.addEventListener('unhandledrejection', (e) => toast(e.reason?.message ?? String(e.reason), true));
if ('serviceWorker' in navigator && window.isSecureContext) navigator.serviceWorker.register('/sw.js').catch(() => {});
render();

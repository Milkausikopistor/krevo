// Krevo wallet app for browsers and phones (PWA). It runs the SAME light wallet as the command
// line (src/light/wallet.js): local scanning with view tags, acceptance proofs with proof of work,
// full-chain membership proofs, Bulletproofs and memos — all running here, in the browser.
// Keys and the recovery phrase stay on this device, encrypted with your password (src/web/browser-wallet.js).
// Every text goes through t() (src/web/i18n.js): English is the default, other languages are dictionaries.
import './boot.js';
import { formatKRV, parseKRV } from '../params.js';
import { LightClient } from '../light/wallet.js';
import { createWallet, unlockWallet, storedWallets } from './browser-wallet.js';
import { generateMnemonic, normalizeMnemonic, mnemonicToEntropy } from '../wallet/bip39.js';
import { encodeQR, qrToSvg } from '../util/qrcode.js';
import { decodeAddress } from '../address.js';
import { buildPaymentURI, parsePaymentURI } from '../wallet/request.js';
import { t, lang, setLang, locale, localNumber, LANGUAGES } from './i18n.js';

const $app = document.getElementById('app');
const $toast = document.getElementById('toast');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const krv = (grains) => localNumber(formatKRV(grains));              // "1,234.5 KRV" / "1.234,5 KRV"
const num = (grains) => krv(grains).replace(' KRV', '');
const plain = (grains) => localNumber(formatKRV(grains).replace(' KRV', '').replace(/,/g, '')); // for inputs: no grouping
const short = (s, a = 10, b = 6) => (s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s);
const $ = (sel) => $app.querySelector(sel);
const on = (sel, ev, fn) => { const el = $(sel); if (el) el.addEventListener(ev, fn); return el; };

/** Amount typed by the user, in the format of the chosen language. "1,000" (en) or "1.000" (pt) is refused: thousands or decimals? */
function parseAmount(v) {
  const s = String(v).trim();
  if (lang() === 'pt') {
    if (/^\d{1,3}(\.\d{3})+$/.test(s)) throw new Error(t('Ambiguous amount: use a comma for decimals (e.g. 1000 or 2,5).'));
    if (s.includes(',')) return parseKRV(s.replace(/\./g, '').replace(',', '.'));
    return parseKRV(s);
  }
  if (/^\d{1,3}(,\d{3})+$/.test(s)) throw new Error(t('Ambiguous amount: use a dot for decimals (e.g. 1000 or 2.5).'));
  return parseKRV(s);
}

const S = { w: null, tab: 'home', syncing: false, lastSync: 0, syncErr: null, timer: null, flow: null, recvKind: 's', from: 'auto', resolved: null };
const SERVER_KEY = 'krevo-server';
let defaultServer = localStorage.getItem(SERVER_KEY) ?? localStorage.getItem('krevo-servidor') ?? 'http://127.0.0.1:8090';

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
const langSelect = (cls = '') => `<select id="lang" class="${cls}" aria-label="${esc(t('Language'))}">${Object.entries(LANGUAGES)
  .map(([k, name]) => `<option value="${k}"${k === lang() ? ' selected' : ''}>${esc(name)}</option>`).join('')}</select>`;
const bindLang = () => on('#lang', 'change', (e) => { setLang(e.target.value); render(); });

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
  try { return await fn(); } catch (e) { toast(t(e.message), true); return undefined; } finally { btn.disabled = false; btn.innerHTML = old; }
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast(t('Copied')); } catch { toast(t('Could not copy automatically; please select the text.'), true); }
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

// ------------------------------------------------------------------ screens without an open wallet
function render() {
  if (!S.w) return S.flow ? renderFlow() : storedWallets().length ? renderUnlock() : renderWelcome();
  return renderMain();
}
const brand = () => `<div class="top"><div class="brand"><span class="wordmark">krevo</span></div><div class="spacer"></div>${langSelect('lang')}</div>`;

function renderWelcome() {
  $app.className = 'app bare';
  $app.innerHTML = `${brand()}
    <h1>${t('Your wallet, on your device.')}</h1>
    <p class="muted">${t('Light and private: no node of your own, and the server you use <b>never gets your keys</b> — every payment you receive is checked against a proof before it counts in your balance.')}</p>
    <div class="card">
      <label for="srv">${t('Light server')}</label>
      <input id="srv" value="${esc(defaultServer)}" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <p class="hint">${t('Any server works. It can neither spend your coins nor see your private balance.')}</p>
      <div class="stack">
        <button class="btn primary" id="b-new">${t('Create a new wallet')}</button>
        <button class="btn" id="b-restore">${t('Restore from recovery phrase')}</button>
        ${storedWallets().length ? `<button class="btn" id="b-back">${t('Back to saved wallets')}</button>` : ''}
      </div>
    </div>
    <ul class="features">
      <li><b>${t('Private by default')}</b><span>${t('Amounts and recipients stay hidden on the network.')}</span></li>
      <li><b>${t('Your keys, your device')}</b><span>${t('Encrypted here; nothing goes to the server.')}</span></li>
      <li><b>${t('Installable')}</b><span>${t('Works as an app on phones and computers.')}</span></li>
    </ul>`;
  bindLang();
  const server = () => { defaultServer = $('#srv').value.trim().replace(/\/+$/, ''); localStorage.setItem(SERVER_KEY, defaultServer); return defaultServer; };
  on('#b-new', 'click', (e) => busy(e.currentTarget, t('Checking the server…'), async () => {
    const info = await new LightClient(server()).info();
    S.flow = { step: 'words', server: defaultServer, network: info.network, words: generateMnemonic(24).split(' ') };
    render();
  }));
  on('#b-restore', 'click', (e) => busy(e.currentTarget, t('Checking the server…'), async () => {
    const info = await new LightClient(server()).info();
    S.flow = { step: 'restore', server: defaultServer, network: info.network };
    render();
  }));
  on('#b-back', 'click', () => { S.flow = null; renderUnlock(); });
}

function renderFlow() {
  const f = S.flow;
  $app.className = 'app bare';
  const back = `<button class="btn" id="f-back">${t('Back')}</button>`;
  if (f.step === 'words') {
    $app.innerHTML = `${brand()}<h1>${t('Recovery phrase')}</h1>
      <p class="muted">${t('These 24 words <b>are</b> your wallet. Write them on paper, in order, and keep them somewhere safe. Whoever has the phrase controls the money — never take a photo, never type it into websites, never send it in a message.')}</p>
      <div class="card"><ol class="words blur" id="words">${f.words.map((w) => `<li>${esc(w)}</li>`).join('')}</ol>
      <div class="stack"><button class="btn" id="show">${t('Show the words')}</button>
      <button class="btn primary" id="next" disabled>${t('I wrote them down')}</button>${back}</div></div>`;
    on('#show', 'click', (e) => { $('#words').classList.remove('blur'); e.currentTarget.remove(); $('#next').disabled = false; });
    on('#next', 'click', () => { f.step = 'confirm'; f.ask = pick3(); render(); });
  } else if (f.step === 'confirm') {
    $app.innerHTML = `${brand()}<h1>${t('Check the phrase')}</h1><p class="muted">${t('Type these words from your notes:')}</p>
      <div class="card">${f.ask.map((i) => `<label for="c${i}">${t('Word #{n}', { n: i + 1 })}</label><input id="c${i}" autocomplete="off" autocapitalize="off" spellcheck="false">`).join('')}
      <div class="stack"><button class="btn primary" id="next">${t('Continue')}</button>${back}</div></div>`;
    on('#next', 'click', () => {
      const ok = f.ask.every((i) => $(`#c${i}`).value.trim().toLowerCase() === f.words[i]);
      if (!ok) return toast(t('A word does not match. Check your notes again.'), true);
      f.step = 'password'; f.mnemonic = f.words.join(' '); render();
    });
  } else if (f.step === 'restore') {
    $app.innerHTML = `${brand()}<h1>${t('Restore')}</h1><p class="muted">${t('Type your 12 or 24 word phrase, separated by spaces.')}</p>
      <div class="card"><label for="ph">${t('Recovery phrase')}</label><textarea id="ph" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>
      <p class="hint" id="ph-hint"></p><div class="stack"><button class="btn primary" id="next">${t('Continue')}</button>${back}</div></div>`;
    on('#next', 'click', () => {
      try {
        const m = normalizeMnemonic($('#ph').value);
        mnemonicToEntropy(m);
        f.mnemonic = m; f.step = 'password'; render();
      } catch (e) { $('#ph-hint').className = 'hint err'; $('#ph-hint').textContent = e.message; }
    });
  } else if (f.step === 'password') {
    $app.innerHTML = `${brand()}<h1>${t('Password for this device')}</h1>
      <p class="muted">${t('It encrypts the wallet here in the browser. If you forget it, just restore from the phrase.')}</p>
      <div class="card"><label for="p1">${t('Password (at least 8 characters)')}</label><input id="p1" type="password" autocomplete="new-password">
      <label for="p2">${t('Repeat the password')}</label><input id="p2" type="password" autocomplete="new-password">
      <p class="hint">${t('Network: <b>{network}</b> · server {server}', { network: esc(f.network), server: esc(f.server) })}</p>
      <div class="stack"><button class="btn primary" id="go">${t('Create wallet')}</button>${back}</div></div>`;
    on('#go', 'click', (e) => {
      const p1 = $('#p1').value, p2 = $('#p2').value;
      if (p1.length < 8) return toast(t('The password needs at least 8 characters.'), true);
      if (p1 !== p2) return toast(t('The passwords do not match.'), true);
      return busy(e.currentTarget, t('Encrypting and creating…'), async () => {
        S.w = await createWallet({ server: f.server, password: p1, mnemonic: f.mnemonic });
        S.flow = null; S.tab = 'home';
        startSync();
        render();
        toast(t('Wallet created'));
      });
    });
  }
  bindLang();
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
  $app.innerHTML = `${brand()}<h1>${t('Welcome back')}</h1>
    <div class="card">
      ${list.length > 1 ? `<label for="net">${t('Wallet')}</label><select id="net">${list.map((x) => `<option value="${esc(x.network)}">${esc(x.network)} · ${esc(x.server)}</option>`).join('')}</select>`
    : `<p class="muted small">${t('Network <b>{network}</b> · {server}', { network: esc(list[0].network), server: esc(list[0].server) })}</p>`}
      <label for="pw">${t('Password')}</label><input id="pw" type="password" autocomplete="current-password">
      <div class="stack"><button class="btn primary" id="go">${t('Open')}</button><button class="btn" id="other">${t('Create or restore another')}</button></div>
    </div>`;
  bindLang();
  const go = (btn) => busy(btn, t('Opening…'), async () => {
    const net = $('#net')?.value ?? list[0].network;
    S.w = await unlockWallet(net, $('#pw').value);
    S.tab = 'home';
    startSync();
    render();
  });
  on('#go', 'click', (e) => go(e.currentTarget));
  on('#pw', 'keydown', (e) => { if (e.key === 'Enter') go($('#go')); });
  on('#other', 'click', () => renderWelcome());
  $('#pw').focus();
}

// ------------------------------------------------------------------ syncing
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
    if (S.w && S.tab === 'home') paintHome();
  }
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') syncNow(); });

function statusChip() {
  // on narrow screens only the indicator shows; the text stays for screen readers (class lbl)
  if (S.syncing) return `<span class="chip status" title="${esc(t('syncing'))}"><span class="spin"></span><span class="lbl">${t('syncing')}</span></span>`;
  if (S.syncErr) return `<span class="chip status bad" title="${esc(t('offline'))}: ${esc(S.syncErr)}"><span class="dot"></span><span class="lbl">${t('offline')}</span></span>`;
  if (S.lastSync) return `<span class="chip status good" title="${esc(t('up to date'))}"><span class="dot"></span><span class="lbl">${t('up to date')}</span></span>`;
  return '<span class="chip">—</span>';
}
function paintStatus() { const el = document.getElementById('status'); if (el) el.innerHTML = statusChip(); }

// ------------------------------------------------------------------ open wallet
function renderMain() {
  $app.className = 'app';
  $app.innerHTML = `<div class="top"><div class="brand"><span class="wordmark">krevo</span></div>
      <span class="chip net">${esc(S.w.network)}</span><div class="spacer"></div><span id="status">${statusChip()}</span>
      <button class="iconbtn" id="refresh" aria-label="${esc(t('Refresh'))}">${icon('refresh')}</button>
      <button class="iconbtn" id="lock" aria-label="${esc(t('Lock'))}">${icon('lock')}</button></div>
    <div id="view"></div>
    <nav class="nav" aria-label="${esc(t('Sections'))}"><div class="inner">
      ${[['home', 'home', 'Home'], ['receive', 'recv', 'Receive'], ['send', 'send', 'Send'], ['settings', 'gear', 'Settings']]
    .map(([tab, i, l]) => `<button data-tab="${tab}" ${S.tab === tab ? 'aria-current="page"' : ''}>${icon(i)}${t(l)}</button>`).join('')}
    </div></nav>`;
  $app.querySelectorAll('.nav button').forEach((b) => b.addEventListener('click', () => { S.tab = b.dataset.tab; renderMain(); }));
  on('#refresh', 'click', () => syncNow());
  on('#lock', 'click', () => { clearInterval(S.timer); S.w = null; S.lastSync = 0; render(); });
  ({ home: paintHome, receive: paintReceive, send: paintSend, settings: paintSettings })[S.tab]();
}

function paintHome() {
  const view = document.getElementById('view');
  if (!view) return;
  const w = S.w, b = w.balance();
  const avail = b.shielded + b.transparent;
  const maturing = b.shieldedImmature + b.transparentImmature + b.shieldedPending + b.transparentPending;
  const fraud = Object.entries(w.fraudReports);
  const h = w.history();
  const mine = new Set(h.sent.map((s) => s.txid)); // outputs of my own transactions = change
  const spent = (r) => (r.spent ? t(' · spent') : '');
  const received = [...h.received].reverse().map((r) => (mine.has(r.txid)
    ? `<div class="tx"><div class="ico">${icon('refresh')}</div><div class="main"><b>${t('Change')}</b><span>${t('back from your payment')}${spent(r)}</span></div>
      <div class="amt">${esc(num(r.amount))}</div></div>`
    : `<div class="tx"><div class="ico">${icon('inArrow')}</div>
      <div class="main"><b>${t('Received')}${r.coinbase ? t(' (mining)') : ''}</b><span>${r.memo ? `“${esc(r.memo)}”` : esc(r.subLabel === 'main' ? t('main address') : r.subLabel)}${spent(r)}</span></div>
      <div class="amt in">+${esc(num(r.amount))}</div></div>`));
  const sent = h.sent.map((s) => `<div class="tx"><div class="ico">${icon('outArrow')}</div>
      <div class="main"><b>${s.name ? t('Sent to @{name}', { name: esc(s.name) }) : t('Sent')}</b><span>${esc(new Date(s.time).toLocaleString(locale()))} · ${esc(short(s.to, 12, 6))}${s.memo ? ` · “${esc(s.memo)}”` : ''}</span></div>
      <div class="amt">−${esc(num(s.amount))}</div></div>`);
  view.innerHTML = `<div class="card hero">
      <div class="balance-label">${t('Available balance')}</div>
      <div class="balance">${esc(num(avail))}<small>KRV</small></div>
      <div class="split"><div class="stat"><b>${esc(num(b.shielded))}</b><span>${t('private')}</span></div><div class="stat"><b>${esc(num(b.transparent))}</b><span>${t('transparent')}</span></div></div>
      ${maturing > 0n ? `<div class="notice">${t('Incoming: {amount} (waiting for confirmations)', { amount: esc(krv(maturing)) })}</div>` : ''}
      ${b.unverified > 0n ? `<div class="notice warn">${t('Waiting for proof: {amount}. The server reported it; the wallet only counts it after checking the proof (a few seconds).', { amount: esc(krv(b.unverified)) })}</div>` : ''}
      ${fraud.map(([txid, why]) => `<div class="notice bad">${t('The server sent FALSE data about {tx}: {why}. That amount was ignored — consider switching servers.', { tx: esc(short(txid, 10, 6)), why: esc(why) })}</div>`).join('')}
      ${w.discrepancies.map((d) => `<div class="notice warn">${t('Servers disagree: {d}', { d: esc(d) })}</div>`).join('')}
      ${w.serverUrls.length > 1 && !w.discrepancies.length && S.lastSync ? `<p class="hint ok">${t('2 servers compared: they agree.')}</p>` : ''}
    </div>
    <div class="row"><button class="btn primary" data-go="send">${icon('send')}${t('Send')}</button><button class="btn" data-go="receive">${icon('recv')}${t('Receive')}</button></div>
    <h2>${t('Activity')}</h2>
    <div class="card">${[...received, ...sent].join('') || `<div class="empty">${t('Nothing here yet. Tap Receive to see your address.')}</div>`}</div>`;
  view.querySelectorAll('[data-go]').forEach((el) => el.addEventListener('click', () => { S.tab = el.dataset.go; renderMain(); }));
}

function paintReceive() {
  const w = S.w;
  const view = document.getElementById('view');
  const addr = S.recvKind === 's' ? w.sAddress : w.tAddress;
  view.innerHTML = `<div class="card">
      <div class="seg" role="group" aria-label="${esc(t('Address type'))}">
        <button data-k="s" aria-pressed="${S.recvKind === 's'}">${t('Private')}</button><button data-k="t" aria-pressed="${S.recvKind === 't'}">${t('Transparent')}</button></div>
      <div class="qr" id="qr"></div>
      <div class="addr mono" id="addr">${esc(addr)}</div>
      <div class="row mt"><button class="btn" id="copy">${t('Copy')}</button>${navigator.share ? `<button class="btn" id="share">${t('Share')}</button>` : ''}</div>
      <label for="ramt">${t('Request an amount (optional)')}</label><input id="ramt" inputmode="decimal" placeholder="${esc(localNumber('0.00'))}" autocomplete="off">
      <p class="hint">${S.recvKind === 's'
    ? t('Private: the amount and the recipient stay hidden on the network. Each payment goes to a one-time address.')
    : t('Transparent: amounts are visible on the network, as in Bitcoin. Prefer private.')}</p></div>`;
  let current = addr;
  const paint = () => {
    let uri = addr;
    const v = $('#ramt').value.trim();
    if (v) { try { uri = buildPaymentURI(w.params, { address: addr, amount: parseAmount(v) }); } catch { uri = addr; } }
    current = uri;
    $('#qr').innerHTML = qrSvg(uri);
    $('#addr').textContent = uri;
  };
  paint();
  view.querySelectorAll('.seg button').forEach((b) => b.addEventListener('click', () => { S.recvKind = b.dataset.k; paintReceive(); }));
  on('#ramt', 'input', paint);
  on('#copy', 'click', () => copy(current));
  on('#share', 'click', () => navigator.share({ title: t('My Krevo address'), text: current }).catch(() => {}));
}

function paintSend() {
  const w = S.w;
  const view = document.getElementById('view');
  const canScan = 'BarcodeDetector' in window && !!navigator.mediaDevices?.getUserMedia;
  view.innerHTML = `<div class="card">
      <label for="to">${t('To')}</label>
      <div class="row"><input id="to" placeholder="${esc(t('krs1…, krv1… or @name'))}" autocomplete="off" autocapitalize="off" spellcheck="false">
      ${canScan ? `<button class="iconbtn" id="scan" aria-label="${esc(t('Scan QR code'))}">${icon('cam')}</button>` : ''}</div>
      <p class="hint" id="to-hint">${t('Paste an address, a krevo: link or an @name.')}</p>
      <label for="amt">${t('Amount (KRV)')}</label><input id="amt" inputmode="decimal" placeholder="${esc(localNumber('0.00'))}" autocomplete="off">
      <label for="memo">${t('Message (optional)')}</label><input id="memo" maxlength="120" autocomplete="off" placeholder="${esc(t('private addresses only — encrypted'))}">
      <label>${t('Pay from')}</label>
      <div class="seg" role="group" aria-label="${esc(t('Source'))}">${[['auto', 'Automatic'], ['private', 'Private'], ['transparent', 'Transparent']]
    .map(([k, l]) => `<button data-from="${k}" aria-pressed="${S.from === k}">${t(l)}</button>`).join('')}</div>
      <div class="stack mt"><button class="btn primary" id="review">${t('Review')}</button></div></div>`;
  let seq = 0;
  const check = async () => {
    const raw = $('#to').value.trim(), hint = $('#to-hint'), my = ++seq;
    S.resolved = null;
    if (!raw) { hint.className = 'hint'; hint.textContent = t('Paste an address, a krevo: link or an @name.'); return; }
    if (raw.toLowerCase().startsWith('krevo:')) {
      try {
        const r = parsePaymentURI(w.params, raw);
        $('#to').value = r.address;
        if (r.amount) $('#amt').value = plain(r.amount);
        if (r.memo) $('#memo').value = r.memo;
        return check();
      } catch (e) { hint.className = 'hint err'; hint.textContent = e.message; return; }
    }
    if (raw.startsWith('@')) {
      hint.className = 'hint'; hint.textContent = t('Looking up the name…');
      try {
        const info = await w.resolveName(raw);
        if (my !== seq) return;
        if (info.status !== 'active') { hint.className = 'hint err'; hint.textContent = info.status === 'free' ? t('Name not registered.') : t('Name expired (in grace period).'); return; }
        S.resolved = { kind: info.targetType, address: info.target, name: info.name };
        hint.className = 'hint ok';
        hint.textContent = `@${info.name} → ${short(info.target, 14, 8)} (${info.targetType === 's' ? t('private') : t('transparent')})`;
      } catch (e) { if (my === seq) { hint.className = 'hint err'; hint.textContent = e.message; } }
      return;
    }
    try {
      const a = decodeAddress(w.params, raw);
      S.resolved = { kind: a.type, address: raw };
      hint.className = 'hint ok';
      hint.textContent = t({ s: 'Private address: amount and recipient hidden.', t: 'Transparent address: amount visible.', q: 'Quantum-safe address (transparent).', m: 'Multisig address (transparent).' }[a.type] ?? 'Valid address.');
    } catch (e) { hint.className = 'hint err'; hint.textContent = e.message; }
  };
  let timer;
  on('#to', 'input', () => { clearTimeout(timer); timer = setTimeout(check, 250); });
  view.querySelectorAll('[data-from]').forEach((b) => b.addEventListener('click', () => {
    S.from = b.dataset.from;
    view.querySelectorAll('[data-from]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  }));
  on('#scan', 'click', () => scanQr((text) => { $('#to').value = text; check(); }));
  on('#review', 'click', async () => {
    await check();
    const to = $('#to').value.trim(), memo = $('#memo').value.trim();
    if (!S.resolved) return toast(t('Check the recipient.'), true);
    let amount;
    try { amount = parseAmount($('#amt').value); if (amount <= 0n) throw new Error(t('Invalid amount.')); } catch (e) { return toast(/Ambiguous|Valor amb/.test(e.message) ? e.message : t('Invalid amount.'), true); }
    if (memo && S.resolved.kind !== 's') return toast(t('Messages are only encrypted to private addresses (krs1…).'), true);
    const fromLabel = t({ auto: 'automatic', private: 'private balance', transparent: 'transparent balance' }[S.from]);
    modal(`<h1>${t('Confirm payment')}</h1>
      <div class="kv"><span>${t('To')}</span><span class="mono">${esc(S.resolved.name ? `@${S.resolved.name}` : short(to, 14, 8))}</span></div>
      ${S.resolved.name ? `<div class="kv"><span>${t('Address')}</span><span class="mono">${esc(short(S.resolved.address, 14, 8))}</span></div>` : ''}
      <div class="kv"><span>${t('Amount')}</span><span><b>${esc(krv(amount))}</b></span></div>
      <div class="kv"><span>${t('From')}</span><span>${esc(fromLabel)}</span></div>
      ${memo ? `<div class="kv"><span>${t('Message')}</span><span>${esc(memo)}</span></div>` : ''}
      <p class="hint">${t('The network fee is a fraction of a cent and is calculated when sending.')}</p>
      <div class="stack mt"><button class="btn primary" id="confirm">${t('Send now')}</button><button class="btn" id="cancel">${t('Cancel')}</button></div>`,
    (m, close) => {
      m.querySelector('#cancel').addEventListener('click', close);
      m.querySelector('#confirm').addEventListener('click', (e) => busy(e.currentTarget, S.from === 'transparent' ? t('Building and signing…') : t('Proving and signing… (a private spend proves it belongs to ALL outputs of the network: it takes a few seconds)'), async () => {
        const t0 = Date.now();
        const r = await w.send({ to, amount, from: S.from, memo: memo || undefined });
        close();
        const done = modal(`<h1>${t('Sent')}</h1><div class="kv"><span>${t('Fee')}</span><span>${esc(krv(r.fee))}</span></div>
          <div class="kv"><span>${t('Transaction')}</span><span class="mono">${esc(short(r.txid, 12, 8))}</span></div>
          <p id="conf" class="hint"><span class="spin"></span> ${t('waiting for the network…')}</p><div class="stack"><button class="btn primary" id="ok">${t('Done')}</button></div>`,
        (m2, close2) => m2.querySelector('#ok').addEventListener('click', () => { close2(); S.tab = 'home'; renderMain(); }));
        try {
          await w.waitAccepted(r.txid, 60_000);
          const el = document.getElementById('conf');
          if (el) { el.className = 'hint ok'; el.textContent = t('Confirmed by the network in {s} s.', { s: localNumber(((Date.now() - t0) / 1000).toFixed(1)) }); }
        } catch { const el = document.getElementById('conf'); if (el) el.textContent = t('Not confirmed yet; the wallet keeps watching.'); }
        void done;
        syncNow();
      }));
    });
  });
}

async function scanQr(onText) {
  let stream, stop = false;
  const close = modal(`<h1>${t('Scan QR code')}</h1><video class="cam" autoplay playsinline muted></video><div class="stack mt"><button class="btn" id="x">${t('Close')}</button></div>`,
    (m, closeFn) => m.querySelector('#x').addEventListener('click', closeFn));
  const finish = () => { stop = true; stream?.getTracks().forEach((tr) => tr.stop()); close(); };
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const video = document.querySelector('.modal video');
    video.srcObject = stream;
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    const loop = async () => {
      if (stop || !document.body.contains(video)) { stream.getTracks().forEach((tr) => tr.stop()); return; }
      try { const codes = await det.detect(video); if (codes[0]) { finish(); onText(codes[0].rawValue); return; } } catch { /* frame not ready yet */ }
      requestAnimationFrame(loop);
    };
    loop();
  } catch (e) { finish(); toast(t('Camera unavailable: {error}', { error: e.message }), true); }
}

function paintSettings() {
  const w = S.w;
  const view = document.getElementById('view');
  const delegated = !!w.light.delegate;
  const [srv1, srv2 = ''] = w.serverUrl.split(',');
  view.innerHTML = `<h2>${t('Language')}</h2><div class="card">${langSelect()}</div>
    <h2>${t('Server')}</h2><div class="card">
      <label for="srv">${t('Light server')}</label><input id="srv" value="${esc(srv1)}" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <label for="srv2">${t('Second server (optional)')}</label><input id="srv2" value="${esc(srv2)}" placeholder="${esc(t('run by another person or company'))}" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false">
      <p class="hint">${t('With two servers run by different owners, the wallet compares their answers: if one hides a payment or shows a coin that was already spent, the other exposes it.')}</p>
      <div class="stack mt"><button class="btn" id="save-srv">${t('Save servers')}</button></div>
      <label>${t('How to find your payments')}</label>
      <div class="seg" role="group" aria-label="${esc(t('Scanning'))}"><button data-scan="local" aria-pressed="${!delegated}">${t('On this device')}</button><button data-scan="delegated" aria-pressed="${delegated}">${t('By the server')}</button></div>
      <p class="hint">${delegated
    ? t('By the server: saves battery, but the server receives your view key and sees what you receive (it still cannot spend).')
    : t('On this device (recommended): the server receives no key and does not know which payments are yours.')}</p></div>
    <h2>${t('Security')}</h2><div class="card stack">
      <button class="btn" id="phrase">${t('Show recovery phrase')}</button>
      <button class="btn" id="viewkey">${t('Copy view key (read-only)')}</button>
      <button class="btn danger" id="forget">${t('Remove the wallet from this device')}</button></div>
    <h2>${t('About')}</h2><div class="card small muted">
      <p>${t('Network <b>{network}</b>. Light wallet: scanning happens here, and every amount received only counts after a proof (Merkle + {depth} blocks with proof of work on top).', { network: esc(w.network), depth: esc(String(w.proofDepth)) })}</p>
      <p>${t('Quantum-safe addresses (krq) and multisig are available in the command-line wallet.')}</p></div>`;
  bindLang();
  on('#save-srv', 'click', (e) => busy(e.currentTarget, t('Checking…'), async () => {
    const urls = [$('#srv').value, $('#srv2').value].map((u) => u.trim().replace(/\/+$/, '')).filter(Boolean);
    if (!urls.length) throw new Error(t('enter the light server'));
    if (urls.length === 2 && urls[0] === urls[1]) throw new Error(t('the second server must be different from the first'));
    for (const url of urls) {
      const info = await new LightClient(url).info();
      if (info.network !== w.network) throw new Error(t('{url} is on the {network} network', { url, network: info.network }));
    }
    w.setServer(urls.join(','));
    toast(urls.length === 2 ? t('Servers saved: the wallet will compare them') : t('Server saved'));
    syncNow();
  }));
  view.querySelectorAll('[data-scan]').forEach((b) => b.addEventListener('click', () => { w.setDelegated(b.dataset.scan === 'delegated'); paintSettings(); syncNow(); }));
  on('#phrase', 'click', () => askPassword(t('Show the phrase'), async (pw) => {
    const phrase = await w.revealMnemonic(pw); // decrypted now; not kept in memory
    modal(`<h1>${t('Recovery phrase')}</h1><p class="muted small">${t('Do not take a photo. Do not show it to anyone.')}</p>
      <ol class="words">${phrase.split(' ').map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
      <div class="stack mt"><button class="btn" id="x">${t('Close')}</button></div>`, (m, close) => m.querySelector('#x').addEventListener('click', close));
  }));
  on('#viewkey', 'click', () => copy(w.keys.viewKey(w.params)));
  on('#forget', 'click', () => modal(`<h1>${t('Remove from this device?')}</h1>
      <p>${t('The money does not disappear — it is on the network. But without the recovery phrase you will <b>not</b> be able to open this wallet again.')}</p>
      <div class="stack"><button class="btn danger" id="yes">${t('Remove')}</button><button class="btn" id="no">${t('Cancel')}</button></div>`, (m, close) => {
    m.querySelector('#no').addEventListener('click', close);
    m.querySelector('#yes').addEventListener('click', () => { w.forget(); close(); clearInterval(S.timer); S.w = null; render(); toast(t('Wallet removed from this device')); });
  }));
}

function askPassword(title, then) {
  modal(`<h1>${esc(title)}</h1><label for="ap">${t('Password')}</label><input id="ap" type="password" autocomplete="current-password">
    <div class="stack mt"><button class="btn primary" id="ok">${t('Confirm')}</button><button class="btn" id="no">${t('Cancel')}</button></div>`, (m, close) => {
    m.querySelector('#no').addEventListener('click', close);
    m.querySelector('#ok').addEventListener('click', (e) => busy(e.currentTarget, t('Checking…'), async () => {
      const pw = m.querySelector('#ap').value;
      if (!(await S.w.checkPassword(pw))) throw new Error(t('wrong password'));
      close();
      await then(pw);
    }));
  });
}

window.addEventListener('unhandledrejection', (e) => toast(e.reason?.message ?? String(e.reason), true));
if ('serviceWorker' in navigator && window.isSecureContext) navigator.serviceWorker.register('/sw.js').catch(() => {});
render();

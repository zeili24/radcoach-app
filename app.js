/* radcoach – Handy-App. Lädt den verschlüsselten Schnappschuss (data.enc) vom PC, entschlüsselt ihn lokal und
   schickt Änderungen (Gefühl, Verschieben, Nachholen, Auslassen) verschlüsselt in den Branch "inbox" des Repos. */
'use strict';
const $ = s => document.querySelector(s);
const LS = {get: k => { try { return JSON.parse(localStorage.getItem('rc_' + k)) } catch { return null } },
  set: (k, v) => localStorage.setItem('rc_' + k, JSON.stringify(v)), del: k => localStorage.removeItem('rc_' + k)};
const DN = ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'];
const STATUS = {strong: ['💪', 'übertroffen'], done: ['✅', 'geschafft'], partial: ['🟡', 'teilweise'],
  failed: ['❌', 'nicht geschafft'], missed: ['⏭️', 'ausgelassen']};
const RPE = {1: 'sehr locker', 2: 'locker', 3: 'leicht', 4: 'angenehm', 5: 'mittel', 6: 'fordernd', 7: 'hart',
  8: 'sehr hart', 9: 'am Limit', 10: 'maximal'};
const PH = {base: 'Grundlage', build: 'Aufbau', peak: 'Spitze', taper: 'Tapering', recovery: 'Erholung'};
let S = null, tab = 'today';

// ------------------------------------------------------------------ Hilfen
const pad = n => String(n).padStart(2, '0');
const iso = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const D = s => new Date(s.slice(0, 10) + 'T12:00');
const TODAY = () => iso(new Date());
const addDays = (s, n) => { const d = D(s); d.setDate(d.getDate() + n); return iso(d) };
const dlabel = s => { const d = D(s); return `${DN[d.getDay()]} ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.` };
const dnice = s => { const t = TODAY(); return s === t ? 'Heute' : s === addDays(t, 1) ? 'Morgen' : s === addDays(t, -1) ? 'Gestern' : dlabel(s) };
const mins = s => Math.round(s / 60);
const fmt = s => { const m = Math.floor(s / 60), r = s % 60; return r ? `${m}:${pad(r)}` : `${m}′` };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const zc = p => p < .56 ? 'var(--z1)' : p < .76 ? 'var(--z2)' : p < .88 ? 'var(--z3)' : p < 1 ? 'var(--z4)' : p < 1.2 ? 'var(--z5)' : p < 1.5 ? 'var(--z6)' : 'var(--z7)';
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
function toast(msg, ms = 2600) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), ms) }
function ago(isoTs) { const m = Math.round((Date.now() - new Date(isoTs)) / 60000);
  return m < 2 ? 'gerade eben' : m < 60 ? `vor ${m} min` : m < 1440 ? `vor ${Math.round(m / 60)} h` : `vor ${Math.round(m / 1440)} Tagen` }
function repo() {  // zeili24.github.io/radcoach-app/ -> zeili24/radcoach-app (lokal testbar mit ?repo=a/b)
  const q = new URLSearchParams(location.search).get('repo'); if (q) LS.set('repo', q);
  if (LS.get('repo')) return LS.get('repo');
  const m = location.hostname.match(/^([^.]+)\.github\.io$/); const p = location.pathname.split('/').filter(Boolean)[0];
  return m && p ? `${m[1]}/${p}` : null }

// ------------------------------------------------------------------ Krypto (passt zu radcoach/crypto.py)
async function deriveKeys(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter}, base, 512);
  return new Uint8Array(bits) }
async function keyObjs(raw) {
  return {enc: await crypto.subtle.importKey('raw', raw.slice(0, 32), 'AES-CTR', false, ['encrypt', 'decrypt']),
    mac: await crypto.subtle.importKey('raw', raw.slice(32), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify'])} }
async function unseal(env, k) {
  const iv = unb64(env.iv), ct = unb64(env.ct), both = new Uint8Array(iv.length + ct.length); both.set(iv); both.set(ct, iv.length);
  if (!await crypto.subtle.verify('HMAC', k.mac, unb64(env.mac), both)) throw new Error('key');
  const raw = await crypto.subtle.decrypt({name: 'AES-CTR', counter: iv, length: 64}, k.enc, ct);
  const txt = await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  return JSON.parse(txt) }
async function seal(obj, k) {
  const iv = new Uint8Array(16); crypto.getRandomValues(iv.subarray(0, 8));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-CTR', counter: iv, length: 64}, k.enc, new TextEncoder().encode(JSON.stringify(obj))));
  const both = new Uint8Array(16 + ct.length); both.set(iv); both.set(ct, 16);
  const mac = await crypto.subtle.sign('HMAC', k.mac, both);
  return JSON.stringify({v: 1, iv: b64(iv), ct: b64(ct), mac: b64(mac)}) }

// ------------------------------------------------------------------ Laden
let KEYS = null, ENV = null;
async function fetchEnv() {
  const r = await fetch('data.enc?t=' + Date.now(), {cache: 'no-store'});
  if (!r.ok) throw new Error('Noch keine Daten – am PC einmal ein Update machen.');
  return r.json() }
async function load(quiet) {
  try { ENV = await fetchEnv() } catch (e) {
    const c = LS.get('cache'); if (c && KEYS) { ENV = c } else { return lockScreen(e.message) }
    if (!quiet) toast('Offline – zeige letzten Stand') }
  const raw = LS.get('keys');
  if (!raw || LS.get('salt') !== ENV.salt) return lockScreen();
  try { KEYS = await keyObjs(unb64(raw)); S = await unseal(ENV, KEYS) } catch { LS.del('keys'); return lockScreen('Passwort wurde geändert – bitte neu eingeben.') }
  LS.set('cache', ENV);
  reconcile(); render(); if (!quiet) toast(`Stand vom PC: ${ago(S.generated)}`) }
async function unlock(pw) {
  const btn = $('#unlockbtn'); btn.disabled = true; btn.innerHTML = '<span class="spin">⟳</span> entschlüssle …';
  try {
    ENV = ENV || await fetchEnv();
    const raw = await deriveKeys(pw, unb64(ENV.salt), ENV.iter);
    KEYS = await keyObjs(raw); S = await unseal(ENV, KEYS);
    LS.set('keys', b64(raw)); LS.set('salt', ENV.salt); LS.set('cache', ENV);
    reconcile(); render(); toast('Willkommen! 🚴')
  } catch (e) { btn.disabled = false; btn.textContent = 'Entsperren'; toast(e.message === 'key' ? 'Falsches Passwort' : e.message) } }
function lockScreen(msg) {
  $('#tabs').classList.add('hidden');
  $('#app').innerHTML = `<div class="lock"><img class="logo" src="icon-180.png" alt="">
    <h1>radcoach</h1><div class="sub">${msg ? esc(msg) : 'Deine Trainingsdaten sind verschlüsselt.<br>Gib dein App-Passwort ein.'}</div>
    <form onsubmit="event.preventDefault();unlock(this.pw.value)" style="display:flex;flex-direction:column;gap:10px;margin-top:10px">
    <input class="field" name="pw" type="password" autocomplete="current-password" placeholder="App-Passwort" required>
    <button class="big" id="unlockbtn">Entsperren</button></form>
    <div class="muted">Das Passwort hast du am PC bei „Handy-App einrichten“ festgelegt.</div></div>` }

// ------------------------------------------------------------------ Änderungen ans PC-Postfach
const pending = () => LS.get('pending') || [];
function reconcile() {  // erledigte Aufträge (vom PC zurückgemeldet) aus der Warteliste nehmen
  const done = Object.fromEntries((S.processed || []).map(p => [p.id, p]));
  const left = [];
  for (const p of pending()) {
    if (done[p.id]) { if (!done[p.id].ok) toast('⚠️ ' + done[p.id].msg, 5000) }
    else if (Date.now() - p.at < 7 * 864e5) left.push(p) }
  LS.set('pending', left) }
async function send(act, label) {
  const token = LS.get('token'), rp = repo();
  if (!token || !rp) { openSettings('Für Änderungen vom Handy braucht die App einmalig einen GitHub-Token.'); return false }
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  const body = await seal({...act, id, created: new Date().toISOString()}, KEYS);
  const r = await fetch(`https://api.github.com/repos/${rp}/contents/inbox/${Date.now()}-${id}.json`, {method: 'PUT',
    headers: {Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json'},
    body: JSON.stringify({message: label, branch: 'inbox', content: btoa(body)})});
  if (!r.ok) { const j = await r.json().catch(() => ({})); toast('GitHub: ' + (j.message || r.status), 5000); return false }
  LS.set('pending', [...pending(), {...act, id, label, at: Date.now()}]);
  closeSheet(); render(true);
  if (S.cloud_repo) cloudRun(true, '📨 ' + label + ' – die Cloud übernimmt das (ca. 1–3 min)');
  else toast('📨 ' + label + ' – wird beim nächsten PC-Update übernommen', 3500);
  return true }

// ------------------------------------------------------------------ Cloud-Lauf (GitHub Actions) anstoßen
let CLOUD = null;  // {since, timer}
async function cloudRun(quiet, msg) {
  const token = LS.get('token');
  if (!token) { openSettings('Zum Aktualisieren über die Cloud braucht die App einen GitHub-Token.'); return }
  const r = await fetch(`https://api.github.com/repos/${S.cloud_repo}/actions/workflows/radcoach.yml/dispatches`, {method: 'POST',
    headers: {Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json'},
    body: JSON.stringify({ref: 'main'})});
  if (!r.ok) { const j = await r.json().catch(() => ({}));
    toast(r.status === 403 || r.status === 404 ? '⚠️ Dem Handy-Token fehlt das Recht „Actions“ für ' + S.cloud_repo : 'GitHub: ' + (j.message || r.status), 6000); return }
  toast(msg || '☁️ Cloud holt neue Fahrten und rechnet – ca. 1–3 min', 4000);
  const since = S.generated; clearInterval(CLOUD && CLOUD.timer);
  CLOUD = {since, started: Date.now(), timer: setInterval(async () => {
    try { const env = await fetchEnv(), s = await unseal(env, KEYS);
      if (s.generated !== since) { ENV = env; S = s; LS.set('cache', env); clearInterval(CLOUD.timer); CLOUD = null; reconcile(); render(true); toast('✅ Aktualisiert – Stand: ' + ago(S.generated)); return } } catch {}
    if (Date.now() - CLOUD.started > 6 * 60e3) { clearInterval(CLOUD.timer); CLOUD = null; render(); toast('Die Cloud braucht länger – später nochmal ⟳') }
    else render(true) }, 15000)};
  render(true) }
const pendingFor = d => pending().filter(p => (p.to || p.date || p.slot || p.from || '').slice(0, 10) === d || (p.from || p.slot || '').slice(0, 10) === d);
function countOn(d) {
  const day = S.days[d]; let n = day && day.items ? day.items.length : 0;
  for (const p of pending()) { if ((p.type === 'move' || p.type === 'catchup') && p.to === d) n++; if ((p.type === 'move' || p.type === 'skip') && (p.from || p.slot || '').slice(0, 10) === d) n-- }
  return n }

// ------------------------------------------------------------------ Bausteine
function profile(w, H = 70, light) {
  const W = 360, T = w.duration_s || 1; let x = 0, out = '';
  for (const s of w.steps) { const wd = s.s / T * W, lo = s.ramp ? s.lo : (s.lo + s.hi) / 2, hi = s.ramp ? s.hi : lo;
    const y1 = H - Math.min(1.7, lo) / 1.7 * H, y2 = H - Math.min(1.7, hi) / 1.7 * H;
    out += `<path d="M${x},${H} L${x},${y1} L${x + wd - .4},${y2} L${x + wd - .4},${H} Z" fill="${light ? 'rgba(255,255,255,' + (.45 + Math.min(.55, lo * .4)) + ')' : zc((lo + hi) / 2)}"/>`; x += wd }
  if (H > 30) { const fy = H - 1 / 1.7 * H; out += `<line x1="0" x2="${W}" y1="${fy}" y2="${fy}" stroke="${light ? 'rgba(255,255,255,.7)' : 'var(--muted)'}" stroke-dasharray="3 4"/><text x="4" y="${fy - 4}" font-size="10" fill="${light ? '#fff' : 'var(--muted)'}">FTP ${S.ftp} W</text>` }
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" preserveAspectRatio="none">${out}</svg>` }
const watts = s => s.lo === s.hi ? `${Math.round(s.lo * S.ftp)} W` : `${Math.round(s.lo * S.ftp)}–${Math.round(s.hi * S.ftp)} W`;
function stepsTable(w) {  // gleiche Intervalle zusammenfassen: "3 × 8′ @ 220 W"
  const rows = []; const st = w.steps;
  for (let i = 0; i < st.length;) {
    let n = 1; const a = st[i], b = st[i + 1];
    if (b && !a.ramp) { while (st[i + 2 * n] && st[i + 2 * n + 1] && st[i + 2 * n].s === a.s && st[i + 2 * n].lo === a.lo && st[i + 2 * n + 1].s === b.s && st[i + 2 * n + 1].lo === b.lo) n++ }
    if (n > 1) { rows.push([zc((a.lo + a.hi) / 2), `${n} × ${fmt(a.s)} ${esc(a.label)} / ${fmt(b.s)} locker`, `${watts(a)} / ${watts(b)}`]); i += 2 * n }
    else { rows.push([zc((a.lo + a.hi) / 2), `${fmt(a.s)} ${esc(a.label)}${a.rpm ? ` · ${a.rpm} rpm` : ''}`, watts(a)]); i++ } }
  return `<table class="steps">${rows.map(r => `<tr><td><span class="sw" style="background:${r[0]}"></span>${r[1]}</td><td>${r[2]}</td></tr>`).join('')}</table>` }
function tags(w) {
  return (w.catchup ? `<span class="tag blue">↻ nachgeholt vom ${dlabel(w.catchup)}</span>` : w.added ? '<span class="tag blue">＋ manuell</span>' : w.moved ? '<span class="tag blue">↔ verschoben</span>' : '') }
const pendTag = d => pendingFor(d).length ? `<span class="tag warn">⏳ ${pendingFor(d).map(p => p.label).join(' · ')}</span>` : '';

// ------------------------------------------------------------------ Seiten
function render(keep) {
  const y = window.scrollY;
  $('#tabs').classList.remove('hidden');
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
  $('#app').innerHTML = ({today: pageToday, plan: pagePlan, history: pageHistory, form: pageForm})[tab]();
  window.scrollTo(0, keep ? y : 0) }

function header(title, sub) {
  return `<div class="top"><div><div class="sub">${sub}</div><h1>${title}</h1></div>
  <div style="display:flex;gap:8px"><button class="iconbtn" onclick="refresh(this)" title="Aktualisieren">⟳</button>
  <button class="iconbtn" onclick="openSettings()" title="Einstellungen">⚙️</button></div></div>` }

function pageToday() {
  const t = TODAY(), day = S.days[t] || {}, items = day.items || [], h = new Date().getHours();
  const hi = h < 11 ? 'Guten Morgen' : h < 18 ? 'Servus' : 'Guten Abend';
  const left = Math.round((D(S.goal.date) - D(t)) / 864e5);
  let html = header(`${hi}${S.name ? ' ' + esc(S.name.split(' ')[0]) : ''} 👋`, `Noch <b>${left} Tage</b> bis ${esc(S.goal.name)}`);
  if (CLOUD) html += `<div class="banner">☁️ <span class="spin">⟳</span> Die Cloud holt neue Fahrten und rechnet … seit ${Math.round((Date.now() - CLOUD.started) / 1000)} s (meist 1–3 min)</div>`;
  else if (S.cloud_repo && Date.now() - new Date(S.generated) > 3 * 3600e3) html += `<div class="banner">🕰️ Stand: ${ago(S.generated)} – tippe oben auf ⟳, dann holt die Cloud neue Fahrten von Wahoo.</div>`;
  else if (!S.cloud_repo && Date.now() - new Date(S.generated) > 36 * 3600e3) html += `<div class="banner">🕰️ Stand vom PC: ${ago(S.generated)}. Neue Fahrten und Planänderungen kommen erst, wenn am PC radcoach läuft (Web-App oder Update) – ⟳ am Handy lädt nur den zuletzt hochgeladenen Stand.</div>`;
  const rides = day.rides || [];
  if (day.event) html += `<div class="hero race"><div class="k">Heute</div><div class="t">${esc(day.event)} 🏁</div><div class="meta">Viel Erfolg – genieß es!</div></div>`;
  else if (items.length) {
    const w = items[0];
    html += `<div class="hero"><div class="k">Heute · ${dlabel(t)}${rides.length ? ' · ✅ gefahren' : ''}</div><div class="t">${esc(w.name)}</div>
      <div class="meta">${mins(w.duration_s)} min · TSS ${Math.round(w.tss)} · Ø ≈ ${Math.round(w.if * S.ftp)} W</div>${tags(w)}
      <div class="prof" onclick="openWorkout('${w.slot}')">${profile(w, 70, true)}</div>
      <div class="chips"><button class="chip" onclick="openWorkout('${w.slot}')">Intervalle</button>
      ${rides.length ? '' : `<button class="chip" onclick="moveTo('${w.slot}','${addDays(t, 1)}')">Auf morgen →</button>`}</div>
      ${items[1] ? `<div class="second" onclick="openWorkout('${items[1].slot}')">＋ 2. Einheit: <b>${esc(items[1].name)}</b> · ${mins(items[1].duration_s)} min</div>` : ''}
      ${pendTag(t) ? `<div style="margin-top:8px">${pendTag(t)}</div>` : ''}</div>`
  } else html += `<div class="hero rest"><div class="k">Heute · ${dlabel(t)}</div><div class="t">${rides.length ? 'Gut gemacht! 🙌' : 'Ruhetag 😌'}</div>
      <div class="meta">${rides.length ? rides.map(r => esc(r.name) + ' · ' + mins(r.dur) + ' min').join('<br>') : 'Erholung ist Training. Beine hoch.'}</div>${pendTag(t) ? `<div style="margin-top:8px">${pendTag(t)}</div>` : ''}</div>`;

  const c = S.current;
  html += `<div class="tiles"><div class="tile"><div class="v">${S.ftp}</div><div class="l">FTP W</div></div>
    <div class="tile"><div class="v">${Math.round(c.ctl)}</div><div class="l">Fitness</div></div>
    <div class="tile"><div class="v">${Math.round(c.atl)}</div><div class="l">Ermüdung</div></div>
    <div class="tile"><div class="v" style="color:${c.tsb > 5 ? 'var(--good)' : c.tsb < -20 ? 'var(--bad)' : c.tsb < -10 ? 'var(--warn)' : 'inherit'}">${c.tsb > 0 ? '+' : ''}${Math.round(c.tsb)}</div><div class="l">Form</div></div></div>`;

  const f = S.forecast;
  if (f) html += `<div class="card fc ${f.status}" onclick="tab='form';render()" style="cursor:pointer;display:flex;align-items:center;gap:12px">
    <span style="font-size:28px">${f.icon}</span><div class="grow"><div class="muted">Zielzeit-Prognose</div>
    <div class="nm" style="font-size:19px">${f.pred_txt} h <span class="muted">· Ziel ${f.target_txt} h · ${esc(f.label)}</span></div></div><div class="right">›</div></div>`;

  // Gefühl nachtragen / verpasste Einheiten nachholen
  const todo = [];
  for (let k = 3; k >= 0; k--) { const d = addDays(t, -k), x = S.days[d]; if (!x) continue;
    const myRpe = pending().find(p => p.type === 'rpe' && p.date === d);
    if (x.rides.length && !x.rpe && !myRpe) todo.push(`<div class="row" onclick="openRpe('${d}')"><div class="dbadge"><b>${D(d).getDate()}</b><span>${DN[D(d).getDay()]}</span></div>
      <div class="grow"><div class="nm">Wie hat sich ${d === t ? 'die Fahrt heute' : esc(x.rides[0].name)} angefühlt?</div><div class="muted">Gefühl 1–10 eintragen – hilft beim Anpassen</div></div><div class="right">›</div></div>`);
    if (x.catch === 'open' && !pending().some(p => p.type === 'catchup' && p.from === d)) todo.push(`<div class="row" onclick="openCatch('${d}')"><div class="dbadge"><b>${D(d).getDate()}</b><span>${DN[D(d).getDay()]}</span></div>
      <div class="grow"><div class="nm">${esc(x.planned.name)} verpasst</div><div class="muted">Nachholen? Kommt zum gewählten Tag dazu.</div></div><div class="right">↻</div></div>`) }
  if (todo.length) html += `<h2>Zu erledigen</h2><div class="card">${todo.join('')}</div>`;

  html += `<h2>Die nächsten Tage</h2><div class="card">`;
  for (let k = 1; k <= 6; k++) html += dayRow(addDays(t, k));
  html += `</div><div class="muted" style="text-align:center;margin-top:14px">Stand vom PC: ${ago(S.generated)}</div>`;
  return html }

function dayRow(d) {
  const x = S.days[d]; if (!x) return '';
  const items = x.items || [], dd = D(d), cls = d === TODAY() ? ' today' : '';
  const body = x.event ? `<div class="nm">🏁 ${esc(x.event)}</div>` : items.length ? items.map(w => `<div class="nm">${esc(w.name)}</div>
      <div class="mini">${profile(w, 18)}</div>${tags(w)}`).join('') : '<div class="nm" style="color:var(--muted);font-weight:500">Ruhetag</div>';
  const tss = items.reduce((a, w) => a + w.tss, 0);
  return `<div class="row" onclick="openDay('${d}')"><div class="dbadge${cls}"><b>${dd.getDate()}</b><span>${DN[dd.getDay()]}</span></div>
    <div class="grow">${body}${pendTag(d)}</div><div class="right">${items.length ? `${mins(items.reduce((a, w) => a + w.duration_s, 0))}′<br>${Math.round(tss)} TSS` : ''}</div></div>` }

function pagePlan() {
  const t = TODAY(); let html = header('Trainingsplan', `FTP ${S.ftp} W · ${esc(S.goal.name)}`);
  let d = addDays(t, -((D(t).getDay() + 6) % 7));  // Montag dieser Woche
  for (let wk = 0; wk < 4; wk++) {
    const w = S.weeks.find(x => x.start === d) || {};
    const days = [...Array(7)].map((_, i) => addDays(d, i)).filter(x => S.days[x] && x >= t);
    if (days.length) {
      html += `<div class="wkhead"><b>${wk === 0 ? 'Diese Woche' : wk === 1 ? 'Nächste Woche' : 'ab ' + dlabel(d)}</b>
        <span>${w.phase ? `<span class="phase ${w.phase}">${esc(w.phase_de || PH[w.phase] || w.phase)}</span> ` : ''}<span class="muted">${w.planned_tss ?? ''} TSS</span></span></div>
        <div class="card" style="padding:4px 16px">${days.map(dayRow).join('')}</div>` }
    d = addDays(d, 7) }
  return html + `<div class="muted" style="text-align:center;margin-top:10px">Tippe auf einen Tag zum Verschieben, Auslassen oder für die Intervalle.</div>` }

function pageHistory() {
  const t = TODAY(); let html = header('Verlauf', 'Die letzten 14 Tage');
  html += '<div class="card" style="padding:4px 16px">';
  for (let k = 0; k <= 14; k++) {
    const d = addDays(t, -k), x = S.days[d]; if (!x) continue;
    if (d === t && !x.rides.length) continue;
    const dd = D(d), ev = x.eval, st = ev && STATUS[ev.status];
    const myRpe = (pending().find(p => p.type === 'rpe' && p.date === d) || {}).rpe;
    const rpe = myRpe || x.rpe;
    let body = x.rides.map(r => `<div class="nm">${esc(r.name)}</div><div class="muted">${mins(r.dur)} min · ${r.tss} TSS${r.np ? ' · NP ' + r.np + ' W' : ''}${r.km ? ' · ' + r.km + ' km' : ''}</div>`).join('');
    if (x.planned) body += `<div class="muted">Plan: ${esc(x.planned.name)} ${st ? st[0] + ' ' + esc(ev.text || st[1]) : ''}</div>`;
    if (!body) body = '<div class="nm" style="color:var(--muted);font-weight:500">Ruhetag</div>';
    if (x.catch && x.catch !== 'open') body += `<span class="tag blue">↻ nachgeholt am ${dlabel(x.catch)}</span>`;
    const act = x.rides.length ? `<button class="chip ${rpe ? 'on' : 'ghost'}" onclick="event.stopPropagation();openRpe('${d}')">${rpe ? (myRpe ? '⏳ ' : '') + rpe + '/10' : 'Gefühl?'}</button>`
      : x.catch === 'open' && !pending().some(p => p.type === 'catchup' && p.from === d) ? `<button class="chip ghost" onclick="event.stopPropagation();openCatch('${d}')">↻ nachholen</button>` : '';
    html += `<div class="row" onclick="${x.rides.length ? `openRpe('${d}')` : x.planned ? `openPast('${d}')` : ''}"><div class="dbadge${d === t ? ' today' : ''}"><b>${dd.getDate()}</b><span>${DN[dd.getDay()]}</span></div>
      <div class="grow">${body}${pendTag(d)}</div><div class="right">${act}</div></div>` }
  return html + '</div>' }

function chart() {
  const W = 360, H = 170, L = 26, B = 18, pts = S.pmc.slice(-60), proj = S.projection || [];
  const all = [...pts.map(p => ({d: p.d, ctl: p.ctl, atl: p.atl, tsb: p.tsb})), ...proj.map(p => ({d: p.d, ctl: p.ctl, tsb: p.tsb, plan: 1}))];
  if (!all.length) return '';
  const t0 = D(all[0].d), t1 = D(all[all.length - 1].d), span = Math.max(1, t1 - t0);
  const target = S.event.target_ctl || 0;
  const vmax = Math.max(target, ...all.map(p => Math.max(p.ctl, p.atl || 0))) * 1.12, vmin = Math.min(0, ...all.map(p => p.tsb)) * 1.1;
  const X = d => L + (D(d) - t0) / span * (W - L - 4), Y = v => (H - B) - (v - vmin) / (vmax - vmin) * (H - B - 6);
  const line = (arr, k) => arr.map((p, i) => `${i ? 'L' : 'M'}${X(p.d).toFixed(1)},${Y(p[k]).toFixed(1)}`).join('');
  let o = `<line x1="${L}" x2="${W}" y1="${Y(0)}" y2="${Y(0)}" stroke="var(--line)"/>`;
  for (const v of [20, 40, 60, 80].filter(v => v < vmax)) o += `<line x1="${L}" x2="${W}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--line)" stroke-dasharray="2 4"/><text x="2" y="${Y(v) + 3}">${v}</text>`;
  if (target) o += `<line x1="${L}" x2="${W}" y1="${Y(target)}" y2="${Y(target)}" stroke="var(--hot)" stroke-dasharray="5 4"/><text x="${W - 70}" y="${Y(target) - 4}" style="fill:var(--hot)">Ziel ${target}</text>`;
  o += pts.map(p => `<rect x="${X(p.d) - 1}" y="${Math.min(Y(0), Y(p.tsb))}" width="2.2" height="${Math.abs(Y(p.tsb) - Y(0))}" fill="${p.tsb >= 0 ? 'var(--accent2)' : 'var(--hot)'}" opacity=".45"/>`).join('');
  o += `<path d="${line(pts, 'atl')}" fill="none" stroke="var(--hot)" stroke-width="1.6" opacity=".8"/>`;
  o += `<path d="${line(pts, 'ctl')}" fill="none" stroke="var(--accent)" stroke-width="2.6"/>`;
  if (proj.length) o += `<path d="${line([pts[pts.length - 1], ...proj], 'ctl')}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-dasharray="4 4" opacity=".7"/>`;
  const tx = X(TODAY()); o += `<line x1="${tx}" x2="${tx}" y1="0" y2="${H - B}" stroke="var(--muted)" stroke-dasharray="2 3"/><text x="${tx + 3}" y="10">heute</text>`;
  o += `<text x="${L}" y="${H - 4}">${dlabel(all[0].d)}</text><text x="${W - 60}" y="${H - 4}">${dlabel(all[all.length - 1].d)}</text>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" width="100%">${o}</svg>
    <div class="muted"><span style="color:var(--accent)">━</span> Fitness (gestrichelt: Prognose bis zum Rennen) · <span style="color:var(--hot)">━</span> Ermüdung · Balken: Form</div>` }

function pageForm() {
  const e = S.event || {}; const NAMES = {sweetspot: 'Sweet Spot', threshold: 'Schwelle', over_under: 'Over-Unders', vo2max: 'VO2max',
    microbursts: 'Microbursts', anaerobic: 'Anaerob', tempo: 'Tempo', endurance_tempo: 'Grundlage+Tempo', durability: 'Lang+Finale',
    race_sim: 'Rennsimulation', climbing: 'Kraftausdauer'};
  let html = header('Form & Ziel', esc(S.goal.name) + ' · ' + dlabel(S.goal.date) + D(S.goal.date).getFullYear());
  const f = S.forecast;
  if (f) {
    const lo = Math.min(f.fast, f.target) - .05, hi = Math.max(f.slow, f.target, f.full) + .05, X = h => ((h - lo) / (hi - lo) * 100).toFixed(1);
    html += `<div class="card fc ${f.status}"><div style="display:flex;align-items:baseline;gap:10px"><span style="font-size:30px">${f.icon}</span>
      <span style="font-size:28px;font-weight:750">${f.pred_txt} h</span><span class="muted">${esc(f.range_txt)} h</span></div>
      <div class="sub">Zielzeit-Prognose · Ziel ${f.target_txt} h · <b>${esc(f.label)}</b></div>
      <div class="fcbar"><i class="rng" style="left:${X(f.fast)}%;width:${X(f.slow) - X(f.fast)}%"></i><i class="tgt" style="left:${X(f.target)}%"></i><i class="dot" style="left:${X(f.pred)}%"></i></div>
      <div class="muted" style="display:flex;justify-content:space-between"><span>schneller</span><span>▮ Ziel · ● Prognose</span><span>langsamer</span></div>
      <div class="tiles" style="grid-template-columns:repeat(3,1fr);margin:12px 0 4px">
      <div class="tile" style="box-shadow:none;background:var(--card2)"><div class="v">${f.ftp_race}</div><div class="l">FTP Renntag</div></div>
      <div class="tile" style="box-shadow:none;background:var(--card2)"><div class="v">${Math.round(f.ctl_peak_real)}</div><div class="l">Fitness-Spitze</div></div>
      <div class="tile" style="box-shadow:none;background:var(--card2)"><div class="v">${f.compliance == null ? '–' : Math.round(f.compliance * 100) + '%'}</div><div class="l">Umsetzung</div></div></div>
      <ul class="tips">${f.advice.map(a => `<li>${esc(a)}</li>`).join('')}</ul></div>` }
  html += `<div class="card">${chart()}</div>`;
  const gap = e.ftp_need ? e.ftp_need - S.ftp : null;
  html += `<div class="tiles" style="grid-template-columns:repeat(3,1fr)"><div class="tile"><div class="v">${S.ftp}</div><div class="l">FTP jetzt</div></div>
    <div class="tile"><div class="v">${e.ftp_need || '–'}</div><div class="l">FTP nötig</div></div>
    <div class="tile"><div class="v" style="color:${gap > 0 ? 'var(--hot)' : 'var(--good)'}">${gap == null ? '–' : (gap > 0 ? '+' : '') + gap}</div><div class="l">Lücke W</div></div></div>`;
  html += `<div class="card"><b>🎯 ${esc(S.goal.name)}</b><div class="sub">${S.goal.distance_km || '?'} km · ${S.goal.elevation_m || '?'} hm · Ziel ${esc((S.goal.target_time || '').slice(0, 5).replace(':', ':'))} h${e.speed ? ' · Ø ' + e.speed + ' km/h' : ''}</div>
    <ul class="tips">${(e.recommendations || []).map(r => `<li>${esc(r)}</li>`).join('')}</ul></div>`;
  const lv = Object.entries(S.levels || {}).filter(([k]) => NAMES[k]).sort((a, b) => b[1] - a[1]);
  if (lv.length) html += `<h2>Trainingsstufen</h2><div class="card">${lv.map(([k, v]) => `<div class="lv"><span>${NAMES[k]}</span><div class="bar"><i style="width:${v * 10}%"></i></div><b>${v}</b></div>`).join('')}
    <div class="muted" style="margin-top:6px">Stufe 1–10: steigt, wenn du die Intervalle schaffst, und bestimmt die nächste Einheit dieses Typs.</div></div>`;
  if ((S.notes || []).length) html += `<h2>Coach-Notizen</h2><div class="card"><ul class="tips">${S.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul></div>`;
  html += `<div class="muted" style="text-align:center">FTP-Quelle: ${esc(S.ftp_source || '')}</div>`;
  return html }

// ------------------------------------------------------------------ Bottom-Sheets & Aktionen
function openSheet(html) { $('#sheetbody').innerHTML = html; $('#sheet').classList.add('open'); $('#sheetbg').classList.add('open') }
function closeSheet() { $('#sheet').classList.remove('open'); $('#sheetbg').classList.remove('open') }
$('#sheetbg').onclick = closeSheet;
function findSlot(slot) { const d = slot.slice(0, 10); return ((S.days[d] || {}).items || []).find(w => w.slot === slot) }

function targets(fn, from) {  // Tagesauswahl: heute + 6 Tage, volle Tage gesperrt
  const t = TODAY(); let h = '<div class="chips" style="margin-top:8px">';
  for (let k = 0; k < 7; k++) { const d = addDays(t, k); if (d === from || !S.days[d] || !S.days[d].avail) continue;
    const n = countOn(d); h += `<button class="chip ${n ? 'ghost' : ''}" ${n >= S.max_per_day ? 'disabled' : ''} onclick="${fn}('${d}')">${dnice(d)}${n ? ' ＋' : ''}</button>` }
  return h + `</div><div class="muted" style="margin-top:8px">＋ = dort ist schon eine Einheit (max. ${S.max_per_day} pro Tag).</div>` }

function openDay(d) { const items = (S.days[d] || {}).items || [];
  if (items.length === 1) return openWorkout(items[0].slot);
  if (!items.length) return openSheet(`<div class="sub">${dnice(d)}</div><h2 style="margin-top:2px">Ruhetag 😌</h2><div class="sub">Flex-Workouts kannst du direkt am BOLT starten (Pläne → Flex …).</div>`);
  openSheet(`<div class="sub">${dnice(d)}</div><h2 style="margin-top:2px">2 Einheiten</h2>` + items.map(w => `<div class="row" onclick="openWorkout('${w.slot}')"><div class="grow"><div class="nm">${esc(w.name)}</div><div class="mini">${profile(w, 18)}</div></div><div class="right">›</div></div>`).join('')) }

function openWorkout(slot) {
  const w = findSlot(slot); if (!w) return; const d = slot.slice(0, 10), t = TODAY(), rode = (S.days[d] || {}).rides?.length;
  const canEdit = d >= t && !(d === t && rode) && !pending().some(p => (p.from || p.slot) === slot);
  openSheet(`<div class="sub">${dnice(d)} ${d !== t ? '' : '· ' + dlabel(d)}</div><h2 style="margin:2px 0 4px">${esc(w.name)}</h2>
    <div class="sub">${mins(w.duration_s)} min · TSS ${Math.round(w.tss)} · IF ${w.if.toFixed(2)} · Ø ≈ ${Math.round(w.if * S.ftp)} W</div>${tags(w)}
    <div style="margin:12px 0 4px">${profile(w, 80)}</div>${stepsTable(w)}
    ${canEdit ? `<h2>Verschieben</h2>${targets(`(x=>moveTo('${slot}',x))`, d)}
    <div class="chips" style="margin-top:14px"><button class="chip ghost" onclick="skip('${slot}')">${w.added ? '🗑️ Entfernen' : '⏭️ Auslassen'}</button></div>` :
    pending().some(p => (p.from || p.slot) === slot) ? '<div class="banner">⏳ Für diese Einheit wartet schon eine Änderung auf den PC.</div>' : ''}`) }

function moveTo(slot, to) { const w = findSlot(slot); if (!w) return;
  if (countOn(to) >= S.max_per_day) return toast(`Am ${dlabel(to)} sind schon ${S.max_per_day} Einheiten.`);
  send({type: 'move', from: slot, to}, `${w.name} → ${dnice(to)}`) }
function skip(slot) { const w = findSlot(slot); if (!w || !confirm(`${w.name} am ${dlabel(slot)} ${w.added ? 'entfernen' : 'auslassen'}?`)) return;
  send({type: 'skip', slot}, `${w.name} ${w.added ? 'entfernen' : 'auslassen'}`) }

function openCatch(d) { const x = S.days[d];
  openSheet(`<div class="sub">verpasst am ${dlabel(d)}</div><h2 style="margin:2px 0 4px">${esc(x.planned.name)} nachholen</h2>
    <div class="sub">Die Einheit kommt am gewählten Tag dazu und wird an den BOLT gesendet.</div>
    <div style="margin:12px 0 4px">${profile(x.planned, 60)}</div>${targets(`(t=>send({type:'catchup',from:'${d}',to:t},'${esc(x.planned.name).replace(/'/g, '')} nachholen → '+dnice(t)))`, null)}`) }
function openPast(d) { const x = S.days[d]; if (x.catch === 'open') return openCatch(d);
  openSheet(`<div class="sub">${dlabel(d)}</div><h2 style="margin:2px 0">${esc(x.planned.name)}</h2><div class="sub">${x.eval ? STATUS[x.eval.status]?.join(' ') : ''}</div><div style="margin-top:12px">${profile(x.planned, 60)}</div>`) }

function openRpe(d) { const x = S.days[d]; const cur = (pending().find(p => p.type === 'rpe' && p.date === d) || {}).rpe || x.rpe;
  const r = x.rides[0] || {}; const ev = x.eval && STATUS[x.eval.status];
  openSheet(`<div class="sub">${dnice(d)}</div><h2 style="margin:2px 0 4px">Wie hat es sich angefühlt?</h2>
    <div class="sub">${esc(r.name || '')}${r.dur ? ' · ' + mins(r.dur) + ' min · ' + r.tss + ' TSS' : ''}${x.planned ? `<br>Plan: ${esc(x.planned.name)} ${ev ? ev[0] + ' ' + esc(x.eval.text || ev[1]) : ''}` : ''}</div>
    <div class="rpe">${[...Array(10)].map((_, i) => `<button class="${cur === i + 1 ? 'on' : ''}" onclick="send({type:'rpe',date:'${d}',rpe:${i + 1}},'Gefühl ${i + 1}/10 (${dlabel(d)})')">${i + 1}</button>`).join('')}</div>
    <div class="muted" style="display:flex;justify-content:space-between;margin-top:6px"><span>1 sehr locker</span><span>5 mittel</span><span>10 maximal</span></div>
    ${cur ? `<div class="sub" style="margin-top:10px">Aktuell: <b>${cur}/10 – ${RPE[cur]}</b></div>` : ''}`) }

function openSettings(msg) {
  const rp = repo(), tok = LS.get('token');
  openSheet(`<h2 style="margin-top:4px">Einstellungen</h2>${msg ? `<div class="banner">${esc(msg)}</div>` : ''}
    <div class="sub" style="margin-bottom:6px"><b>Änderungen vom Handy</b> (Gefühl, Verschieben, Nachholen) landen verschlüsselt in deinem Repo <b>${esc(rp || '?')}</b>, der PC holt sie beim nächsten Update ab.
    Dafür braucht die App einen GitHub-Token (Fine-grained, nur dieses Repo, „Contents: Read and write“)${S.cloud_repo ? `, für ⟳ zusätzlich <b>${esc(S.cloud_repo)}</b> mit „Actions: Read and write“` : ""}.</div>
    ${tok ? `<div class="banner" style="background:color-mix(in srgb,var(--good) 14%,var(--card))">✅ <b>Token ist gespeichert</b> (…${esc(tok.slice(-4))}) – Änderungen vom Handy sind aktiv. Nichts weiter zu tun.</div>
    <div class="chips"><button class="chip ghost" onclick="$('#tokbox').classList.toggle('hidden')">Token ersetzen</button>
    <button class="chip ghost" onclick="LS.del('token');closeSheet();toast('Token entfernt')">Token entfernen</button></div>` : ''}
    <div id="tokbox" class="${tok ? 'hidden' : ''}" style="margin-top:10px"><input class="field" id="tok" type="password" placeholder="github_pat_…" autocomplete="off">
    <div class="chips" style="margin-top:10px"><button class="chip primary" onclick="saveToken()">Token speichern</button></div></div>
    ${pending().length ? `<h2>Wartet auf den PC</h2><div class="card" style="margin:0">${pending().map(p => `<div class="muted">⏳ ${esc(p.label)}</div>`).join('')}</div>` : ''}
    <h2>App</h2><div class="sub">Stand vom PC: ${ago(S.generated)} · FTP ${S.ftp} W</div>
    <div class="chips" style="margin-top:10px"><button class="chip ghost" onclick="logout()">🔒 Abmelden</button></div>`) }
function saveToken() { const v = $('#tok').value.trim(); if (!v) return toast('Bitte Token einfügen');
  if (!/^(github_pat_|ghp_)/.test(v)) return toast('Das sieht nicht nach einem GitHub-Token aus');
  LS.set('token', v); closeSheet(); toast('Token gespeichert ✓') }
function logout() { if (!confirm('Abmelden? Passwort und Token werden von diesem Handy gelöscht.')) return;
  ['keys', 'salt', 'token', 'cache', 'pending'].forEach(LS.del); location.reload() }
async function refresh(btn) { btn.innerHTML = '<span class="spin">⟳</span>';
  if (S && S.cloud_repo && LS.get('token') && !CLOUD) return cloudRun();
  await load(false) }

document.querySelectorAll('#tabs button').forEach(b => b.onclick = () => { tab = b.dataset.tab; render() });
document.addEventListener('visibilitychange', () => { if (!document.hidden && KEYS) load(true) });
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
load(true);

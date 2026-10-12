const $ = s => document.querySelector(s);
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };
let mode = 'individual';
const TEXT = {
  individual: ['Check a link before you click it.', 'Paste any web address. We look for the tricks scammers use and explain each warning in plain words.'],
  company: ['Track link risk across your team.', 'Scan suspicious links reported by staff or customers, scan batches, and watch risk trends on your dashboard.']
};
async function api(path, opts) {
  let r, d;
  try { r = await fetch(path, opts); d = await r.json(); } catch (e) { throw new Error('Cannot reach the server. Check that it is running.'); }
  if (!r.ok) throw new Error(d.error || 'Something went wrong.');
  return d;
}
function msg(t, cls) { const m = $('#msg'); m.textContent = t || ''; m.className = cls || ''; }
const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

function show(r) {
  const box = $('#result'); box.hidden = false; box.replaceChildren();
  const lv = r.level.toLowerCase(), g = el('div', 'gauge ' + lv);
  g.style.setProperty('--p', r.score * 3.6 + 'deg'); g.append(el('span', null, r.score));
  const t = el('div'); t.append(el('span', 'pill ' + lv, r.level + ' risk'), el('h2', null, r.host), el('p', 'muted', r.advice));
  const top = el('div', 'top'); top.append(g, t);
  const ul = el('ul', 'finds');
  if (!r.findings.length) ul.append(el('li', null, 'None of our URL checks raised a warning. This does not prove the site is safe.'));
  r.findings.forEach(f => { const li = el('li'); li.append(el('b', null, `${f.label} (+${f.points})`), el('span', null, f.detail)); ul.append(li); });
  const i = el('div', 'intel'); i.append(el('b', null, `${r.intel.source}: ${r.intel.status.replace('_', ' ')}`), el('span', null, r.intel.detail));
  box.append(top, el('h3', null, 'Why this score'), ul, i, el('p', 'muted small', r.disclaimer));
  box.scrollIntoView({ behavior: 'smooth' });
}

async function loadHistory() {
  const { scans } = await api('/api/history?mode=' + mode);
  const tb = $('#rows'); tb.replaceChildren();
  if (!scans.length) { const tr = el('tr'), td = el('td', null, 'No scans yet. Paste a link above and press Scan link.'); td.colSpan = 4; tr.append(td); tb.append(tr); }
  scans.forEach(s => {
    const tr = el('tr'); tr.tabIndex = 0;
    const open = async () => { try { show(await api('/api/scan/' + s.id)); } catch (e) { msg(e.message, 'bad'); } };
    tr.onclick = open; tr.onkeydown = e => { if (e.key === 'Enter') open(); };
    const c = el('td'); c.append(el('span', 'pill ' + s.level.toLowerCase(), s.level));
    tr.append(el('td', null, s.url), el('td', null, s.score), c, el('td', null, s.created_at.replace('T', ' ')));
    tb.append(tr);
  });
}

async function loadDash() {
  if (mode !== 'company') return;
  const s = await api('/api/stats?mode=company');
  const cards = $('#cards'); cards.replaceChildren();
  [['Scans', s.total], ['Average score', s.average_score], ['High', s.levels.High], ['Medium', s.levels.Medium], ['Low', s.levels.Low]]
    .forEach(([k, v]) => { const c = el('div', 'card'); c.append(el('b', null, v), el('span', 'muted', k)); cards.append(c); });
  const max = Math.max(1, ...s.daily.map(d => d.c)), dl = $('#daily'); dl.replaceChildren();
  if (!s.daily.length) dl.append(el('span', 'muted', 'No scans yet.'));
  s.daily.forEach(d => { const b = el('div'); b.style.height = (d.c / max * 100) + '%'; b.title = d.d; b.append(el('small', null, d.c)); dl.append(b); });
  const top = $('#top'); top.replaceChildren();
  if (!s.top_indicators.length) top.append(el('li', 'muted', 'No warning signs recorded yet.'));
  s.top_indicators.forEach(([k, v]) => top.append(el('li', null, `${k}: ${v} scans`)));
  const hi = $('#high'); hi.replaceChildren();
  if (!s.recent_high_risk.length) hi.append(el('li', 'muted', 'No high-risk links found yet.'));
  s.recent_high_risk.forEach(r => hi.append(el('li', null, `${r.url} (score ${r.score})`)));
}

const refresh = () => Promise.all([loadHistory(), loadDash()]).catch(e => msg(e.message, 'bad'));

function setMode(m) {
  mode = m;
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.mode === m));
  $('#title').textContent = TEXT[m][0]; $('#sub').textContent = TEXT[m][1];
  $('#bulkbox').hidden = $('#dash').hidden = m !== 'company';
  $('#result').hidden = true; msg(''); refresh();
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => setMode(b.dataset.mode));

$('#f').onsubmit = async e => {
  e.preventDefault(); msg('Scanning...'); $('#go').disabled = true;
  try { show(await api('/api/scan', post({ url: $('#u').value, mode }))); msg(''); refresh(); }
  catch (err) { msg(err.message, 'bad'); }
  $('#go').disabled = false;
};
$('#bgo').onclick = async () => {
  const urls = $('#bulk').value.split('\n').map(x => x.trim()).filter(Boolean);
  if (!urls.length) return msg('Add at least one link, one per line.', 'bad');
  msg('Scanning...');
  try {
    const { results } = await api('/api/scan/bulk', post({ urls }));
    const bad = results.filter(r => r.error).length;
    msg(`Scanned ${results.length - bad} links${bad ? `, ${bad} invalid and skipped` : ''}.`, 'ok'); refresh();
  } catch (err) { msg(err.message, 'bad'); }
};
setMode('individual');

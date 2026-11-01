const paths = {
  shield: '<path d="M12 3 20 6v6c0 5-3.4 8-8 10-4.6-2-8-5-8-10V6Z"/><path d="M12 8v5m0 3h.01"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
  arrow: '<path d="M4 12h15m-6-6 6 6-6 6"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  down: '<path d="m6 9 6 6 6-6"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  upload: '<path d="M12 16V4m-5 5 5-5 5 5M4 15v5h16v-5"/>',
  download: '<path d="M12 4v12m-5-5 5 5 5-5M4 18v3h16v-3"/>',
  play: '<path d="m8 4 12 8-12 8Z"/>',
  moon: '<path d="M20.5 13a8.5 8.5 0 1 1-9.5-9.5A7 7 0 0 0 20.5 13Z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M3 20v-2a6 6 0 0 1 12 0v2m2-14a3 3 0 0 1 0 6m1 3a5 5 0 0 1 3 5"/>',
  network: '<rect x="8" y="2" width="8" height="6" rx="1"/><rect x="2" y="16" width="7" height="6" rx="1"/><rect x="15" y="16" width="7" height="6" rx="1"/><path d="M12 8v4H5v4m7-4h7v4"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01m5-11h5m-5 11h5"/>',
  activity: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  layers: '<path d="m12 3 10 6-10 6L2 9Zm-10 12 10 6 10-6M2 15l10 6 10-6"/>',
  check: '<path d="m5 12 4 4 10-10"/>',
  alert: '<path d="m12 3 10 18H2Zm0 6v5m0 3h.01"/>',
  spark: '<path d="m12 3 2.7 6.3L21 12l-6.3 2.7L12 21l-2.7-6.3L3 12l6.3-2.7ZM20 2v4m-2-2h4"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  terminal: '<rect x="2" y="3" width="20" height="18" rx="3"/><path d="m6 8 4 4-4 4m7 0h5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  external: '<path d="M14 3h7v7m0-7L10 14M10 3H3v18h18v-7"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  settings: '<path d="m9 3-1 3-3 1-2 5 2 5 3 1 1 3h6l1-3 3-1 2-5-2-5-3-1-1-3Z"/><circle cx="12" cy="12" r="3"/>',
  folder: '<path d="M3 5h7l2 3h9v13H3Z"/>',
  chart: '<path d="M3 3v18h18M7 16v-5m5 5V7m5 9v-8"/>',
  building: '<path d="M4 21V7l8-4v18M12 10h8v11M2 21h20M8 8v1m0 3v1m0 3v1m8-3v1m0 3v1"/>',
  file: '<path d="M14 2H4v20h16V8Zm0 0v6h6M8 12h8m-8 4h6"/>',
  refresh: '<path d="M20 7a9 9 0 0 0-15-2L2 8m0-5v5h5m-3 9a9 9 0 0 0 15 2l3-3m0 5v-5h-5"/>',
  branch: '<circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 6v12m12-10c0 6-12 3-12 9"/>',
};
const icon = (name, size = 16) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const num = value => Number(value || 0).toLocaleString();
const pct = value => value == null ? '—' : `${(value * 100).toFixed(value === 1 || value === 0 ? 0 : 1)}%`;
const title = value => String(value || '').replaceAll('_', ' ').replaceAll('-', ' ');
const short = (value, max = 26) => String(value).length > max ? String(value).slice(0, max - 1) + '…' : String(value);
const date = value => new Date(value).toLocaleDateString('en', {month:'short',day:'numeric'});
const utc = value => new Date(value).toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',timeZone:'UTC'});
function ago(value) {
  const seconds = Math.max(0, (Date.now() - new Date(value)) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds >= 365*86400) return `${Math.floor(seconds / (365*86400))}y ago`;
  if (seconds >= 30*86400) return `${Math.floor(seconds / (30*86400))}mo ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
const badge = (severity, label = severity) => `<span class="badge ${esc(severity)}"><span class="dot"></span>${esc(title(label))}</span>`;
const pages = [
  {path:'/',label:'Overview',icon:'layers'},
  {path:'/investigations',label:'Investigations',icon:'shield'},
  {path:'/identity',label:'Identity',icon:'network'},
  {path:'/datasets',label:'Datasets',icon:'database'},
  {path:'/research',label:'Research',icon:'chart'},
];

let data;
let activeIncident;
let selectedFinding;
let route = location.pathname;
let researchDomain = 'authentication';
let researchDataset = 'northstar-lab';
let caseFilter = {q:'',status:'all',severity:'',rule:''};
let caseLimit = 30;
let accessToken = '';
let analystName = 'analyst';
let online = true;
let shellReady = false;
let paletteIndex = 0;
try { accessToken = sessionStorage.getItem('identityshield-access') || ''; analystName = localStorage.getItem('identityshield-analyst') || 'analyst'; } catch {}

async function api(path, options = {}) {
  const headers = {'Accept':'application/json', ...(options.headers || {})};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let body = options.body;
  if (body && !(body instanceof FormData)) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
  const response = await fetch(path, {...options, headers, body});
  const result = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(result.error || `Request failed (${response.status})`); error.status = response.status; throw error; }
  return result;
}

let loadGeneration = 0;
async function load(quiet = false) {
  const generation = ++loadGeneration;
  try {
    const next = await api('/api/state');
    if (generation !== loadGeneration) return;
    data = next; online = true;
    if (!shellReady) { renderShell(); shellReady = true; }
    const editing = ['INPUT','SELECT','TEXTAREA'].includes(document.activeElement?.tagName);
    if (!quiet || (!document.querySelector('dialog[open]') && !editing)) renderPage();
    updateConnection();
  } catch (error) {
    online = false;
    if (error.status === 401) { authenticate(); return; }
    if (!quiet) document.querySelector('#app').innerHTML = `<div class="boot"><div class="boot-mark">i</div><h2>Let’s reconnect.</h2><p>${esc(error.message)}</p><button class="btn" data-action="reload">${icon('refresh')}Try again</button></div>`;
    updateConnection();
  }
}

function updateConnection() {
  const element = document.querySelector('#connection');
  if (element) element.innerHTML = `<span class="dot ${online ? 'live-dot' : 'danger'}"></span><span>${online ? 'Workspace connected' : 'Workspace offline'}</span>`;
}

function renderShell() {
  document.querySelector('#app').innerHTML = `
    <header class="topbar"><div class="topbar-inner">
      <a href="/" class="brand" data-route="/" aria-label="IdentityShield overview"><span class="brand-mark">${icon('shield',20)}</span>IdentityShield</a>
      <nav class="topnav" aria-label="Workspace navigation">${pages.map(page => `<a class="nav-link" href="${page.path}" data-route="${page.path}">${page.label}</a>`).join('')}</nav>
      <div class="top-tools">
        <button class="search-trigger" data-action="search" aria-label="Search workspace"><span>${icon('search',14)}</span><span>Search</span><kbd>⌘ K</kbd></button>
        <button class="icon-button" id="theme-button" data-action="theme" aria-label="Toggle color theme">${icon(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon',17)}</button>
        <button class="avatar" data-action="settings" aria-label="Workspace settings">YA</button>
      </div>
    </div></header>
    <div class="workspace">
      <div class="workspace-line"><div class="breadcrumb">${icon('building',13)}<span id="organization">${esc(data.organization)}</span><span class="slash">/</span><span class="workspace-label">Security workspace</span></div><div class="connection" id="connection"></div></div>
      <main id="main" tabindex="-1"></main>
      <footer class="footer"><span>Built in Go. Grounded in evidence.</span><div class="footer-links"><a href="/rules" data-route="/rules">Detection library ${iconInline('external')}</a><a href="https://github.com/YeandAmen/identityshield" target="_blank" rel="noreferrer">Source ${iconInline('external')}</a><span class="mono">v0.1.0</span></div></footer>
    </div>`;
  updateConnection();
}

function iconInline(name) { return `<span style="display:inline-flex;vertical-align:middle;margin-left:3px">${icon(name,10)}</span>`; }
function heading(eyebrow, main, subtitle, actions = '') {
  return `<header class="page-heading"><div><div class="eyebrow"><span class="dot"></span>${esc(eyebrow)}</div><h1>${main}</h1><p class="page-subtitle">${subtitle}</p></div>${actions ? `<div class="actions">${actions}</div>` : ''}</header>`;
}
function sectionHeader(number, name, extra = '') { return `<div class="section-header"><div class="section-title"><span class="section-number">${number}</span><h2>${name}</h2></div>${extra}</div>`; }
function empty(name, message, action = '') { return `<div class="empty"><div class="empty-icon">${icon('folder',19)}</div><h3>${name}</h3><p>${message}</p>${action}</div>`; }

function renderPage() {
  document.querySelectorAll('.nav-link').forEach(link => { link.classList.toggle('active', link.dataset.route === route); if (link.dataset.route === route) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current'); });
  document.querySelector('#organization').textContent = data.organization;
  const views = {'/':overview,'/investigations':investigations,'/identity':identityPage,'/datasets':datasetsPage,'/research':researchPage,'/rules':rulesPage};
  document.querySelector('#main').innerHTML = `<div class="view">${(views[route] || overview)()}</div>`;
  bindPage();
  document.title = `IdentityShield — ${pages.find(p => p.path === route)?.label || 'Detection library'}`;
}

function navigate(path) {
  if (!data) return;
  closeModal(); route = path;
  history.pushState({}, '', path);
  renderPage(); window.scrollTo({top:0,behavior:'instant'});
}
window.addEventListener('popstate', () => { route = location.pathname; closeModal(); if (data) renderPage(); });

function overview() {
  const counts = data.counts;
  const open = data.incidents.filter(item => item.status === 'open');
  const finding = chosenFinding();
  const model = data.models.authentication;
  const highFindings = data.findings.filter(item => item.severity === 'high').length;
  return `${heading('A little context goes a long way', 'Security, in context.', 'The right access. The right signals. One clearer picture.', `<button class="btn" data-action="replay">${icon('play',13)}Replay lab</button><button class="btn btn-primary" data-action="import">${icon('plus',13)}Import evidence</button>`)}
    <div class="source-notice"><div class="notice-copy">${icon(data.data_mode === 'synthetic' ? 'terminal' : 'database',13)}<span>${data.data_mode === 'synthetic' ? 'Controlled lab workspace. All starter events are synthetic; real endpoints are not connected.' : data.data_mode === 'mixed' ? 'Mixed workspace. Imported evidence and explicitly labelled lab scenarios are kept traceable.' : 'Your evidence workspace. Import events and an approved permission snapshot to begin.'}</span></div><code>${esc(data.snapshot.policy_version)}</code></div>
    <div class="metrics">
      ${metric('Open investigations', num(counts.open_incidents), `${open.filter(i => i.severity === 'critical').length} high-impact cases to review`, 'shield')}
      ${metric('Permission drift', num(counts.findings), `<span class="accent">${counts.critical_findings} critical</span><span>· ${highFindings} high</span>`, 'network')}
      ${metric('Evidence events', num(counts.events), `${num(counts.identities)} identities · ${num(data.datasets.length)} source imports`, 'database')}
      ${metric('Observed coverage', `${counts.matched_rules}<span class="denominator">/ ${counts.active_rules}</span>`, 'Enabled rules with matches in this corpus', 'activity')}
    </div>
    <div class="content-grid">
      <section class="section">${sectionHeader('01', 'Needs a closer look', `<a class="text-button" href="/investigations" data-route="/investigations">All investigations ${icon('arrow',13)}</a>`)}
        <div class="card"><div class="case-list">${open.slice(0,6).map(item => caseRow(item)).join('') || empty('A clear queue', 'There are no open investigations in the current evidence.')}</div><div class="card-bottom"><span>Ranked by rule severity and verified access context</span><span class="mono">${open.length} open</span></div></div>
        <section class="telemetry">${sectionHeader('02', 'A day in signals', '<span class="mono muted" style="font-size:9px">LAST 24 HOURS · UTC</span>')}<div class="card"><div class="chart-wrap">${telemetryChart(data.series)}</div><div class="card-bottom"><div class="chart-legend"><span><i class="legend-square"></i>Events</span><span><i class="legend-square accent"></i>Rule-matching activity</span></div><span>Observed event counts</span></div></div></section>
      </section>
      <section class="section">${sectionHeader('03', 'Identity exposure', `<span class="count-pill">${data.findings.length} paths</span>`)}
        <div class="card">${finding ? `<div class="trace-summary"><h3>${esc(finding.user_name)}</h3><p class="role">${esc(finding.role)} → ${esc(title(finding.right))}</p></div>${traceGraphic(finding)}<div class="trace-description">${esc(finding.reason)}</div><div class="card-bottom"><span>Nested access, made visible</span><button class="text-button" data-action="identity">Trace path ${icon('arrow',12)}</button></div>` : empty('No observed drift', 'The supplied permission snapshot matches its declared policy.')}</div>
        <div class="card brief-card"><div class="brief-title">${icon('spark',15)}A second pair of eyes.</div><p>Turn selected evidence and permission context into a concise, cited investigation brief.</p><div class="report-status" style="margin-top:12px;margin-bottom:0"><span class="dot"></span>${esc(data.ai.model)} · ${data.ai.remote ? 'cloud inference' : 'local mode'}</div><button class="text-button" data-action="first-incident">Open analyst workspace ${icon('arrow',12)}</button></div>
      </section>
    </div>
    <div class="overview-bottom"><section class="section">${sectionHeader('04', 'Workspace activity')}<div class="card activity-list">${[...data.datasets].sort((a,b) => new Date(b.imported_at)-new Date(a.imported_at)).slice(0,3).map(dataset => `<div class="activity-item"><span class="activity-mark">${icon(dataset.synthetic?'terminal':'upload',13)}</span><div class="activity-text">${esc(dataset.name)}<p>${num(dataset.event_count)} events imported · ${esc(dataset.format)} ${dataset.synthetic ? '· synthetic' : ''}</p></div><time>${ago(dataset.imported_at)}</time></div>`).join('') || empty('Ready for evidence', 'Your next import will appear here.')}</div></section>
      <section class="section">${sectionHeader('05', 'An explainable baseline')}<div class="card model-mini">${model ? `<header><span class="model-name">Isolation Forest</span><span class="badge badge-outline">${model.tree_count} trees</span></header><p class="model-sub">AUTHENTICATION · HELD-OUT WINDOWS</p><div class="mini-metrics"><div class="mini-metric"><strong>${pct(model.metrics.precision)}</strong><span>Precision</span></div><div class="mini-metric"><strong>${pct(model.metrics.recall)}</strong><span>Recall</span></div></div><p class="mini-model-note">${model.test_windows} held-out windows. Actual benchmark results on the ${data.datasets.find(d => d.id === model.dataset_id)?.synthetic ? 'synthetic lab' : 'selected'} corpus.</p><a class="text-button" style="margin-top:12px" href="/research" data-route="/research">Inspect the experiment ${icon('arrow',12)}</a>` : empty('Train your first baseline', 'Label normal activity, preserve independent runs, and evaluate on held-out evidence.')}</div></section>
    </div>`;
}

function metric(label, value, note, name) { return `<div class="metric"><div class="metric-label">${label}${icon(name,14)}</div><div class="metric-value">${value}</div><div class="metric-note">${note}</div></div>`; }
function caseRow(item, full = false) {
  const age=item.time_basis?.startsWith('relative')?'relative time':ago(item.last_seen);
  return `<button class="case-row" data-open-case="${esc(item.id)}" aria-label="Open ${esc(item.title)} for ${esc(item.actor)}"><span class="case-icon ${esc(item.severity)}">${icon(item.rule_id === 'IS-012' ? 'activity' : 'shield',15)}</span><span style="min-width:0"><span class="case-title" style="display:block">${esc(item.title)}</span><span class="case-meta"><code>${esc(item.actor)}</code><span>·</span><code>${esc(item.host)}</code>${item.findings.length ? `<span class="accent">· access context</span>` : ''}</span></span>${full ? `<span class="case-rule">${esc(item.rule_id)}<br><span class="faint" style="font-size:9px">${esc(item.technique)}</span></span>` : ''}<span class="case-side">${badge(item.severity)}<span class="case-time">${age}</span></span><span class="case-arrow">${icon('chevron',13)}</span></button>`;
}

function chosenFinding() {
  return data.findings.find(item => item.id === selectedFinding) || data.findings.find(item => item.user_id === 'maya.chen' && item.right === 'local-admin') || data.findings[0];
}
function traceGraphic(finding) {
  const nodes = finding.path;
  const height = 42 + nodes.length*46;
  const positions = nodes.map((_,i) => ({x:i%2?242:72,y:31+i*46}));
  const lines = positions.slice(1).map((point,i) => {const before=positions[i];return `<path class="trace-line" d="M${before.x} ${before.y+15} C${before.x} ${before.y+40},${point.x} ${point.y-35},${point.x} ${point.y-15}"/><path class="trace-risk" d="M${before.x} ${before.y+15} C${before.x} ${before.y+40},${point.x} ${point.y-35},${point.x} ${point.y-15}"/>`;}).join('');
  return `<svg class="trace-graphic" viewBox="0 0 320 ${height}" role="img" aria-label="Access path: ${esc(nodes.join(' to '))}">${lines}${positions.map((point,i) => `<g><circle class="${i === positions.length-1?'node-risk':'node-bg'}" cx="${point.x}" cy="${point.y}" r="16"/><g class="node-symbol ${i===positions.length-1?'risk-symbol':''}" transform="translate(${point.x-7},${point.y-7}) scale(.58)">${paths[i===0?'user':i===positions.length-1?'shield':'users']}</g><text x="${point.x+(i%2?-25:25)}" y="${point.y+3}" text-anchor="${i%2?'end':'start'}">${esc(short(nodes[i],27))}<title>${esc(nodes[i])}</title></text></g>`).join('')}</svg>`;
}
function telemetryChart(series) {
  const max = Math.max(1,...series.map(point=>point.events));
  const width=760, left=20, barWidth=11, gap=(width-left-15)/series.length;
  return `<svg class="chart" viewBox="0 0 760 150" preserveAspectRatio="none" role="img" aria-label="Actual event counts over the past 24 hours">${[22,66,110].map(y=>`<line class="chart-grid" x1="20" x2="748" y1="${y}" y2="${y}"/>`).join('')}${series.map((point,i)=>{const h=point.events/max*98;return `<rect class="chart-bar${point.alerts?' chart-bar-alert':''}" x="${left+i*gap}" y="${115-h}" width="${barWidth}" height="${h}" rx="2"><title>${utc(point.time)} UTC: ${point.events} events, ${point.alerts} matching cases</title></rect>`;}).join('')}${[0,12,24,36,47].map(i=>`<text class="chart-label" x="${left+i*gap}" y="139" text-anchor="${i===47?'end':'start'}">${utc(series[i].time)}</text>`).join('')}</svg>`;
}

function filteredCases() {
  return data.incidents.filter(item => (!caseFilter.q || `${item.title} ${item.actor} ${item.host} ${item.id}`.toLowerCase().includes(caseFilter.q.toLowerCase())) && (!caseFilter.severity || item.severity===caseFilter.severity) && (!caseFilter.rule || item.rule_id===caseFilter.rule) && (caseFilter.status==='all' || item.status===caseFilter.status));
}
function caseTable() {
  const items=filteredCases();
  return `<div class="card investigation-list"><div class="list-heading"><span>${items.length} investigations ${caseFilter.rule?`· ${esc(caseFilter.rule)}`:''}</span><span>Priority · severity · context</span></div>${items.slice(0,caseLimit).map(item=>caseRow(item,true)).join('') || empty('Nothing in this view', 'Try another filter or replay a lab scenario to collect new signals.')}<div class="card-bottom"><span>Showing ${Math.min(caseLimit,items.length)} of ${items.length}</span>${items.length>caseLimit?'<button class="text-button" data-action="more-cases">Show more '+icon('plus',12)+'</button>':'<span>Evidence first. Verdict second.</span>'}</div></div>`;
}
function investigations() {
  return `${heading('Follow the evidence', 'A closer look at your signals.', 'Every case brings its events, access paths, and analyst notes into one place.', `<button class="btn" data-action="replay">${icon('play',13)}Replay scenario</button><button class="btn btn-primary" data-action="evidence">${icon('file',13)}Evidence browser</button>`)}
    <div class="toolbar"><div class="search-field">${icon('search',14)}<input id="case-search" type="search" placeholder="Search accounts, hosts, or investigations…" value="${esc(caseFilter.q)}" aria-label="Search investigations"></div><select class="select" id="case-severity" aria-label="Filter severity"><option value="">All severities</option>${['critical','high','medium','low'].map(s=>`<option value="${s}" ${caseFilter.severity===s?'selected':''}>${title(s)}</option>`).join('')}</select><div class="filter-tabs" role="group" aria-label="Investigation status">${['all','open','closed','confirmed'].map(status=>`<button class="filter-tab ${caseFilter.status===status?'active':''}" data-status="${status}">${title(status)}</button>`).join('')}</div></div>
    <div id="case-table">${caseTable()}</div>`;
}

function identityPage() {
  const finding=chosenFinding();
  return `${heading('Access, made understandable', 'Know where privilege comes from.', 'Compare observed access against an explicit role policy. Follow every unexpected permission back to its source.', `<button class="btn" data-action="export-snapshot">${icon('download',13)}Export snapshot</button><button class="btn btn-primary" data-action="import-snapshot">${icon('upload',13)}Import snapshot</button>`)}
    <div class="source-notice"><div class="notice-copy">${icon('branch',13)}<span>${esc(data.snapshot.source)} snapshot · ${date(data.snapshot.captured_at)} · ${esc(data.snapshot.policy_version)}</span></div><span class="mono" style="font-size:9px">7 SUPPORTED NORMALIZED ACTIONS</span></div>
    <div class="identity-top"><section class="section">${sectionHeader('01','Outside the approved policy',`<span class="count-pill">${data.findings.length}</span>`)}<div class="card">${data.findings.map(item=>`<button class="finding-row ${finding?.id===item.id?'selected':''}" data-finding="${esc(item.id)}"><span class="case-icon ${item.severity}">${icon('network',14)}</span><span class="finding-copy"><strong>${esc(item.user_name)} <span class="muted">→ ${esc(item.asset_name)}</span></strong><p>${esc(item.role)} · ${esc(title(item.right))}</p></span>${badge(item.severity)}${icon('chevron',12)}</button>`).join('') || empty('Policy matches observed access', 'No discrepancies were found for the supported actions in this snapshot.')}</div></section>
      <section class="section">${sectionHeader('02','The permission path')}<div class="card">${finding?`<div class="card-top"><h3>${esc(finding.user_name)}</h3><span class="badge badge-outline">${esc(title(finding.right))}</span></div><div class="access-graphic">${traceGraphic(finding)}</div><div class="path-tags">${finding.path.map(p=>`<span>${esc(p)}</span>`).join('')}</div><div class="info-box">${esc(finding.reason)}<br><button class="btn btn-small" data-preview="${esc(finding.id)}">${icon('branch',12)}Preview remediation impact</button></div>`:empty('An explainable path', 'Select a discrepancy to inspect its membership and permission chain.')}</div></section></div>
    <section class="section">${sectionHeader('03','People & service identities', `<span class="mono muted" style="font-size:9px">${data.snapshot.users.length} IDENTITIES · ${data.snapshot.groups.length} GROUPS</span>`)}<div class="card table-scroll"><table class="data-table"><thead><tr><th>Identity</th><th>Approved role</th><th>Direct memberships</th><th>Policy drift</th></tr></thead><tbody>${data.snapshot.users.map(user=>{const findings=data.findings.filter(f=>f.user_id===user.id);return `<tr><td><div class="name-cell"><span class="person">${esc(user.name.slice(0,2).toUpperCase())}</span><span><strong>${esc(user.name)}</strong><small>${esc(user.department)}</small></span></div></td><td>${esc(user.role)}</td><td><span class="mono muted">${user.groups.map(g=>esc(data.snapshot.groups.find(group=>group.id===g)?.name ||g)).join(', ') || '—'}</span></td><td>${findings.length?badge(findings[0].severity,`${findings.length} findings`):'<span class="badge good">Within policy</span>'}</td></tr>`;}).join('')}</tbody></table></div></section>
    <div class="inline-note">The auditor evaluates declared, normalized single-action grants with nested groups and canonical explicit/inherited precedence. Collectors must resolve Windows object scope before export. This view does not claim full arbitrary AD DACL evaluation.</div>`;
}

function qualityBar(dataset) {
  const total=Math.max(1,dataset.event_count);
  return `<div class="quality-cell"><div class="quality-bar" role="img" aria-label="${dataset.benign_count} benign, ${dataset.malicious_count} malicious, ${dataset.unknown_count} unknown"><i class="benign" style="width:${dataset.benign_count/total*100}%"></i><i class="malicious" style="width:${dataset.malicious_count/total*100}%"></i><i class="unknown" style="width:${dataset.unknown_count/total*100}%"></i></div><span>${Math.round((dataset.benign_count+dataset.malicious_count)/total*100)}% labelled</span></div>`;
}
function datasetsPage() {
  return `${heading('Good evidence is the foundation', 'Give your models better context.', 'Curated sources, explicit labels, and a clear chain of provenance. Keep distinct domains and feature schemas separate.', `<button class="btn" data-action="kaggle">${icon('database',13)}Kaggle import</button><button class="btn btn-primary" data-action="import">${icon('plus',13)}Import evidence</button>`)}
    <section class="section import-section">${sectionHeader('01','Your evidence library',`<span class="mono muted" style="font-size:9px">${num(data.counts.events)} EVENTS · ${data.datasets.length} IMPORTS</span>`)}<div class="card table-scroll">${data.datasets.length?`<table class="data-table"><thead><tr><th>Source import</th><th>Events</th><th>Label completeness</th><th>Provenance</th></tr></thead><tbody>${[...data.datasets].sort((a,b)=>new Date(b.imported_at)-new Date(a.imported_at)).map(dataset=>`<tr><td><button class="dataset-name-button" data-manifest="${esc(dataset.id)}"><strong>${esc(dataset.name)}</strong><div style="margin-top:4px"><span class="mono faint" style="font-size:9px">${esc(dataset.format)}</span> ${dataset.synthetic?'<span class="badge badge-outline" style="margin-left:4px">synthetic</span>':''}</div></button></td><td class="mono">${num(dataset.event_count)}</td><td>${qualityBar(dataset)}</td><td><button class="text-button" data-manifest="${esc(dataset.id)}">${icon('file',12)}Manifest ${icon('chevron',11)}</button></td></tr>`).join('')}</tbody></table>`:empty('Your library is ready', 'Import a supported event file to begin tracing its provenance.')}</div></section>
    <section class="section">${sectionHeader('02','Curated research sources',`<span class="credentials-line"><span class="dot"></span>Kaggle ${data.kaggle_configured?'authenticated':'public access'}</span>`)}<div class="dataset-grid">${data.catalog.map((entry,index)=>`<article class="card dataset-card"><div class="dataset-body"><div class="dataset-head"><span class="dataset-icon ${entry.id==='otrf'?'featured':''}">${icon(entry.category.startsWith('ICS')?'activity':entry.id==='lanl'?'network':'database',18)}</span><span class="badge badge-outline">${esc(entry.category)}</span></div><h3>${esc(entry.name)}</h3><p class="dataset-description">${esc(entry.description)}</p><div class="dataset-tags"><span class="badge">${esc(entry.format)}</span><span class="badge">${esc(entry.access)}</span></div></div><footer class="dataset-footer"><button class="text-button" data-source-info="${esc(entry.id)}">Source details ${icon('external',11)}</button>${entry.can_fetch?`<button class="btn btn-small" data-fetch="${esc(entry.id)}">${icon('download',11)}Import sample</button>`:`<button class="text-button" data-import-source="${esc(entry.id)}">Import export ${icon('arrow',12)}</button>`}</footer></article>`).join('')}</div></section>
    <div class="inline-note">The library distinguishes scenario annotations from event labels. OTRF and EVTX attack captures include background activity; those records start as unknown. LANL compromise labels are sparse. ICS time series receive a separate, schema-compatible model.</div>`;
}

function researchPage() {
  const model=data.models[researchDomain];
  const imported=data.datasets.find(item=>item.id===model?.dataset_id);
  const reviews=Object.values(data.reviews).sort((a,b)=>new Date(b.reviewed_at)-new Date(a.reviewed_at));
  return `${heading('Measure what matters', 'An experiment you can explain.', 'Inspect the split, the features, and the false positives. Every number below comes from a persisted training run.', `<button class="btn" data-action="export-model">${icon('download',13)}Export experiment</button><button class="btn btn-primary" data-action="rules">${icon('shield',13)}Detection library</button>`)}
    <div class="training-controls"><div class="filter-tabs" role="group" aria-label="Model domain">${['authentication','ics'].map(kind=>`<button class="filter-tab ${researchDomain===kind?'active':''}" data-domain="${kind}">${kind==='ics'?'Industrial process':'Authentication'}</button>`).join('')}</div><label class="sr-only" for="training-dataset">Training dataset</label><select class="select" id="training-dataset"><optgroup label="Individual imports">${data.datasets.map(item=>`<option value="${esc(item.id)}" ${researchDataset===item.id?'selected':''}>${esc(short(item.name,38))}</option>`).join('')}</optgroup><optgroup label="Same-source collection cohorts">${[...new Set(data.datasets.map(item=>item.source))].map(source=>`<option value="source:${esc(source)}" ${researchDataset==='source:'+source?'selected':''}>All ${esc(source)} imports</option>`).join('')}</optgroup></select><button class="btn" data-action="train">${icon('play',12)}Train & evaluate</button></div>
    ${model?`<div class="metrics research-metrics">${metric('Precision',pct(model.metrics.precision),'Of predicted anomalous test windows','chart')}${metric('Recall',pct(model.metrics.recall),'Of labelled attack test windows','activity')}${metric('Average precision',pct(model.metrics.average_precision),'Threshold-independent ranking measure','layers')}${metric('False positives',num(model.metrics.false_positive),`${model.metrics.true_negative} correctly normal · ${model.metrics.unknown} unknown excluded`,'shield')}</div>
      <div class="two-col"><section class="section">${sectionHeader('01','The training record',`<span class="badge badge-outline">${imported?.synthetic?'Synthetic lab benchmark':'Selected evidence benchmark'}</span>`)}<div class="card"><header class="experiment-header"><div><h3>${esc(model.algorithm)}</h3><p>${model.tree_count} TREES · SEED ${model.seed} · ${esc(model.schema)}</p></div><span class="badge good">Persisted</span></header><div class="split-track"><i class="split-train"></i><i class="split-validation"></i><i class="split-test"></i></div><div class="split-labels"><div><strong>${model.training_windows} windows</strong><span>Benign training · ${model.training_groups.length} groups</span></div><div><strong>${model.validation_windows} windows</strong><span>Validation · ${model.validation_groups.length} groups</span></div><div><strong>${model.test_windows} windows</strong><span>Held-out test · ${model.test_groups.length} groups</span></div></div><div class="comparison-row header"><span>Same held-out cases</span><span>Precision</span><span>Recall</span></div><div class="comparison-row"><span>Isolation Forest</span><span>${pct(model.metrics.precision)}</span><span>${pct(model.metrics.recall)}</span></div><div class="comparison-row"><span>Transparent z-score baseline</span><span>${pct(model.baseline_metrics.precision)}</span><span>${pct(model.baseline_metrics.recall)}</span></div><div class="feature-list">${model.feature_names.map(name=>`<span class="feature-tag">${esc(name)}</span>`).join('')}</div><p class="experiment-note">${model.training_groups.length}/${model.validation_groups.length}/${model.test_groups.length} entire runs or collection-day groups in chronological order. Only verified benign training windows fit the forest. Test labels never set its threshold.</p><div class="card-bottom"><span>${date(model.trained_at)} · ${utc(model.trained_at)} UTC · ${model.duration_ms} ms</span><span class="mono">THRESHOLD ${model.threshold.toFixed(3)}</span></div></div></section>
      <section class="section">${sectionHeader('02','Held-out anomaly scores')}<div class="card"><div class="chart-wrap">${scorePlot(model)}</div><div class="card-bottom"><div class="chart-legend"><span><i class="legend-square" style="background:var(--ink)"></i>Normal</span><span><i class="legend-square accent"></i>Attack-labelled</span></div><span>Dashed: validation threshold</span></div></div><div class="inline-note">${model.metrics.true_positive} true positives · ${model.metrics.false_negative} missed attack windows. Anomaly scores are rankings, not probabilities. Rules and permission context provide complementary signals.</div></section></div>
      <section class="section">${sectionHeader('03','Reproducibility notes')}<div class="card"><ul class="notes-list">${model.notes.map(note=>`<li>${esc(note)}</li>`).join('')}</ul><div class="card-bottom"><span>Training-data fingerprint</span><code>${esc(short(model.data_hash,24))}</code></div></div></section>`:empty('Build your first baseline', 'Choose a feature-compatible dataset with at least ten independent runs or days and verified normal windows.')}
    <section class="section">${sectionHeader('04','The decisions behind the alerts',`<span class="count-pill">${reviews.length} reviews</span>`)}<div class="card">${reviews.length?reviews.slice(0,10).map(review=>{const incident=data.incidents.find(item=>item.id===review.incident_id);return `<article class="review-card"><h4>${esc(incident?.title||review.incident_id)} ${badge(review.verdict==='benign'?'good':'medium',review.verdict==='benign'?'False positive':review.verdict)}</h4><p>${esc(review.reason)}</p><footer>${esc(review.reviewer)} · ${date(review.reviewed_at)}<button class="text-button" data-open-case="${esc(review.incident_id)}">Review evidence ${icon('arrow',11)}</button></footer></article>`;}).join(''):empty('Make the tuning visible', 'Investigate a case, record why it was benign or suspicious, and preserve the evidence behind that decision.', '<button class="btn btn-small" data-action="investigations">Review a case '+icon('arrow',12)+'</button>')}</div></section>`;
}

function scorePlot(model) {
  const scores=model.test_scores, w=370,h=205, bottom=174;
  const min=.2,max=.85;
  const y=value=>bottom-(value-min)/(max-min)*145;
  return `<svg class="score-plot" viewBox="0 0 ${w} ${h}" role="img" aria-label="Observed anomaly scores on held-out windows">${[.3,.5,.7].map(value=>`<line class="chart-grid" x1="30" x2="356" y1="${y(value)}" y2="${y(value)}"/><text class="chart-label" x="7" y="${y(value)+3}">${value.toFixed(1)}</text>`).join('')}<line class="threshold-line" x1="30" x2="356" y1="${y(model.threshold)}" y2="${y(model.threshold)}"/>${scores.map((sample,i)=>`<circle class="score-point ${sample.label==='malicious'?'attack':''}" cx="${35+i*(310/Math.max(1,scores.length-1))}" cy="${y(sample.score)}" r="${sample.label==='malicious'?4:3}"><title>${esc(sample.group)} · ${sample.label} · ${sample.score.toFixed(3)}</title></circle>`).join('')}<text class="chart-label" x="30" y="197">EARLIER TEST WINDOWS</text><text class="chart-label" x="356" y="197" text-anchor="end">LATER</text></svg>`;
}

function rulesPage() {
  return `${heading('Every signal has a reason', 'A library built for inspection.', 'Twelve transparent detections, with their telemetry requirements and known false-positive contexts.', `<button class="btn" data-action="replay">${icon('play',13)}Validate in lab</button>`)}<div class="rule-grid">${data.rules.map(rule=>`<article class="card rule-card"><div class="rule-top"><span class="mono">${esc(rule.id)} · ${esc(rule.technique)}</span><button class="toggle" role="switch" aria-checked="${rule.enabled}" aria-label="Enable ${esc(rule.name)}" data-toggle-rule="${esc(rule.id)}"></button></div><h3>${esc(rule.name)}</h3><p>${esc(rule.description)}</p><details><summary>Telemetry & false-positive context</summary><p><strong>${esc(rule.log_source)}</strong><br>${esc(rule.false_positives)}</p></details><footer>${badge(rule.severity)}<button class="text-button" data-rule-cases="${esc(rule.id)}">${rule.matches} matching cases ${icon('arrow',12)}</button></footer></article>`).join('')}</div>`;
}

function bindPage() {
  const search=document.querySelector('#case-search');
  search?.addEventListener('input',()=>{caseFilter.q=search.value;document.querySelector('#case-table').innerHTML=caseTable();});
  document.querySelector('#case-severity')?.addEventListener('change',event=>{caseFilter.severity=event.target.value;document.querySelector('#case-table').innerHTML=caseTable();});
  document.querySelector('#training-dataset')?.addEventListener('change',event=>{researchDataset=event.target.value;});
}

let previousFocus;
function modal(html, className = 'modal') {
  closeModal();
  previousFocus=document.activeElement;
  const dialog=document.createElement('dialog');
  dialog.className=className;
  dialog.innerHTML=html;
  const heading=dialog.querySelector('h2');
  if (heading) { heading.id='dialog-title'; dialog.setAttribute('aria-labelledby','dialog-title'); }
  document.querySelector('#overlay-root').append(dialog);
  dialog.addEventListener('click',event=>{ if(event.target===dialog) { const rect=dialog.getBoundingClientRect(); if(event.clientX<rect.left ||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom) dialog.close(); } });
  dialog.addEventListener('close',()=>{dialog.remove();previousFocus?.focus?.({preventScroll:true});});
  dialog.showModal();
  return dialog;
}
function closeModal() { document.querySelectorAll('dialog').forEach(dialog=>{dialog.close();dialog.remove();}); }
function modalHeader(name, subtitle='') {return `<header class="modal-header"><div><h2>${name}</h2>${subtitle?`<p>${subtitle}</p>`:''}</div><button class="icon-button" data-close aria-label="Close dialog">${icon('close',17)}</button></header>`;}
let toastTimer;
function toast(message, error=false) {
  clearTimeout(toastTimer);
  document.querySelector('#toast-root').innerHTML=`<div class="toast ${error?'error':''}" role="status">${icon(error?'alert':'check',15)}<span>${esc(message)}</span></div>`;
  toastTimer=setTimeout(()=>document.querySelector('#toast-root').replaceChildren(),4500);
}
function inlineError(dialog,error) {const element=dialog.querySelector('[data-form-message]');if(element) element.innerHTML=`<div class="inline-error" role="alert">${esc(error.message || error)}</div>`;else toast(error.message || error,true);}

function openPalette() {
  const dialog=modal(`<div class="command-search">${icon('search',18)}<input id="command-input" placeholder="Where would you like to go?" aria-label="Search workspace commands" autocomplete="off"><kbd>esc</kbd></div><div class="command-results" id="command-results"></div><div class="command-help"><span>↑ ↓ navigate · ↵ open</span><span>IdentityShield workspace</span></div>`,'command-dialog');
  const input=dialog.querySelector('input');
  function results() {
    const query=input.value.toLowerCase();
    const destinations=[...pages,{path:'/rules',label:'Detection library',icon:'shield'}].filter(p=>p.label.toLowerCase().includes(query));
    const incidents=data.incidents.filter(item=>`${item.title} ${item.actor} ${item.host} ${item.id}`.toLowerCase().includes(query)).slice(0,5);
    const users=data.snapshot.users.filter(user=>`${user.name} ${user.role}`.toLowerCase().includes(query)).slice(0,3);
    dialog.querySelector('#command-results').innerHTML=`${destinations.length?'<div class="command-group">Workspace</div>':''}${destinations.map(page=>`<button class="command-option" data-route="${page.path}">${icon(page.icon,15)}<span>${page.label}</span><span class="option-meta">Go to</span></button>`).join('')}${query&&incidents.length?'<div class="command-group">Investigations</div>':''}${query?incidents.map(item=>`<button class="command-option" data-open-case="${esc(item.id)}">${icon('shield',15)}<span>${esc(short(item.title,44))}</span><span class="option-meta">${esc(item.actor)}</span></button>`).join(''):''}${query&&users.length?'<div class="command-group">Identities</div>':''}${query?users.map(user=>`<button class="command-option" data-action="identity">${icon('user',15)}<span>${esc(user.name)}</span><span class="option-meta">${esc(short(user.role,24))}</span></button>`).join(''):''}`;
    paletteIndex=0;highlight();
  }
  function highlight(){dialog.querySelectorAll('.command-option').forEach((option,index)=>option.classList.toggle('selected',index===paletteIndex));}
  input.addEventListener('input',results);
  input.addEventListener('keydown',event=>{
    const options=dialog.querySelectorAll('.command-option');
    if(event.key==='ArrowDown'){event.preventDefault();paletteIndex=Math.min(options.length-1,paletteIndex+1);highlight();}
    if(event.key==='ArrowUp'){event.preventDefault();paletteIndex=Math.max(0,paletteIndex-1);highlight();}
    if(event.key==='Enter'){event.preventDefault();options[paletteIndex]?.click();}
  });
  results();input.focus();
}

let modalGeneration=0;
async function openIncident(id) {
  const generation=++modalGeneration;
  const info=await api(`/api/incidents/${encodeURIComponent(id)}`);
  if(generation!==modalGeneration) return;
  activeIncident=info;
  const incident=info.incident;
  const matching=new Set(incident.event_ids);
  const synthetic=info.events.every(event=>event.source==='synthetic-lab');
  const dialog=modal(`<header class="investigation-header"><div class="case-id-row"><span class="case-id">${icon('shield',13)}${esc(incident.id)}<span class="slash">/</span>${esc(incident.rule_id)}${badge(incident.severity)}</span><button class="icon-button" data-close aria-label="Close investigation">${icon('close',18)}</button></div><h2>${esc(incident.title)}</h2><div class="incident-meta"><span>${icon('user',12)}${esc(incident.actor)}</span><span>${icon('server',12)}${esc(incident.host)}</span><span>${icon('clock',12)}${date(incident.started_at)} · ${utc(incident.started_at)} UTC</span><span class="badge badge-outline">${synthetic?'Synthetic lab evidence':'Imported evidence'}</span></div></header>
    <div class="investigation-body"><section class="evidence-pane"><div class="pane-heading"><h3>Follow the evidence</h3><span class="mono muted" style="font-size:9px">${info.events.length} EVENTS</span></div><p class="evidence-intro">${esc(incident.summary)} Related events are correlated by source, run, and a bounded time window.</p><div id="incident-timeline">${timeline(info.events,matching)}</div>${incident.findings.length?`<div class="report-label">Linked access context</div>${incident.findings.map(finding=>`<div class="linked-access"><strong>${esc(finding.user_name)} · ${esc(title(finding.right))}</strong><p>${esc(finding.reason)}</p><span class="mono">${esc(finding.path.join(' → '))}</span></div>`).join('')}`:''}</section>
    <section class="analyst-pane"><div class="pane-heading"><h3>${iconInline('spark')}Analyst workspace</h3><span class="badge badge-outline">Evidence-backed</span></div><div id="report-content">${reportHTML(info.report || info.brief)}</div><div id="report-message" data-form-message></div><div class="report-tools"><button class="btn btn-primary btn-small" data-action="generate-report">${icon('spark',12)}Generate AI report</button><button class="btn btn-small" data-action="save-brief">${icon('file',12)}Save local brief</button>${info.report?'<button class="btn btn-small" data-action="export-report">'+icon('download',12)+'Export</button>':''}</div><p class="ai-disclosure">${data.ai.remote?'Agent Router sends only the selected normalized incident evidence and permission context to '+esc(data.ai.model)+'. Raw logs and truth labels are omitted.':'Configured mode: '+esc(data.ai.provider)+'. Local evidence briefs require no model connection.'}</p></section></div>
    <footer class="investigation-footer"><span>Priority ${incident.priority}/100 · deterministic ranking, not probability</span><div class="actions"><button class="btn btn-small" data-action="review-case">${icon('check',12)}Record verdict</button><button class="btn btn-small" data-action="copy-bundle">${icon('copy',12)}Copy evidence</button></div></footer>`,'investigation-dialog');
  if(!data.ai.configured || data.ai.provider==='local') dialog.querySelector('[data-action="generate-report"]').disabled=true;
  const analystPane=dialog.querySelector('.analyst-pane');
  analystPane.querySelector('.pane-heading').after(analystPane.querySelector('.report-tools'));
  analystPane.querySelector('.report-tools').after(analystPane.querySelector('.ai-disclosure'));
}

function timeline(events,matching) {
  return events.map(event=>`<article class="timeline-item ${matching.has(event.id)?'rule-match':''}" data-event-id="${esc(event.id)}"><time>${utc(event.timestamp)}:${new Date(event.timestamp).getUTCSeconds().toString().padStart(2,'0')} UTC</time><h4>${esc(title(event.kind))} ${matching.has(event.id)?'<span class="badge badge-outline" style="margin-left:4px">rule match</span>':''}</h4><p><code>${esc(event.actor)}</code> on <code>${esc(event.host)}</code>${event.target?` · target ${esc(event.target)}`:''}</p>${event.data.command?`<pre class="timeline-command">${esc(event.data.command)}</pre>`:''}${event.kind==='ics_sample'?`<p class="mono" style="margin-top:6px">${Object.entries(event.data).filter(([key])=>['tank_level','pressure','flow_rate'].includes(key)).map(([key,value])=>`${esc(key)}: ${esc(value)}`).join(' · ')}</p>`:''}<button class="event-link" data-event="${esc(event.id)}">${esc(event.id)} · inspect record ${iconInline('external')}</button></article>`).join('');
}
function reportHTML(report) {
  return `<div class="report-status"><span class="dot"></span>${report.provider==='local'?'LOCAL EVIDENCE BRIEF':esc(report.provider).toUpperCase()+' · '+esc(report.model)}</div><p class="report-summary">${esc(report.summary)}</p><span class="badge ${report.verdict==='benign'?'good':'medium'}">Suggested verdict: ${esc(title(report.verdict))}</span><div class="report-label">Supported observations</div>${report.claims.map(claim=>`<div class="report-claim">${esc(claim.text)}<div class="citations">${claim.evidence_ids.map(id=>`<button class="citation" data-citation="${esc(id)}">${esc(short(id,24))}</button>`).join('')}</div></div>`).join('')}<div class="report-label">Next steps</div><ol class="report-steps">${report.next_steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ol><div class="report-limitations"><strong>Scope & limitations</strong><ul>${report.limitations.map(note=>`<li>${esc(note)}</li>`).join('')}</ul><span>Citation membership is checked. The meaning of each claim still requires analyst review.</span></div>`;
}
async function generateReport(provider) {
  if(!activeIncident) return;
  const id=activeIncident.incident.id;
  const dialog=document.querySelector('.investigation-dialog');
  const button=dialog?.querySelector(`[data-action="${provider==='local'?'save-brief':'generate-report'}"]`);
  if(!button) return;
  const label=button.innerHTML;
  button.disabled=true;button.innerHTML='<span class="loading-dots"><i></i><i></i><i></i></span>'+ (provider==='local'?'Saving brief':'Reading the evidence');
  dialog.querySelector('#report-message').replaceChildren();
  try {
    const report=await api(`/api/incidents/${encodeURIComponent(id)}/report`,{method:'POST',body:{provider:provider==='local'?'local':data.ai.provider}});
    if(!dialog.isConnected || activeIncident?.incident.id!==id) return;
    activeIncident.report=report;
    dialog.querySelector('#report-content').innerHTML=reportHTML(report);
    if(!dialog.querySelector('[data-action="export-report"]')) dialog.querySelector('.report-tools').insertAdjacentHTML('beforeend','<button class="btn btn-small" data-action="export-report">'+icon('download',12)+'Export</button>');
    toast(provider==='local'?'Local evidence brief saved.':'Cited analyst report saved.');
  } catch(error) { if(dialog.isConnected) inlineError(dialog,error); }
  finally { if(button.isConnected) {button.disabled=false;button.innerHTML=label;} }
}

function reviewCase() {
  const id=activeIncident.incident.id;
  const existing=data.reviews[id];
  const dialog=modal(`${modalHeader('Record your reasoning','Preserve the verdict and the evidence behind your decision.')}<form id="review-form"><div class="modal-body"><div class="form-field"><label for="review-verdict">Analyst verdict</label><select id="review-verdict" name="verdict">${[['benign','Benign · false positive'],['malicious','Malicious · true positive'],['unknown','Needs more evidence']].map(([value,label])=>`<option value="${value}" ${existing?.verdict===value?'selected':''}>${label}</option>`).join('')}</select></div><div class="form-field"><label for="review-reason">What supports this decision?</label><textarea class="textarea" id="review-reason" name="reason" placeholder="Record the relevant events, change context, and any tuning decision…" required>${esc(existing?.reason||'')}</textarea></div><div class="form-field"><label for="reviewer">Reviewer</label><input class="input" id="reviewer" name="reviewer" value="${esc(analystName)}" required></div><div class="inline-note">The case verdict is stored separately from event-level training labels. Review individual records before changing their ground truth.</div><div data-form-message></div></div><footer class="modal-footer"><button type="button" class="btn" data-close>Cancel</button><button class="btn btn-primary" type="submit">${icon('check',12)}Save review</button></footer></form>`);
  dialog.querySelector('form').addEventListener('submit',async event=>{
    event.preventDefault();const form=new FormData(event.target);const button=event.target.querySelector('[type="submit"]');button.disabled=true;
    try {await api(`/api/incidents/${encodeURIComponent(id)}/review`,{method:'POST',body:Object.fromEntries(form)});closeModal();await load();toast('Review saved with your reasoning.');await openIncident(id);}catch(error){inlineError(dialog,error);}finally{button.disabled=false;}
  });
}

function openImport(source='user-import') {
  const entry=data.catalog.find(item=>item.id===source);
  const dialog=modal(`${modalHeader('Bring your evidence in.','Normalized events, traceable sources, and explicit labels.')}<form id="import-form"><div class="modal-body"><label class="dropzone" id="dropzone">${icon('upload',24)}<strong id="file-caption">Drop a file here, or choose one</strong><small>JSONL, JSON, CSV, GZ, or compatible ZIP · up to 64 MiB</small><input id="import-file" type="file" name="file" accept=".json,.jsonl,.ndjson,.csv,.txt,.gz,.zip" required aria-label="Evidence file"></label><div class="form-row"><div class="form-field"><label for="import-source">Source</label><select id="import-source" name="source"><option value="user-import">My own evidence</option>${data.catalog.map(item=>`<option value="${item.id}" ${item.id===source?'selected':''}>${esc(item.name)}</option>`).join('')}</select></div><div class="form-field"><label for="import-format">Event adapter</label><select id="import-format" name="format">${[['canonical','Canonical event JSONL'],['windows-jsonl','Windows / Sysmon JSONL'],['lanl-auth','LANL authentication CSV'],['hai-csv','ICS numeric-tag CSV']].map(([value,label])=>`<option value="${value}" ${(entry?.format||'canonical')===value?'selected':''}>${label}</option>`).join('')}</select></div></div><div class="form-field"><label for="import-name">Import name</label><input class="input" id="import-name" name="name" placeholder="A name that preserves the collection context"></div><div class="form-field" id="lanl-labels" style="display:none"><label for="label-file">Optional LANL redteam.txt companion</label><input class="input" id="label-file" name="labels" type="file" accept=".txt,.csv,.gz"><small>Only exact time/user/source/destination matches receive a compromise label.</small></div><label class="checkbox-row" id="verified-normal"><input type="checkbox" name="verified_normal" value="true"><span>I independently verified this file contains normal activity only. Unchecked records without explicit labels remain unknown.</span></label><div class="inline-note" id="adapter-note">${esc(entry?.notes || 'Canonical records require a timestamp, kind, and explicit benign/malicious/unknown label. Missing labels remain unknown. Native EVTX and Splunk index binaries require a normalized export.')}</div><div data-form-message></div></div><footer class="modal-footer"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-primary" type="submit">${icon('plus',12)}Import evidence</button></footer></form>`);
  const input=dialog.querySelector('#import-file'),format=dialog.querySelector('#import-format'),zone=dialog.querySelector('#dropzone');
  input.addEventListener('change',()=>{const file=input.files[0];if(file){dialog.querySelector('#file-caption').textContent=file.name;dialog.querySelector('#import-name').value=file.name;}});
  ['dragenter','dragover'].forEach(type=>zone.addEventListener(type,event=>{event.preventDefault();zone.classList.add('drag');}));
  ['dragleave','drop'].forEach(type=>zone.addEventListener(type,event=>{event.preventDefault();zone.classList.remove('drag');if(type==='drop'&&event.dataTransfer.files.length){input.files=event.dataTransfer.files;input.dispatchEvent(new Event('change'));}}));
  const update=()=>{dialog.querySelector('#lanl-labels').style.display=format.value==='lanl-auth'?'flex':'none';dialog.querySelector('#verified-normal').style.display=format.value==='canonical'?'none':'flex';};
  format.addEventListener('change',update);update();
  dialog.querySelector('#import-source').addEventListener('change',event=>{const entry=data.catalog.find(item=>item.id===event.target.value);if(entry){format.value=entry.format;dialog.querySelector('#adapter-note').textContent=entry.notes;}update();});
  dialog.querySelector('form').addEventListener('submit',async event=>{
    event.preventDefault();const form=new FormData(event.target);const file=input.files[0];const button=event.target.querySelector('[type="submit"]');
    if(!file ||file.size>64*1024*1024){inlineError(dialog,new Error('Choose a file no larger than 64 MiB.'));return;}
    if(!form.get('verified_normal'))form.set('verified_normal','false');
    if(!form.get('labels')?.size)form.delete('labels');
    button.disabled=true;button.innerHTML='Validating & importing…';
    try {const result=await api('/api/datasets/import',{method:'POST',body:form});closeModal();await load();toast(`${num(result.event_count)} events imported with provenance.`);}catch(error){inlineError(dialog,error);}finally{button.disabled=false;button.innerHTML=icon('plus',12)+'Import evidence';}
  });
}

async function fetchSource(id,button) {
  const label=button.innerHTML;button.disabled=true;button.innerHTML='Importing…';
  try {const result=await api(`/api/datasets/fetch/${encodeURIComponent(id)}`,{method:'POST'});await load();toast(`${num(result.event_count)} publisher events imported. Labels remain explicit.`);}catch(error){toast(error.message,true);}finally{if(button.isConnected){button.disabled=false;button.innerHTML=label;}}
}
function sourceInfo(id) {
  const entry=data.catalog.find(item=>item.id===id);
  modal(`${modalHeader(esc(entry.name),esc(entry.category))}<div class="modal-body"><p class="muted" style="font-size:12px;line-height:1.9">${esc(entry.description)}</p><dl><div class="key-value"><dt>Publisher</dt><dd><a href="${esc(entry.source_url)}" target="_blank" rel="noreferrer">${esc(entry.source_url)} ${iconInline('external')}</a></dd></div><div class="key-value"><dt>Adapter</dt><dd><code>${esc(entry.format)}</code></dd></div><div class="key-value"><dt>License</dt><dd>${esc(entry.license)}</dd></div><div class="key-value"><dt>Access</dt><dd>${esc(entry.access)}</dd></div></dl><div class="inline-note">${esc(entry.notes)}</div></div><footer class="modal-footer"><button class="btn" data-close>Close</button><button class="btn btn-primary" data-import-source="${esc(entry.id)}">Import normalized export ${icon('arrow',12)}</button></footer>`);
}
function manifest(id) {
  const entry=data.datasets.find(item=>item.id===id);
  const dialog=modal(`${modalHeader('The evidence manifest.',esc(entry.name))}<div class="modal-body"><dl>${[['Import',entry.id],['Source',entry.source],['Format',entry.format],['Imported',new Date(entry.imported_at).toLocaleString()],['Events',num(entry.event_count)],['Labels',`${entry.benign_count} benign · ${entry.malicious_count} malicious · ${entry.unknown_count} unknown`],['License',entry.license],['Payload SHA',entry.sha256]].map(([key,value])=>`<div class="key-value"><dt>${key}</dt><dd${key==='Payload SHA'?' class="mono"':''}>${esc(value)}</dd></div>`).join('')}${entry.source_url?`<div class="key-value"><dt>Original source</dt><dd><a href="${esc(entry.source_url)}" target="_blank" rel="noreferrer">${esc(entry.source_url)}</a></dd></div>`:''}</dl><div class="inline-note">${esc(entry.notes)}</div></div><footer class="modal-footer"><button class="btn" data-close>Close</button><button class="btn btn-primary" id="export-manifest">${icon('download',12)}Export manifest</button></footer>`);
  dialog.querySelector('#export-manifest').addEventListener('click',()=>downloadData(entry,entry.id+'-manifest.json'));
}

async function kaggleDialog() {
  const dialog=modal(`${modalHeader('HAI, from its publisher.','Download one bounded CSV from the authoritative Kaggle dataset.')}<form id="kaggle-form"><div class="modal-body"><div class="inline-note" style="margin-top:0">Publisher dataset: <a href="https://www.kaggle.com/datasets/icsdataset/hai-security-dataset" target="_blank" rel="noreferrer"><code>icsdataset/hai-security-dataset</code> ${iconInline('external')}</a><br>${data.kaggle_configured?'Server-side credentials are configured.':'This public publisher dataset supports anonymous access. Optional Kaggle credentials stay on the Go server.'}</div><div class="form-field" style="margin-top:20px"><label for="kaggle-file">Exact publisher filename</label><input class="input" id="kaggle-file" name="file" list="kaggle-file-options" placeholder="Loading the publisher’s CSV listing…" required><datalist id="kaggle-file-options"></datalist><small id="kaggle-file-note">One CSV/CSV.GZ or its server-side ZIP wrapper, up to 64 MiB expanded. Large releases should be sliced locally.</small></div><div data-form-message></div></div><footer class="modal-footer"><button class="btn" type="button" data-close>Close</button><button class="btn btn-primary" type="submit">${icon('download',12)}Import HAI file</button></footer></form>`);
  dialog.querySelector('form').addEventListener('submit',async event=>{event.preventDefault();const button=event.target.querySelector('[type="submit"]');button.disabled=true;button.innerHTML='Downloading & normalizing…';try{const result=await api('/api/datasets/kaggle',{method:'POST',body:{file:dialog.querySelector('input').value}});closeModal();await load();toast(`${num(result.event_count)} HAI samples imported.`);}catch(error){inlineError(dialog,error);}finally{button.disabled=false;button.innerHTML=icon('download',12)+'Import HAI file';}});
  try {const result=await api('/api/datasets/kaggle/files');if(!dialog.isConnected)return;dialog.querySelector('datalist').innerHTML=result.files.map(file=>`<option value="${esc(file.name)}">${(file.size/1048576).toFixed(1)} MiB${file.within_limit?'':' · prepare a slice'}</option>`).join('');dialog.querySelector('input').placeholder='Choose a CSV from the publisher’s listing';const bounded=result.files.find(file=>file.within_limit);if(bounded)dialog.querySelector('input').value=bounded.name;}catch(error){if(dialog.isConnected){dialog.querySelector('input').placeholder='Copy the exact CSV path from the publisher';inlineError(dialog,error);}}
}

function replayDialog() {
  const descriptions={'identity-to-ot':'Nested privilege drift, an engineering logon, and a simulated tank anomaly.','credential-access':'Sensitive permission change, directory replication, and memory-dump telemetry.','password-spray':'Failed authentication against several lab accounts from a shared source.','persistence':'Remote-service and scheduled-task telemetry with synthetic marker commands.','benign-admin':'An approved administrator change with a ticket, plus a benign deployment signal.'};
  const dialog=modal(`${modalHeader('A repeatable lab moment.','Generate labelled telemetry and validate the real detection pipeline.')}<form id="replay-form"><div class="modal-body"><div class="form-field"><label for="replay-scenario">Scenario</label><select id="replay-scenario">${data.scenarios.map(name=>`<option value="${name}">${title(name)}</option>`).join('')}</select></div><div class="inline-note" id="scenario-description">${esc(descriptions[data.scenarios[0]])}</div><p class="muted" style="font-size:10px;margin-top:16px">This generates controlled synthetic events. It executes no VM commands, exploits, or physical-controller writes.</p><div data-form-message></div></div><footer class="modal-footer"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-primary" type="submit">${icon('play',12)}Replay scenario</button></footer></form>`);
  const select=dialog.querySelector('select');select.addEventListener('change',()=>dialog.querySelector('#scenario-description').textContent=descriptions[select.value]);
  dialog.querySelector('form').addEventListener('submit',async event=>{event.preventDefault();const button=event.target.querySelector('[type="submit"]');button.disabled=true;try{const result=await api('/api/lab/replay',{method:'POST',body:{scenario:select.value}});closeModal();await load();toast(`${result.event_count} new labelled events replayed through detection.`);}catch(error){inlineError(dialog,error);}finally{button.disabled=false;}});
}

async function previewFinding(id) {
  const result=await api('/api/identity/preview',{method:'POST',body:{finding_id:id}});
  modal(`${modalHeader('Understand the impact first.','Read-only permission-snapshot preview.')}<div class="modal-body"><div class="key-value"><dt>Finding</dt><dd>${esc(result.finding.user_name)} · ${esc(title(result.finding.right))}</dd></div><div class="key-value"><dt>Grant</dt><dd><code>${esc(result.removed_grant)}</code></dd></div><div class="key-value"><dt>Before / after</dt><dd>${result.before.length} discrepancies → ${result.after.length} after removing this entire grant</dd></div><div class="key-value"><dt>Affected users</dt><dd>${result.affected_users.map(user=>esc(user)).join(', ')}</dd></div><div class="inline-note">${esc(result.recommendation)}</div><div class="inline-note">${esc(result.mode)}. Validate legitimate access as well as the unwanted path.</div></div><footer class="modal-footer"><button class="btn btn-primary" data-close>Understood</button></footer>`);
}

async function importSnapshot() {
  const input=document.createElement('input');input.type='file';input.accept='.json';
  input.addEventListener('change',async()=>{const file=input.files[0];if(!file)return;try{if(file.size>2*1024*1024)throw new Error('Snapshot limit is 2 MiB.');await api('/api/identity/snapshot',{method:'POST',body:JSON.parse(await file.text())});selectedFinding=null;await load();toast('Snapshot imported and audited.');}catch(error){toast(error.message,true);}});input.click();
}

function settingsDialog() {
  const dialog=modal(`${modalHeader('A considered setup.','The Go server owns credentials. The browser only sees configuration status.')}<div class="modal-body"><div class="form-field"><label for="analyst-name">Your reviewer name</label><input class="input" id="analyst-name" value="${esc(analystName)}"></div><dl><div class="key-value"><dt>Inference</dt><dd>${esc(data.ai.provider)} · <code>${esc(data.ai.model)}</code></dd></div><div class="key-value"><dt>Endpoint</dt><dd>${esc(data.ai.host)}</dd></div><div class="key-value"><dt>Credential</dt><dd>${data.ai.configured?'Configured; live validity is checked separately':'Not configured'}</dd></div><div class="key-value"><dt>Kaggle</dt><dd>${data.kaggle_configured?'Server credential configured':'Token not present'}</dd></div></dl><div class="code-block"># Set these in the ignored .env file, then restart:
AGENT_ROUTER_API_KEY=&lt;your replacement key&gt;
IDENTITYSHIELD_AI_MODEL=gpt-6.1-sol
AGENT_ROUTER_BASE_URL=https://agentrouter.org/v1

# Optional genuinely local inference:
IDENTITYSHIELD_AI_PROVIDER=ollama
IDENTITYSHIELD_AI_MODEL=qwen3:8b
IDENTITYSHIELD_AI_BASE_URL=http://127.0.0.1:11434/v1</div><p class="muted" style="font-size:11px;line-height:1.8">Agent Router is cloud inference. Selected incident evidence leaves this machine when you generate an AI report. Local evidence briefs are deterministic and work offline.</p><div data-form-message></div></div><footer class="modal-footer"><button class="btn" id="check-provider">${icon('activity',12)}Check connection</button><button class="btn btn-primary" id="save-settings">Save preferences</button></footer>`);
  dialog.querySelector('#save-settings').addEventListener('click',()=>{analystName=dialog.querySelector('#analyst-name').value.trim()||'analyst';try{localStorage.setItem('identityshield-analyst',analystName);}catch{}closeModal();toast('Reviewer preferences saved.');});
  dialog.querySelector('#check-provider').addEventListener('click',async event=>{const button=event.currentTarget;button.disabled=true;try{const result=await api('/api/ai/check',{method:'POST'});dialog.querySelector('[data-form-message]').innerHTML=`<div class="inline-success">Connected to ${esc(result.provider)} · ${esc(result.model)}.</div>`;}catch(error){inlineError(dialog,error);}finally{button.disabled=false;}});
}

let browserEvents=[];
async function evidenceBrowser() {
  const dialog=modal(`${modalHeader('The evidence browser.','Inspect original records and review their labels individually.')}<div class="modal-body"><div class="toolbar"><div class="search-field">${icon('search',13)}<input id="event-search" placeholder="Search account, host, kind, or ID…" aria-label="Search evidence"></div><select class="select" id="event-label" aria-label="Filter event label"><option value="">All labels</option><option value="unknown">Unknown</option><option value="benign">Benign</option><option value="malicious">Malicious</option></select></div><div id="evidence-table">Loading records…</div><div data-form-message></div></div><footer class="modal-footer"><button class="btn" data-close>Close</button><button class="btn" data-action="export-events">${icon('download',12)}Export JSONL</button></footer>`,'modal');
  async function refresh(){try{const result=await api(`/api/events?q=${encodeURIComponent(dialog.querySelector('#event-search').value)}&label=${dialog.querySelector('#event-label').value}`);if(!dialog.isConnected)return;browserEvents=result.events;dialog.querySelector('#evidence-table').innerHTML=`<p class="muted" style="font-size:10px;margin-bottom:12px">${result.total} matching records · first ${result.events.length}</p><div class="card">${result.events.map(event=>`<button class="finding-row" data-event="${esc(event.id)}"><span class="finding-copy"><strong>${esc(event.actor)} <span class="muted">· ${esc(title(event.kind))}</span></strong><p>${esc(event.host)} · ${date(event.timestamp)} ${utc(event.timestamp)} UTC</p></span><span class="badge ${event.label==='benign'?'good':''}">${esc(event.label)}</span>${icon('chevron',12)}</button>`).join('')||empty('No records in this view','Change the filter or import another source.')}</div>`;}catch(error){inlineError(dialog,error);}}
  let timer;dialog.querySelector('#event-search').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(refresh,200);});dialog.querySelector('#event-label').addEventListener('change',refresh);await refresh();
}
let inspectedEvent;
async function inspectEvent(id) {
  inspectedEvent=activeIncident?.events.find(event=>event.id===id)||browserEvents.find(event=>event.id===id);
  if(!inspectedEvent){const result=await api(`/api/events?q=${encodeURIComponent(id)}`);inspectedEvent=result.events.find(event=>event.id===id);}
  if(!inspectedEvent) throw new Error('Evidence record not found.');
  const event=inspectedEvent;
  const dialog=modal(`${modalHeader('An original record.',esc(event.id))}<div class="modal-body"><dl>${[['Observed',new Date(event.timestamp).toISOString()],['Actor',event.actor],['Host',event.host],['Kind',event.kind],['Label',event.label],['Source',event.source],['Run / day',event.run_id],['Raw SHA',event.raw_sha256]].map(([key,value])=>`<div class="key-value"><dt>${key}</dt><dd class="mono">${esc(value||'—')}</dd></div>`).join('')}</dl><pre class="code-block">${esc(JSON.stringify(event.data,null,2))}</pre><details><summary class="muted" style="font-size:11px;cursor:pointer">Preserved raw evidence</summary><pre class="code-block">${esc(event.raw||'No original raw payload was supplied.')}</pre></details></div><footer class="modal-footer"><button class="btn" data-close>Close</button><button class="btn" id="copy-record">${icon('copy',12)}Copy record</button><button class="btn btn-primary" data-action="label-event">Review label</button></footer>`);
  dialog.querySelector('#copy-record').addEventListener('click',()=>copy(JSON.stringify(event,null,2)));
}
function labelEvent() {
  const event=inspectedEvent;
  const dialog=modal(`${modalHeader('Label one piece of evidence.','A reviewer and an independent reason are required.')}<form><div class="modal-body"><div class="form-field"><label for="event-new-label">Ground-truth label</label><select id="event-new-label" name="label">${['unknown','benign','malicious'].map(label=>`<option value="${label}" ${event.label===label?'selected':''}>${title(label)}</option>`).join('')}</select></div><div class="form-field"><label for="label-reason">Independent evidence supporting this label</label><textarea class="textarea" id="label-reason" name="reason" required placeholder="Use scenario logs or independently verified incident evidence, not the detector’s output."></textarea></div><div class="form-field"><label for="label-reviewer">Reviewer</label><input class="input" name="reviewer" id="label-reviewer" value="${esc(analystName)}" required></div><div data-form-message></div></div><footer class="modal-footer"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-primary" type="submit">Save reviewed label</button></footer></form>`);
  dialog.querySelector('form').addEventListener('submit',async submission=>{submission.preventDefault();try{await api(`/api/events/${encodeURIComponent(event.id)}/label`,{method:'POST',body:Object.fromEntries(new FormData(submission.target))});closeModal();await load();toast('Event label and provenance counts updated. Retrain to evaluate the new labels.');}catch(error){inlineError(dialog,error);}});
}

async function copy(value) {try{await navigator.clipboard.writeText(value);toast('Copied to clipboard.');}catch{toast('Clipboard access is unavailable in this browser.',true);}}
function downloadData(value,filename) {const blob=new Blob([JSON.stringify(value,null,2)],{type:'application/json'});downloadBlob(blob,filename);}
function downloadBlob(blob,filename) {const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function downloadEndpoint(path,filename) {const headers={};if(accessToken)headers.Authorization=`Bearer ${accessToken}`;const response=await fetch(path,{headers});if(!response.ok){const error=await response.json();throw new Error(error.error ||'Export failed');}downloadBlob(await response.blob(),filename);}

function authenticate() {
  if(document.querySelector('#access-form')) return;
  const dialog=modal(`${modalHeader('Your workspace access.','This server requires its configured workspace bearer token.')}<form id="access-form"><div class="modal-body"><div class="form-field"><label for="access-token">Workspace access token</label><input class="input" id="access-token" type="password" autocomplete="off" required></div><div data-form-message></div></div><footer class="modal-footer"><button class="btn btn-primary" type="submit">Open workspace ${icon('arrow',12)}</button></footer></form>`);
  dialog.querySelector('form').addEventListener('submit',async event=>{event.preventDefault();accessToken=dialog.querySelector('input').value;try{await api('/api/state');try{sessionStorage.setItem('identityshield-access',accessToken);}catch{}closeModal();shellReady=false;await load();}catch(error){inlineError(dialog,error);}});
}

document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k'&&data){event.preventDefault();openPalette();}});
document.addEventListener('click',async event=>{
  const target=event.target.closest('button,a');if(!target) return;
  if(target.hasAttribute('data-close')){event.preventDefault();closeModal();return;}
  if(target.dataset.route){if(event.metaKey||event.ctrlKey||event.shiftKey)return;event.preventDefault();navigate(target.dataset.route);return;}
  try {
    if(target.dataset.openCase){event.preventDefault();await openIncident(target.dataset.openCase);return;}
    if(target.dataset.finding){selectedFinding=target.dataset.finding;renderPage();return;}
    if(target.dataset.preview){await previewFinding(target.dataset.preview);return;}
    if(target.dataset.fetch){await fetchSource(target.dataset.fetch,target);return;}
    if(target.dataset.importSource){openImport(target.dataset.importSource);return;}
    if(target.dataset.sourceInfo){sourceInfo(target.dataset.sourceInfo);return;}
    if(target.dataset.manifest){manifest(target.dataset.manifest);return;}
    if(target.dataset.event){await inspectEvent(target.dataset.event);return;}
    if(target.dataset.citation){const element=document.querySelector(`[data-event-id="${CSS.escape(target.dataset.citation)}"]`);if(element){element.scrollIntoView({behavior:'smooth',block:'center'});element.classList.add('highlight');setTimeout(()=>element.classList.remove('highlight'),1800);}return;}
    if(target.dataset.status){caseFilter.status=target.dataset.status;renderPage();return;}
    if(target.dataset.domain){researchDomain=target.dataset.domain;renderPage();return;}
    if(target.dataset.ruleCases){caseFilter={q:'',status:'all',severity:'',rule:target.dataset.ruleCases};navigate('/investigations');return;}
    if(target.dataset.toggleRule){target.disabled=true;await api(`/api/rules/${target.dataset.toggleRule}`,{method:'POST',body:{enabled:target.getAttribute('aria-checked')!=='true'}});await load();toast('Rule configuration saved and detections recomputed.');return;}
    switch(target.dataset.action){
      case 'reload': shellReady=false;await load();break;
      case 'search': openPalette();break;
      case 'theme': {const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('identityshield-theme',theme);}catch{}target.innerHTML=icon(theme==='dark'?'sun':'moon',17);break;}
      case 'settings':settingsDialog();break;
      case 'import':openImport();break;
      case 'kaggle':await kaggleDialog();break;
      case 'replay':replayDialog();break;
      case 'identity':navigate('/identity');break;
      case 'rules':navigate('/rules');break;
      case 'investigations':caseFilter.rule='';navigate('/investigations');break;
      case 'first-incident':if(data.incidents.length)await openIncident(data.incidents[0].id);else navigate('/investigations');break;
      case 'more-cases':caseLimit+=30;document.querySelector('#case-table').innerHTML=caseTable();break;
      case 'evidence':await evidenceBrowser();break;
      case 'generate-report':await generateReport(data.ai.provider);break;
      case 'save-brief':await generateReport('local');break;
      case 'export-report':await downloadEndpoint(`/api/export/report/${activeIncident.incident.id}`,activeIncident.incident.id+'-report.md');break;
      case 'copy-bundle':await copy(JSON.stringify(activeIncident.events,null,2));break;
      case 'review-case':reviewCase();break;
      case 'label-event':labelEvent();break;
      case 'export-events':await downloadEndpoint('/api/export/events','identityshield-evidence.jsonl');break;
      case 'export-snapshot':downloadData(data.snapshot,'identityshield-permission-snapshot.json');break;
      case 'import-snapshot':await importSnapshot();break;
      case 'export-model':if(data.models[researchDomain])await downloadEndpoint(`/api/export/model/${researchDomain}`,`identityshield-${researchDomain}-model.json`);else toast('Train an experiment first.',true);break;
      case 'train': {const label=target.innerHTML;target.disabled=true;target.innerHTML='<span class="loading-dots"><i></i><i></i><i></i></span>Training & evaluating';try{await api('/api/research/train',{method:'POST',body:{domain:researchDomain,dataset_id:researchDataset}});await load();toast('Forest trained. Held-out results and reproducibility record saved.');}finally{if(target.isConnected){target.disabled=false;target.innerHTML=label;}}break;}
    }
  } catch(error){toast(error.message,true);if(target.isConnected)target.disabled=false;}
});

await load();
if(data&&!accessToken){
  const stream=new EventSource('/api/stream');
  stream.addEventListener('ready',()=>{online=true;updateConnection();});
  stream.addEventListener('heartbeat',()=>{online=true;updateConnection();});
  stream.addEventListener('change',()=>load(true));
  stream.onerror=()=>{online=false;updateConnection();};
}
setInterval(()=>{if(data&&!document.hidden)load(true);},30000);

/* ═══════════════════════════════════════════════════════════════
   CROSSFAULT — browser front end

   No framework, no build step, no runtime dependencies. The heavy
   lifting is done by the Go engine in engine.wasm; everything here
   is rendering and input.

   The one invariant worth stating: this file never simulates
   anything. It reads state out of the engine and draws it. If the
   UI shows a livelock, it is because the engine livelocked.
   ═══════════════════════════════════════════════════════════════ */
'use strict';

const NODE_POS = {
  'aws-a': { x: 150, y: 105, cloud: 'AWS' },
  'gcp-b': { x: 610, y: 105, cloud: 'GCP' },
  'gcp-c': { x: 380, y: 288, cloud: 'GCP' },
};
const R = 40;                 // node radius
const BOW = 30;               // how far each directed arc bows out
const SVG_NS = 'http://www.w3.org/2000/svg';

const state = {
  mode: 'crossfault',
  running: true,
  ticksPerSecond: 9,
  ready: false,
  timer: null,
};

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  }
  kids.forEach((c) => n.appendChild(c));
  return n;
};
const svgEl = (tag, attrs = {}) => {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};

/* ── engine boot ─────────────────────────────────────────────── */

/* Called from Go once the engine is initialised.
   Wrapped in try/catch because syscall/js converts a thrown JS exception into a
   Go panic that terminates the engine — the UI must never be able to kill it. */
window.onCrossfaultReady = () => {
  try {
    state.ready = true;
    const boot = $('boot');
    boot.classList.add('fading');
    setTimeout(() => { boot.hidden = true; }, 420);
    render();
  } catch (err) {
    console.error('crossfault: render failed on boot', err);
  }
};

async function boot() {
  if (!('WebAssembly' in window)) {
    $('boot').textContent = 'This page needs WebAssembly, which this browser does not support.';
    return;
  }
  const go = new Go();
  try {
    const result = await WebAssembly.instantiateStreaming(fetch('engine.wasm'), go.importObject);
    go.run(result.instance);
  } catch (err) {
    // instantiateStreaming needs the right MIME type; some static hosts get it
    // wrong. Fall back rather than showing a blank page.
    try {
      const bytes = await (await fetch('engine.wasm')).arrayBuffer();
      const result = await WebAssembly.instantiate(bytes, go.importObject);
      go.run(result.instance);
    } catch (err2) {
      $('boot').textContent = 'Could not load the consensus engine: ' + err2.message;
    }
  }
}

/* ── main loop ───────────────────────────────────────────────── */

/* The simulation clock is driven by setInterval, not requestAnimationFrame.
   rAF is paused entirely in a background or hidden tab, which would silently
   freeze the engine — the page would look alive but the cluster would not be
   running. setInterval is throttled when backgrounded but still fires, so the
   simulation keeps making progress and the tick counter stays honest. */
function startClock() {
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (!state.ready || !state.running) return;
    crossfaultStep(1);
    render();
  }, Math.round(1000 / state.ticksPerSecond));
}

function readState() {
  try { return JSON.parse(crossfaultState()); } catch { return null; }
}

/* ── render ──────────────────────────────────────────────────── */

function render() {
  const s = readState();
  if (!s || !s.nodes) return;
  // Defence in depth against the nil-slice-becomes-null trap; the Go side now
  // guarantees these, but a null here must never throw across the boundary.
  s.nodes = s.nodes || [];
  s.links = s.links || [];
  s.events = s.events || [];

  $('tick').textContent = s.tick;
  $('leaderread').textContent = s.stable ? s.leader : 'none';
  $('m-bumps').textContent = s.totalTermBumps;
  $('m-commit').textContent = s.maxCommit;
  $('m-rejected').textContent = s.totalRejected;
  $('m-relayed').textContent = s.relayed;

  renderTopology(s);
  renderNodes(s);
  renderMatrix(s);
  renderLog(s);
}

/* Topology: a directed graph where each ordered pair gets its own arc, so
   cutting A→B and cutting B→A are visibly different actions. That separation
   is the entire point of the demo — a single undirected line would hide the
   fault class being demonstrated. */
function renderTopology(s) {
  const svg = $('topology');
  svg.textContent = '';

  const defs = svgEl('defs');
  for (const [id, color] of [
    ['ah-up', 'var(--hair-2)'], ['ah-down', 'var(--accent)'],
    ['ah-asym', 'var(--accent-lit)'], ['ah-corrupt', 'var(--gold)'],
  ]) {
    const m = svgEl('marker', {
      id, viewBox: '0 0 10 10', refX: '9', refY: '5',
      markerWidth: '5', markerHeight: '5', orient: 'auto-start-reverse',
    });
    m.appendChild(svgEl('path', { d: 'M0,0 L10,5 L0,10 z', fill: color }));
    defs.appendChild(m);
  }
  svg.appendChild(defs);

  const roleOf = {};
  s.nodes.forEach((n) => { roleOf[n.id] = n; });

  for (const link of s.links) {
    const a = NODE_POS[link.from], b = NODE_POS[link.to];
    if (!a || !b) continue;

    const dx = b.x - a.x, dy = b.y - a.y;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len, uy = dy / len;
    const px = -uy, py = ux;                        // perpendicular

    const sx = a.x + ux * R + px * 9;
    const sy = a.y + uy * R + py * 9;
    const ex = b.x - ux * (R + 7) + px * 9;
    const ey = b.y - uy * (R + 7) + py * 9;
    const cx = (a.x + b.x) / 2 + px * BOW;
    const cy = (a.y + b.y) / 2 + py * BOW;
    const d = `M ${sx} ${sy} Q ${cx} ${cy} ${ex} ${ey}`;

    let cls = 'edge edge--up', marker = 'ah-up';
    if (link.corrupt) { cls = 'edge edge--corrupt'; marker = 'ah-corrupt'; }
    else if (link.down && link.asymmetry) { cls = 'edge edge--down edge--asym'; marker = 'ah-asym'; }
    else if (link.down) { cls = 'edge edge--down'; marker = 'ah-down'; }

    // Wide invisible hit area first, so thin arcs are still easy to click.
    const hit = svgEl('path', { d, class: 'edge-hit' });
    hit.addEventListener('click', () => toggleLink(link));
    hit.setAttribute('tabindex', '0');
    hit.setAttribute('role', 'button');
    hit.setAttribute('aria-label',
      `${link.down ? 'Restore' : 'Cut'} link from ${link.from} to ${link.to}`);
    hit.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleLink(link); }
    });
    svg.appendChild(hit);

    svg.appendChild(svgEl('path', { d, class: cls, 'marker-end': `url(#${marker})` }));
  }

  for (const [id, p] of Object.entries(NODE_POS)) {
    const n = roleOf[id];
    if (!n) continue;

    let cls = 'node';
    if (n.role === 'leader') cls += ' node--leader';
    else if (n.role === 'candidate' || n.role === 'precandidate') cls += ' node--candidate';
    if (!n.hasQuorum) cls += ' node--isolated';

    const g = svgEl('g', { class: cls });
    g.appendChild(svgEl('circle', { cx: p.x, cy: p.y, r: R, class: 'node-ring' }));

    const label = svgEl('text', { x: p.x, y: p.y - 4, class: 'node-label' });
    label.textContent = id;
    g.appendChild(label);

    const sub = svgEl('text', { x: p.x, y: p.y + 12, class: 'node-sub' });
    sub.textContent = `${n.role} · t${n.term}`;
    g.appendChild(sub);

    const cloud = svgEl('text', { x: p.x, y: p.y + 25, class: 'node-sub' });
    cloud.textContent = p.cloud;
    g.appendChild(cloud);

    svg.appendChild(g);
  }
}

function toggleLink(link) {
  if (link.down) crossfaultHeal(link.from, link.to);
  else crossfaultCut(link.from, link.to);
  render();
}

function renderNodes(s) {
  const box = $('nodes');
  box.textContent = '';

  for (const n of s.nodes) {
    let cls = 'noderow';
    if (n.role === 'leader') cls += ' noderow--leader';
    if (!n.hasQuorum) cls += ' noderow--isolated';

    const row = el('div', { class: cls });

    const left = el('div', {});
    left.appendChild(el('span', { class: 'noderow__id', text: n.id }));
    left.appendChild(el('span', { class: 'noderow__cloud', text: n.cloud }));
    row.appendChild(left);
    row.appendChild(el('span', { class: `pill pill--${n.role}`, text: n.role }));

    const stats = el('div', { class: 'noderow__stats' });
    const stat = (label, value) => {
      const s2 = el('span', { text: label + ' ' });
      s2.appendChild(el('b', { text: String(value) }));
      stats.appendChild(s2);
    };
    stat('term', n.term);
    stat('log', n.logLen);
    stat('commit', n.commitIndex);
    stat('bumps', n.termBumps);
    if (n.droppedBadSig) stat('rejected', n.droppedBadSig);
    if (n.declinedToRun) stat('declined', n.declinedToRun);
    row.appendChild(stats);

    box.appendChild(row);
  }
}

/* The matrix is the most informative panel: it shows ground truth AND what the
   sending node believes. A cell marked "blind" is a link that is really down
   while the sender still thinks it works — the state in which a partial
   partition does its damage, and the thing no ordinary health check reveals. */
function renderMatrix(s) {
  const ids = s.nodes.map((n) => n.id);
  const byPair = {};
  s.links.forEach((l) => { byPair[l.from + '>' + l.to] = l; });

  const table = el('table', { class: 'matrix' });

  const head = el('tr');
  head.appendChild(el('th', { class: 'rowhead', text: '' }));
  ids.forEach((id) => head.appendChild(el('th', { text: id })));
  table.appendChild(head);

  for (const from of ids) {
    const tr = el('tr');
    tr.appendChild(el('th', { class: 'rowhead', text: from }));

    for (const to of ids) {
      const td = el('td');
      if (from === to) {
        td.appendChild(el('div', { class: 'cell cell--self', text: '·' }));
      } else {
        const link = byPair[from + '>' + to];
        let cls = 'cell cell--up', glyph = '→';
        if (link) {
          if (link.corrupt) { cls = 'cell cell--corrupt'; glyph = '⚠'; }
          else if (link.down && link.believed) { cls = 'cell cell--blind'; glyph = '?'; }
          else if (link.down) { cls = 'cell cell--down'; glyph = '×'; }
        }
        const cell = el('div', { class: cls, text: glyph });
        cell.title = link && link.down
          ? (link.believed
              ? `${from} → ${to} is DOWN, but ${from} still believes it works`
              : `${from} → ${to} is down and ${from} knows it`)
          : `${from} → ${to} reachable`;
        td.appendChild(cell);
      }
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }

  const box = $('matrix');
  box.textContent = '';
  box.appendChild(table);
}

let lastLogKey = '';

function renderLog(s) {
  const box = $('log');
  const events = s.events.slice(-70);

  // Skip the rebuild when nothing new happened. Most ticks produce no events,
  // and tearing down 70 rows nine times a second for an unchanged list is both
  // wasteful and a source of layout churn.
  const key = events.length ? `${events.length}:${events[events.length - 1].tick}:${events[events.length - 1].kind}` : '0';
  if (key === lastLogKey) return;
  lastLogKey = key;

  box.textContent = '';
  for (const e of events) {
    const row = el('div', { class: 'log__row', 'data-kind': e.kind });
    row.appendChild(el('span', { class: 'log__t', text: 't' + e.tick }));
    row.appendChild(el('span', { class: 'log__node', text: e.node }));
    row.appendChild(el('span', { class: 'log__text', text: e.text }));
    box.appendChild(row);
  }
}

/* ── controls ────────────────────────────────────────────────── */

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll('.seg button').forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.mode === mode));
  });
  crossfaultReset(mode, 42);
  render();
}

let proposeCounter = 0;

function wireControls() {
  document.querySelectorAll('.seg button').forEach((b) => {
    b.addEventListener('click', () => setMode(b.dataset.mode));
  });

  $('playpause').addEventListener('click', (e) => {
    state.running = !state.running;
    e.target.textContent = state.running ? '⏸ pause' : '▶ run';
    e.target.setAttribute('aria-pressed', String(state.running));
  });

  $('stepbtn').addEventListener('click', () => { crossfaultStep(10); render(); });

  $('proposebtn').addEventListener('click', () => {
    const res = crossfaultPropose(`set k${++proposeCounter}=${Date.now() % 1000}`);
    if (res && res.ok === false) {
      // Honest failure: with no leader there is nowhere to send a write. Say so
      // rather than silently queueing it and implying progress.
      flash($('proposebtn'), 'no leader — write refused');
    }
    render();
  });

  $('cutbtn').addEventListener('click', () => {
    // The signature fault: aws-a can still SEND to everyone, but hears nothing.
    crossfaultCut('gcp-b', 'aws-a');
    crossfaultCut('gcp-c', 'aws-a');
    render();
  });

  $('resetbtn').addEventListener('click', () => { crossfaultReset(state.mode, 42); render(); });

  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === ' ') { e.preventDefault(); $('playpause').click(); }
    if (e.key === 's') $('stepbtn').click();
    if (e.key === 'r') $('resetbtn').click();
  });
}

function flash(btn, msg) {
  const original = btn.textContent;
  btn.textContent = msg;
  btn.disabled = true;
  setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 1400);
}

wireControls();
boot();
startClock();

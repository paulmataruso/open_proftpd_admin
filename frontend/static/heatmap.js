/*
 * Activity heatmap (weekday × hour, viewer's local timezone) + range picker.
 * Shared by index.html (admin "Busiest Times" pages) and public.html, so both
 * draw identically. Relies on the page's .chart-card / .range-tab / .sort-tab
 * styles and CSS variables; everything heatmap-specific is injected below.
 *
 *   const map = HeatmapUI.createMap(el, { label, source, path, fetchJson, kind?, noun?, onData? });
 *   const picker = HeatmapUI.createRangePicker(el, { initial: '30d', onChange: (query, label) => map.load(query, label) });
 *   map.load(picker.current().query, picker.current().label);
 *   const best = HeatmapUI.createBestTimes(el, [{ map, noun: 'download' }, ...], 'FTP');  // call best.update() from onData
 *
 * fetchJson(path) must resolve to { ok, data }. The backend
 * (/admin/logs/heatmap, /public/overview/heatmap) returns per-cell totals plus
 * how often each weekday/hour occurred in the range (slots), so cells show an
 * average per hour and stay comparable whatever the range.
 */
(function () {
  'use strict';

  const CSS = `
.hm-grid { display: grid; grid-template-columns: 2.4rem repeat(24, minmax(0, 1fr)) 14px 3.6rem; gap: 2px; font-family: var(--mono); font-size: 0.62rem; color: var(--text3); transition: opacity .2s; }
.hm-grid.loading { opacity: .45; }
.hm-grid .hl { display: flex; align-items: center; }
.hm-grid .hx { white-space: nowrap; overflow: visible; }
.hm-grid .hc { aspect-ratio: 1.35; min-height: 12px; border-radius: 2px; background: var(--bg3); }
.hm-grid .hc:hover { outline: 2px solid var(--text); outline-offset: -1px; }
.hm-grid .hc.peak:not(:hover) { outline: 1px solid var(--text); outline-offset: -1px; }
.hm-grid .hd, .hm-grid .hdl { border-left: 1px solid var(--border2); padding-left: 8px; }
.hm-grid .hd { display: flex; align-items: center; }
.hm-grid .hd i, .hm-grid .hh i { display: block; border-radius: 2px; }
.hm-grid .hd:hover i, .hm-grid .hh:hover i { outline: 1px solid var(--text); }
.hm-grid .hd i { height: 60%; }
.hm-grid .hgap { grid-column: 1 / -1; height: 12px; border-bottom: 1px solid var(--border2); margin-bottom: 6px; }
.hm-grid .hh { height: 34px; display: flex; align-items: flex-end; }
.hm-grid .hh i { width: 100%; }
.hm-grid .hml { color: var(--text3); font-size: 0.55rem; text-transform: uppercase; letter-spacing: 0.05em; }
.hm-empty { grid-column: 1 / -1; padding: 2rem 0; text-align: center; color: var(--text3); font-size: 0.8rem; font-family: var(--sans); }
.hm-sub { color: var(--text3); font-weight: 400; text-transform: none; letter-spacing: 0; font-size: 0.75rem; margin-left: 0.4rem; }
.hm-foot { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem 1rem; flex-wrap: wrap; margin-top: 0.75rem; font-size: 0.72rem; color: var(--text2); }
.hm-foot b { color: var(--text); font-weight: 600; }
.hm-scale { display: inline-flex; align-items: center; gap: 0.4rem; font-family: var(--mono); font-size: 0.62rem; color: var(--text3); }
.hm-scale .ramp { display: inline-block; width: 120px; height: 8px; border-radius: 2px; }
.hm-picker { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 0.5rem 0.75rem; }
.hm-custom { display: none; align-items: center; flex-wrap: wrap; gap: 0.4rem; font-size: 0.72rem; color: var(--text3); }
.hm-custom.show { display: inline-flex; }
.hm-custom input { color-scheme: dark; background: var(--bg3); border: 1px solid var(--border2); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: 0.72rem; padding: 0.2rem 0.4rem; }
.hm-custom input:focus { outline: none; border-color: var(--accent); }
.hm-custom .hm-err { color: var(--red); }
.hm-best-wrap { overflow-x: auto; }
.hm-best { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.hm-best th { text-align: left; font-size: 0.66rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text3); padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
.hm-best td { padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--border); color: var(--text2); white-space: nowrap; }
.hm-best tr:last-child td { border-bottom: none; }
.hm-best td.k { color: var(--text); font-weight: 600; font-family: var(--sans); }
.hm-best td.when { color: var(--text); font-family: var(--mono); }
.hm-best .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 0.5rem; vertical-align: 0; }
.hm-best-note { margin-top: 0.75rem; font-size: 0.7rem; color: var(--text3); line-height: 1.5; }
#hm-tip { position: fixed; z-index: 1000; pointer-events: none; display: none; background: var(--bg2); border: 1px solid var(--border2); border-radius: var(--radius); padding: 0.5rem 0.65rem; font-size: 0.75rem; color: var(--text2); line-height: 1.45; box-shadow: 0 4px 16px rgba(0,0,0,.4); max-width: 280px; }
#hm-tip b { color: var(--text); font-weight: 600; }
@media (max-width: 600px) { .hm-grid { grid-template-columns: 1.9rem repeat(24, minmax(0, 1fr)) 8px 2.4rem; gap: 1px; font-size: 0.55rem; } }
`;

  function injectCss() {
    if (document.getElementById('hm-css')) return;
    const s = document.createElement('style');
    s.id = 'hm-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  const TZ = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })();
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  // Green (quiet) → yellow → orange → red (busy), interpolated in sRGB.
  const STOPS = [[0, [22, 163, 74]], [0.35, [132, 204, 22]], [0.6, [234, 179, 8]], [0.8, [249, 115, 22]], [1, [220, 38, 38]]];
  function heatColor(t) {
    t = Math.max(0, Math.min(1, t));
    for (let i = 1; i < STOPS.length; i++) {
      const [t1, c1] = STOPS[i];
      if (t <= t1) {
        const [t0, c0] = STOPS[i - 1];
        const f = (t - t0) / (t1 - t0);
        return `rgb(${c0.map((v, k) => Math.round(v + (c1[k] - v) * f)).join(',')})`;
      }
    }
    return 'rgb(220,38,38)';
  }
  const RAMP_CSS = `linear-gradient(90deg, ${STOPS.map(([t]) => `${heatColor(t)} ${t * 100}%`).join(', ')})`;

  const fmtNum = n => (n == null ? '—' : Number(n).toLocaleString());
  function fmtBytes(b) {
    if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(u.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
    return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const hourLbl = h => String(h).padStart(2, '0') + ':00';
  const sum = a => a.reduce((x, y) => x + y, 0);
  const fmtVal = (v, isBytes) => isBytes ? fmtBytes(Math.round(v))
    : v >= 10 ? fmtNum(Math.round(v)) : (Math.round(v * 10) / 10).toLocaleString();

  // ── Map ────────────────────────────────────────────────────────────────────
  function createMap(el, opts) {
    injectCss();
    const noun = opts.noun || 'downloads';
    const Noun = noun[0].toUpperCase() + noun.slice(1);
    el.innerHTML = `
      <div class="chart-card">
        <h3><span>Busiest Times — ${esc(opts.label)}<span class="hm-sub"></span></span>
          <span class="sort-toggle-group">
            <button class="sort-tab active" data-metric="count">${Noun}</button>
            <button class="sort-tab" data-metric="bytes">Data</button>
          </span></h3>
        <div class="hm-grid"><div class="hm-empty">Loading…</div></div>
        <div class="hm-foot"><span class="hm-peak"></span>
          <span class="hm-scale">quiet <span class="ramp" style="background:${RAMP_CSS}"></span> busy</span></div>
      </div>`;
    const grid = el.querySelector('.hm-grid'), sub = el.querySelector('.hm-sub'), peakEl = el.querySelector('.hm-peak');
    const st = { data: null, label: '', metric: 'count', seq: 0, loading: false };

    el.querySelectorAll('[data-metric]').forEach(b => b.addEventListener('click', () => {
      st.metric = b.dataset.metric;
      el.querySelectorAll('[data-metric]').forEach(x => x.classList.toggle('active', x === b));
      render();
    }));
    grid.addEventListener('mousemove', ev => tip(ev));
    grid.addEventListener('mouseleave', () => { const t = document.getElementById('hm-tip'); if (t) t.style.display = 'none'; });

    async function load(query, label) {
      const seq = ++st.seq;  // drop responses from an older range
      st.label = label || '';
      st.loading = true;
      grid.classList.add('loading');
      try {
        const tzQS = TZ ? `&tz=${encodeURIComponent(TZ)}` : '';
        const kindQS = opts.kind ? `&kind=${opts.kind}` : '';
        const { ok, data } = await opts.fetchJson(`${opts.path}?source=${opts.source}${kindQS}${query ? '&' + query : ''}${tzQS}`);
        if (seq !== st.seq) return;
        if (!ok) throw new Error('heatmap');
        st.data = data;
        render();
      } catch (e) {
        if (seq === st.seq) { st.data = null; grid.innerHTML = '<div class="hm-empty">Failed to load</div>'; peakEl.textContent = ''; }
      } finally {
        if (seq === st.seq) {
          st.loading = false;
          grid.classList.remove('loading');
          if (opts.onData) opts.onData(st.data);
        }
      }
    }

    function view() {
      const d = st.data, isBytes = st.metric === 'bytes';
      const raw = isBytes ? d.bytes : d.count;
      return { d, isBytes, raw, grand: (isBytes ? d.total_bytes : d.total) || 0, unit: isBytes ? '/hr' : ` ${noun}/hr` };
    }

    function render() {
      if (!st.data) return;
      const { d, isBytes, raw, grand, unit } = view();
      sub.textContent = `${st.label}${st.label ? ' · ' : ''}${d.tz}`;
      if (!grand) {
        grid.innerHTML = `<div class="hm-empty">No ${noun} in this range</div>`;
        peakEl.textContent = '';
        return;
      }
      const avg = raw.map((row, i) => row.map((v, h) => d.slots[i][h] ? v / d.slots[i][h] : 0));
      let max = 0, peak = [0, 0];
      avg.forEach((row, i) => row.forEach((v, h) => { if (v > max) { max = v; peak = [i, h]; } }));
      // Colour scales to the 95th percentile (cells above it are full red):
      // traffic is bursty, and one 10× outlier hour would wash out the grid.
      const nz = avg.flat().filter(v => v > 0).sort((a, b) => a - b);
      const scaleMax = nz[Math.floor(0.95 * (nz.length - 1))] || max;
      // Margins: average per weekday (right) and per hour across all days (bottom).
      const dayAvg = raw.map((row, i) => { const n = sum(d.slots[i]) / 24; return n ? sum(row) / n : 0; });
      const hourAvg = [...Array(24).keys()].map(h => { const n = sum(d.slots.map(r => r[h])); return n ? sum(raw.map(r => r[h])) / n : 0; });
      const dayMax = Math.max(...dayAvg) || 1, hourMax = Math.max(...hourAvg) || 1;
      const hasHour = hourAvg.map((_, h) => sum(d.slots.map(r => r[h])) > 0);
      const busiestDay = dayAvg.indexOf(Math.max(...dayAvg));
      const busiestHour = hourAvg.indexOf(Math.max(...hourAvg));
      const quietHour = hourAvg.reduce((q, v, h) => (hasHour[h] && (q < 0 || v < hourAvg[q]) ? h : q), -1);

      let html = '<div></div>';
      for (let h = 0; h < 24; h++) html += `<div class="hx">${h % 3 === 0 ? String(h).padStart(2, '0') : ''}</div>`;
      html += '<div></div><div class="hx hdl hml">per day</div>';
      for (let i = 0; i < 7; i++) {
        html += `<div class="hl">${DAYS[i]}</div>`;
        for (let h = 0; h < 24; h++) {
          const v = avg[i][h];
          const bg = v > 0 ? ` style="background:${heatColor(v / scaleMax)}"` : '';
          html += `<div class="hc${i === peak[0] && h === peak[1] ? ' peak' : ''}" data-k="c" data-d="${i}" data-h="${h}"${bg}></div>`;
        }
        const t = dayAvg[i] / dayMax;
        html += `<div></div><div class="hd" data-k="d" data-d="${i}"><i style="width:${Math.max(2, Math.round(100 * t))}%;background:${heatColor(t)}"></i></div>`;
      }
      html += '<div class="hgap"></div><div class="hl hml">per hr</div>';
      for (let h = 0; h < 24; h++) {
        const t = hourAvg[h] / hourMax;
        html += `<div class="hh" data-k="h" data-h="${h}"><i style="height:${Math.max(2, Math.round(100 * t))}%;background:${heatColor(t)}"></i></div>`;
      }
      html += '<div></div><div></div>';
      grid.innerHTML = html;
      grid.setAttribute('aria-label', `Busiest ${DAYS[peak[0]]} ${hourLbl(peak[1])}, ${fmtVal(max, isBytes)}${unit}`);
      peakEl.innerHTML = `Peak <b>${DAYS[peak[0]]} ${hourLbl(peak[1])}</b> (${fmtVal(max, isBytes)}${unit})`
        + ` · busiest day <b>${DAYS[busiestDay]}</b> · busiest hour <b>${hourLbl(busiestHour)}</b>`
        + (quietHour >= 0 ? ` · quietest <b>${hourLbl(quietHour)}</b>` : '');
    }

    function tip(ev) {
      let t = document.getElementById('hm-tip');
      if (!t) { t = document.createElement('div'); t.id = 'hm-tip'; document.body.appendChild(t); }
      const cell = ev.target.closest('[data-k]');
      if (!cell || !st.data) { t.style.display = 'none'; return; }
      const { d, isBytes, raw, grand, unit } = view();
      const k = cell.dataset.k, i = +cell.dataset.d, h = +cell.dataset.h;
      let title, v, n;
      if (k === 'c') { title = `${DAYS[i]} ${hourLbl(h)}–${hourLbl((h + 1) % 24)}`; v = raw[i][h]; n = d.slots[i][h]; }
      else if (k === 'd') { title = `${DAYS[i]} (whole day)`; v = sum(raw[i]); n = sum(d.slots[i]); }
      else { title = `${hourLbl(h)}–${hourLbl((h + 1) % 24)} (all days)`; v = sum(raw.map(r => r[h])); n = sum(d.slots.map(r => r[h])); }
      const avgLine = !n ? 'not in this range'
        : k === 'd' ? `avg <b>${fmtVal(v / (n / 24), isBytes)}</b> per ${DAYS[i]}`
        : `avg <b>${fmtVal(v / n, isBytes)}</b>${unit}`;
      const total = isBytes ? fmtBytes(v) : `${fmtNum(v)} ${noun}`;
      t.innerHTML = `<b>${title}</b><br>${avgLine}<br>${total} total · ${(100 * v / (grand || 1)).toFixed(1)}% of all`;
      t.style.display = 'block';
      const r = t.getBoundingClientRect();
      let x = ev.clientX + 14, y = ev.clientY + 14;
      if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - 14;
      if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - 14;
      t.style.left = x + 'px'; t.style.top = y + 'px';
    }

    return { load, render, data: () => st.data, label: () => st.label, loading: () => st.loading };
  }

  // ── Best / worst times table ───────────────────────────────────────────────
  // rows: [{ map, noun: 'download' }]. "Best" = the weekday/hour with the least
  // data moved (least load, so the fastest transfers), "worst" = the most. Ties
  // (e.g. the many hours with no uploads at all) go to the slot with the least
  // traffic on the other maps. Only slots that occurred in the range count.
  function createBestTimes(el, rows, title) {
    injectCss();
    el.innerHTML = `
      <div class="chart-card">
        <h3><span>Best &amp; Worst Times${title ? ' — ' + esc(title) : ''}<span class="hm-sub"></span></span></h3>
        <div class="hm-best-wrap"><table class="hm-best">
          <thead><tr><th></th><th>Day &amp; hour</th><th>Average then</th><th>Day overall</th><th>Hour overall</th></tr></thead>
          <tbody><tr><td colspan="5" style="text-align:center;color:var(--text3)">Loading…</td></tr></tbody>
        </table></div>
        <div class="hm-best-note">Best = least data transferred at that time (least load on the server, so usually the fastest);
          worst = the most. Averages per hour over the selected range, in your local time.</div>
      </div>`;
    const tbody = el.querySelector('tbody'), sub = el.querySelector('.hm-sub');

    // Average bytes / transfers per hour for each weekday/hour cell; null where the slot never occurred.
    const cellAvg = d => d.bytes.map((row, i) => row.map((b, h) => d.slots[i][h]
      ? { b: b / d.slots[i][h], n: d.count[i][h] / d.slots[i][h] } : null));
    const pick = (cands, worst) => cands.reduce((best, c) => {
      if (!best) return c;
      const s = worst ? -1 : 1;
      if (c.v !== best.v) return s * (c.v - best.v) < 0 ? c : best;
      return s * (c.tie - best.tie) < 0 ? c : best;
    }, null);

    function update() {
      if (rows.some(r => r.map.loading())) return;  // wait until every map shows the same range
      const ds = rows.map(r => r.map.data());
      const d0 = ds.find(Boolean);
      if (!d0) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text3)">No data</td></tr>'; return; }
      const label = rows.map(r => r.map.label()).find(Boolean) || '';
      sub.textContent = `${label}${label ? ' · ' : ''}${d0.tz}`;
      const avgs = ds.map(d => d && cellAvg(d));
      // Other maps' load at a cell / day / hour, for tie-breaks.
      const otherCell = (k, i, h) => sum(avgs.map((a, j) => (j !== k && a && a[i][h]) ? a[i][h].b : 0));

      let html = '';
      rows.forEach((r, k) => {
        const d = ds[k], a = avgs[k];
        const nounPl = r.noun + 's';
        if (!d) { html += `<tr><td class="k" colspan="5">${esc(r.noun)}: failed to load</td></tr>`; return; }
        const cells = [];
        for (let i = 0; i < 7; i++) for (let h = 0; h < 24; h++)
          if (a[i][h]) cells.push({ i, h, v: a[i][h].b, n: a[i][h].n, tie: otherCell(k, i, h) });
        const days = [...Array(7).keys()].map(i => {
          const n = sum(d.slots[i]) / 24;
          return n ? { i, v: sum(d.bytes[i]) / n, tie: sum(d.count[i]) / n } : null;
        }).filter(Boolean);
        const hours = [...Array(24).keys()].map(h => {
          const n = sum(d.slots.map(x => x[h]));
          return n ? { h, v: sum(d.bytes.map(x => x[h])) / n, tie: sum(d.count.map(x => x[h])) / n } : null;
        }).filter(Boolean);
        if (!cells.length) { html += `<tr><td class="k" colspan="5">No ${esc(nounPl)} in this range</td></tr>`; return; }
        [false, true].forEach(worst => {
          const c = pick(cells, worst), dy = pick(days, worst), hr = pick(hours, worst);
          const colour = worst ? heatColor(1) : heatColor(0);
          html += `<tr>
            <td class="k"><span class="dot" style="background:${colour}"></span>${worst ? 'Worst' : 'Best'} time to ${esc(r.noun)}</td>
            <td class="when">${DAYS[c.i]} ${hourLbl(c.h)}–${hourLbl((c.h + 1) % 24)}</td>
            <td>${fmtBytes(Math.round(c.v))}/hr · ${fmtVal(c.n, false)} ${esc(nounPl)}/hr</td>
            <td class="when">${dy ? DAYS[dy.i] : '—'}</td>
            <td class="when">${hr ? `${hourLbl(hr.h)}–${hourLbl((hr.h + 1) % 24)}` : '—'}</td>
          </tr>`;
        });
      });
      tbody.innerHTML = html;
    }

    return { update };
  }

  // ── Range picker: presets + custom From/To ─────────────────────────────────
  const PRESETS = [
    ['24h', 'days=1', 'last 24 hours'], ['7d', 'days=7', 'last 7 days'], ['30d', 'days=30', 'last 30 days'],
    ['90d', 'days=90', 'last 90 days'], ['1y', 'days=365', 'last year'], ['All', '', 'all available history'],
  ];
  const toLocalInput = d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const fmtWhen = d => d.toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  function createRangePicker(el, opts) {
    injectCss();
    const initial = PRESETS.find(p => p[0] === opts.initial) || PRESETS[2];
    let cur = { key: initial[0], query: initial[1], label: initial[2] };
    const now = new Date();
    el.innerHTML = `
      <div class="hm-picker">
        <div class="range-tabs">
          ${PRESETS.map(p => `<button class="range-tab" data-key="${p[0]}">${p[0]}</button>`).join('')}
          <button class="range-tab" data-key="custom">Custom…</button>
        </div>
        <div class="hm-custom">
          <span>From</span><input type="datetime-local" class="hm-from" value="${toLocalInput(new Date(now - 7 * 86400000))}">
          <span>to</span><input type="datetime-local" class="hm-to" value="${toLocalInput(now)}">
          <button class="range-tab hm-apply">Apply</button>
          <span class="hm-err"></span>
        </div>
      </div>`;
    const custom = el.querySelector('.hm-custom'), err = el.querySelector('.hm-err');
    const from = el.querySelector('.hm-from'), to = el.querySelector('.hm-to');
    const mark = key => el.querySelectorAll('[data-key]').forEach(b => b.classList.toggle('active', b.dataset.key === key));
    mark(cur.key);

    el.querySelectorAll('[data-key]').forEach(b => b.addEventListener('click', () => {
      if (b.dataset.key === 'custom') { custom.classList.toggle('show'); return; }
      const p = PRESETS.find(x => x[0] === b.dataset.key);
      custom.classList.remove('show');
      cur = { key: p[0], query: p[1], label: p[2] };
      mark(cur.key);
      opts.onChange(cur.query, cur.label);
    }));
    const apply = () => {
      const f = new Date(from.value), t = to.value ? new Date(to.value) : new Date();
      if (isNaN(f) || isNaN(t)) { err.textContent = 'Pick both dates'; return; }
      if (f >= t) { err.textContent = '"From" must be before "to"'; return; }
      err.textContent = '';
      cur = { key: 'custom', query: `start=${encodeURIComponent(f.toISOString())}&end=${encodeURIComponent(t.toISOString())}`, label: `${fmtWhen(f)} → ${fmtWhen(t)}` };
      mark('custom');
      opts.onChange(cur.query, cur.label);
    };
    el.querySelector('.hm-apply').addEventListener('click', apply);
    [from, to].forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') apply(); }));

    return { current: () => cur, isCustom: () => cur.key === 'custom' };
  }

  window.HeatmapUI = { createMap, createRangePicker, createBestTimes };
})();

// history.js (Enhanced v2.0 Dashboard Engine)
// Custom Glass Dropdowns, live KPI metrics, search filtering, multi-verdict filter, empty state & exports

(function(){
  const grid = document.getElementById('historyGrid');
  const searchBox = document.getElementById('searchBox');
  const exportCsvBtn = document.getElementById('exportCsv');
  const exportJsonBtn = document.getElementById('exportJson');
  const exportMdBtn = document.getElementById('exportMd');
  const clearBtn = document.getElementById('clearAll');

  const metricTotal = document.getElementById('metricTotal');
  const metricMalicious = document.getElementById('metricMalicious');
  const metricSuspicious = document.getElementById('metricSuspicious');
  const metricClean = document.getElementById('metricClean');

  // Custom Glass Dropdown Elements
  const typeTrigger = document.getElementById('typeTrigger');
  const typeTriggerLabel = document.getElementById('typeTriggerLabel');
  const typeMenu = document.getElementById('typeMenu');
  let selectedType = 'all';

  const verdictTrigger = document.getElementById('verdictTrigger');
  const verdictTriggerLabel = document.getElementById('verdictTriggerLabel');
  const verdictMenu = document.getElementById('verdictMenu');
  let selectedVerdict = 'all';

  // Wire Custom Type Dropdown
  typeTrigger.addEventListener('click', (e) => {
    e.stopPropagation();
    verdictMenu.classList.remove('show');
    typeMenu.classList.toggle('show');
  });

  typeMenu.querySelectorAll('.custom-dropdown-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.stopPropagation();
      typeMenu.querySelectorAll('.custom-dropdown-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      selectedType = item.dataset.val;
      typeTriggerLabel.textContent = item.textContent;
      typeMenu.classList.remove('show');
      loadAll();
    });
  });

  // Wire Custom Verdict Dropdown
  verdictTrigger.addEventListener('click', (e) => {
    e.stopPropagation();
    typeMenu.classList.remove('show');
    verdictMenu.classList.toggle('show');
  });

  verdictMenu.querySelectorAll('.custom-dropdown-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.stopPropagation();
      verdictMenu.querySelectorAll('.custom-dropdown-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      selectedVerdict = item.dataset.val;
      verdictTriggerLabel.textContent = item.textContent;
      verdictMenu.classList.remove('show');
      loadAll();
    });
  });

  // Close dropdowns on outside click
  document.addEventListener('click', () => {
    typeMenu.classList.remove('show');
    verdictMenu.classList.remove('show');
  });

  function loadAll() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      let entries = Object.keys(cache)
        .filter(k => k && !k.includes('<') && !k.includes('html'))
        .map(k => ({ ioc: k, ...cache[k] }));
      entries.sort((a,b) => (b.ts || 0) - (a.ts || 0));

      updateMetrics(entries);
      filterAndRender(entries);
    });
  }

  function updateMetrics(entries) {
    let malicious = 0;
    let suspicious = 0;
    let clean = 0;

    entries.forEach(e => {
      const d = e.data || {};
      const m = d.malicious || 0;
      const s = d.suspicious || 0;
      if (m >= 5 || (m >= 1 && s >= 1)) malicious++;
      else if (m >= 1 || s >= 1) suspicious++;
      else clean++;
    });

    metricTotal.textContent = entries.length;
    metricMalicious.textContent = malicious;
    metricSuspicious.textContent = suspicious;
    metricClean.textContent = clean;
  }

  function filterAndRender(entries) {
    const q = searchBox.value.trim().toLowerCase();

    let filtered = entries.filter(e => {
      const d = e.data || {};
      const m = d.malicious || 0;
      const s = d.suspicious || 0;

      const matchQuery = !q || e.ioc.toLowerCase().includes(q) || JSON.stringify(d).toLowerCase().includes(q);
      const matchType = selectedType === 'all' || d.type === selectedType;

      let matchVerdict = true;
      if (selectedVerdict === 'malicious') matchVerdict = m >= 1;
      else if (selectedVerdict === 'suspicious') matchVerdict = s >= 1 && m < 5;
      else if (selectedVerdict === 'clean') matchVerdict = m === 0 && s === 0;

      return matchQuery && matchType && matchVerdict;
    });

    render(filtered);
  }

  function render(list) {
    grid.innerHTML = '';
    if (!list || !list.length) {
      grid.innerHTML = `
        <div class="empty-state-card">
          <div class="empty-icon-wrap">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          </div>
          <div class="empty-title">No Threat Intelligence History Found</div>
          <div class="empty-desc">Search an IOC in the extension popup or hover over highlighted indicators on web pages to populate your local threat repository.</div>
        </div>
      `;
      return;
    }

    list.forEach(item => {
      const d = item.data || {};
      const malicious = d.malicious || 0;
      const suspicious = d.suspicious || 0;
      const harmless = d.harmless || 0;
      const undetected = d.undetected || 0;
      const vendors = d.vendors || 0;
      const ts = item.ts ? new Date(item.ts).toLocaleString() : '—';

      let scoreBadge = `<span class="badge good">Clean</span>`;
      if (malicious >= 5) scoreBadge = `<span class="badge bad">Malicious (${malicious})</span>`;
      else if (malicious >= 1 || suspicious >= 1) scoreBadge = `<span class="badge warn">Suspicious (${malicious})</span>`;

      const tagsHtml = (d.tags && d.tags.length)
        ? `<div class="card-tags">${d.tags.map(t => `<span class="card-tag">${escapeHtml(t)}</span>`).join('')}</div>`
        : '';

      let typeIcon = '🌐';
      if (d.type === 'domain') typeIcon = '🔗';
      else if (d.type === 'hash') typeIcon = '🔑';
      else if (d.type === 'url') typeIcon = '⚡';

      const card = document.createElement('div');
      card.className = 'history-card';
      card.innerHTML = `
        <div>
          <div class="card-top">
            <div class="ioc-title-wrap">
              <div class="ioc-name">${typeIcon} ${escapeHtml(item.ioc)}</div>
              <div class="ioc-meta">${ts} ${d.type ? `• ${d.type.toUpperCase()}` : ''}</div>
            </div>
            ${scoreBadge}
          </div>

          <div style="margin-top:12px;" class="card-stats">
            <div class="stat-item">
              <span class="stat-lbl">Malicious</span>
              <span class="stat-val" style="color:#ff6b6b">${malicious}</span>
            </div>
            <div class="stat-item">
              <span class="stat-lbl">Suspicious</span>
              <span class="stat-val" style="color:#ffc107">${suspicious}</span>
            </div>
            <div class="stat-item">
              <span class="stat-lbl">Harmless</span>
              <span class="stat-val" style="color:#69f0ae">${harmless}</span>
            </div>
            <div class="stat-item">
              <span class="stat-lbl">Vendors</span>
              <span class="stat-val">${vendors}</span>
            </div>
          </div>

          ${d.asn ? `<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:8px;">${escapeHtml(d.asn)}</div>` : ''}
          ${tagsHtml}
        </div>

        <div style="display:flex;gap:8px">
          <button class="btn btn-gradient open-btn" data-ioc="${escapeHtml(item.ioc)}" style="flex:1">View on VT</button>
          <button class="btn btn-secondary copy-btn" data-ioc="${escapeHtml(item.ioc)}" style="flex:1">Copy IOC</button>
        </div>
      `;
      grid.appendChild(card);
    });

    grid.querySelectorAll('.open-btn').forEach(b => b.addEventListener('click', ev => {
      const ioc = ev.target.dataset.ioc;
      window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`, '_blank');
    }));

    grid.querySelectorAll('.copy-btn').forEach(b => b.addEventListener('click', ev => {
      const ioc = ev.target.dataset.ioc;
      navigator.clipboard.writeText(ioc).then(() => alert('Copied IOC to clipboard'));
    }));
  }

  // Export CSV
  function exportCsv() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      const rows = [['IOC', 'Type', 'Timestamp', 'Malicious', 'Suspicious', 'Harmless', 'Undetected', 'Vendors', 'ASN']];
      Object.keys(cache).forEach(k => {
        const e = cache[k];
        const d = e.data || {};
        rows.push([k, d.type||'unknown', new Date(e.ts).toISOString(), d.malicious||0, d.suspicious||0, d.harmless||0, d.undetected||0, d.vendors||0, d.asn||'']);
      });
      const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
      downloadFile(csv, 'vt_history.csv', 'text/csv');
    });
  }

  // Export JSON
  function exportJson() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      const jsonStr = JSON.stringify(cache, null, 2);
      downloadFile(jsonStr, 'vt_history.json', 'application/json');
    });
  }

  // Export Markdown SOC Incident Report
  function exportMarkdown() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      let md = `# VirusTotal Threat Intelligence Summary Report\n\n`;
      md += `*Generated:* ${new Date().toLocaleString()}\n\n`;
      md += `| Indicator of Compromise (IOC) | Type | Verdict | Malicious | Suspicious | Vendors | Last Scan |\n`;
      md += `|---|---|---|---|---|---|---|\n`;

      Object.keys(cache).forEach(k => {
        const e = cache[k];
        const d = e.data || {};
        const m = d.malicious || 0;
        const s = d.suspicious || 0;
        let verdict = 'Clean';
        if (m >= 5) verdict = '🔴 Malicious';
        else if (m >= 1 || s >= 1) verdict = '🟡 Suspicious';

        md += `| \`${k}\` | ${d.type || 'unknown'} | ${verdict} | ${m} | ${s} | ${d.vendors || 0} | ${d.date || 'N/A'} |\n`;
      });

      downloadFile(md, 'vt_threat_report.md', 'text/markdown');
    });
  }

  function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  clearBtn.addEventListener('click', () => {
    if (!confirm('Are you sure you want to clear all stored VirusTotal history and cache?')) return;
    chrome.storage.local.remove(['vt_cache'], () => { loadAll(); });
  });

  exportCsvBtn.addEventListener('click', exportCsv);
  exportJsonBtn.addEventListener('click', exportJson);
  exportMdBtn.addEventListener('click', exportMarkdown);

  searchBox.addEventListener('input', loadAll);

  function escapeHtml(s){ return String(s).replace(/[&<>"']/g,(m)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  loadAll();
})();

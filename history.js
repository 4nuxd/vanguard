// history.js - simple history viewer/admin (uses vt_cache in storage)

(function(){
  const grid = document.getElementById('historyGrid');
  const searchBox = document.getElementById('searchBox');
  const exportBtn = document.getElementById('exportCsv');
  const clearBtn = document.getElementById('clearAll');

  function loadAll() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      let entries = Object.keys(cache).map(k => ({ ioc: k, ...cache[k] }));
      entries.sort((a,b) => b.ts - a.ts);
      render(entries);
    });
  }

  function render(list) {
    grid.innerHTML = '';
    if (!list || !list.length) {
      grid.innerHTML = '<div style="color:var(--muted)">No history found.</div>';
      return;
    }

    list.forEach(item => {
      const s = item.data;
      const stats = s && s.malicious !== undefined ? s : (s && s.stats ? s.stats : null);
      const vendors = stats && stats.vendors !== undefined ? stats.vendors : (s && s.raw && s.raw.data && s.raw.data[0] && s.raw.data[0].attributes && s.raw.data[0].attributes.last_analysis_results ? Object.keys(s.raw.data[0].attributes.last_analysis_results).length : 'N/A');
      const ts = item.ts ? new Date(item.ts).toLocaleString() : '—';

      const card = document.createElement('div');
      card.className = 'history-card';
      card.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-weight:700">${escapeHtml(item.ioc)}</div>
          <div style="font-size:12px;color:var(--muted)">${ts}</div>
        </div>
        <div style="margin-top:8px">
          <div style="font-size:13px">Vendors: ${vendors}</div>
        </div>
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn btn-ghost open-btn" data-ioc="${escapeHtml(item.ioc)}">Open VT</button>
          <button class="btn btn-secondary copy-btn" data-ioc="${escapeHtml(item.ioc)}">Copy IOC</button>
        </div>
      `;
      grid.appendChild(card);
    });

    grid.querySelectorAll('.open-btn').forEach(b => b.addEventListener('click', ev => {
      const ioc = ev.target.dataset.ioc; window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`, '_blank');
    }));
    grid.querySelectorAll('.copy-btn').forEach(b => b.addEventListener('click', ev => {
      const ioc = ev.target.dataset.ioc; navigator.clipboard.writeText(ioc).then(()=> alert('Copied'));
    }));
  }

  function exportCsv() {
    chrome.storage.local.get(['vt_cache'], res => {
      const cache = res.vt_cache || {};
      const rows = [['ioc','ts','malicious','suspicious','harmless','undetected','vendors']];
      Object.keys(cache).forEach(k => {
        const e = cache[k];
        const d = e.data || {};
        rows.push([k, new Date(e.ts).toISOString(), d.malicious||0, d.suspicious||0, d.harmless||0, d.undetected||0, d.vendors||0]);
      });
      const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'vt_history.csv'; a.click(); URL.revokeObjectURL(url);
    });
  }

  clearBtn.addEventListener('click', () => {
    if (!confirm('Clear all stored history and cache?')) return;
    chrome.storage.local.remove(['vt_cache','lastIOC'], () => { loadAll(); alert('Cleared'); });
  });

  exportBtn.addEventListener('click', exportCsv);

  searchBox.addEventListener('input', () => {
    const q = searchBox.value.trim().toLowerCase();
    chrome.storage.local.get(['vt_cache'], res => {
      let entries = Object.keys(res.vt_cache || {}).map(k => ({ ioc: k, ...res.vt_cache[k] }));
      entries.sort((a,b) => b.ts - a.ts);
      if (q) entries = entries.filter(e => e.ioc.toLowerCase().includes(q) || JSON.stringify(e.data).toLowerCase().includes(q));
      render(entries);
    });
  });

  function escapeHtml(s){ return String(s).replace(/[&<>"']/g,(m)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  loadAll();
})();

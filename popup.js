// popup.js (Full updated)
// Contains: settings dropdown, search (shimmer -> vtQuery), results, rescan in card, recent list, view history
document.addEventListener('DOMContentLoaded', () => {

  // Elements
  const panel = document.getElementById('settingsPanel');
  const menuBtn = document.getElementById('menuBtn');
  const closeBtn = document.getElementById('closeSettings');

  const apiInput = document.getElementById('apiInput');
  const saveBtn = document.getElementById('saveBtn');
  const testBtn = document.getElementById('testBtn');
  const clearBtn = document.getElementById('clearBtn');
  const keyStatus = document.getElementById('keyStatus');
  const autoToggle = document.getElementById('autoHighlightToggle');

  const searchBox = document.getElementById('searchBox');
  const searchResults = document.getElementById('searchResults');
  const recentList = document.getElementById('recentList');
  const viewAllBtn = document.getElementById('viewAllBtn');

  const toastRoot = document.getElementById('toast-root');

  // Toast
  function toast(msg, type='info') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    toastRoot.appendChild(t);
    setTimeout(() => t.remove(), 2400);
  }

  // escape
  function esc(s) { return (''+s).replace(/[&<>"]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m])); }

  // load cache array sorted
  function loadCache(cb) {
    chrome.storage.local.get(['vt_cache'], res => {
      const c = res.vt_cache || {};
      const arr = Object.keys(c).map(k => ({ ioc: k, ...c[k] }));
      arr.sort((a,b) => b.ts - a.ts);
      cb(arr);
    });
  }

  // vtQuery via background
  function vtQuery(ioc) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'vt_query', ioc }, res => resolve(res));
    });
  }

  // badge builder
  function badge(s) {
    if (!s) return `<span class="badge neutral">No data</span>`;
    if (s.malicious >= 5) return `<span class="badge bad">Malicious (${s.malicious})</span>`;
    if (s.malicious >= 1 || s.suspicious >= 1) return `<span class="badge warn">Suspicious (${s.malicious})</span>`;
    return `<span class="badge good">Clean</span>`;
  }

  // load recent
  function loadRecent() {
    loadCache(entries => {
      recentList.innerHTML = '';
      const last5 = entries.slice(0,5);
      if (!last5.length) {
        recentList.innerHTML = `<div class="empty">No recent lookups yet.</div>`;
        return;
      }
      last5.forEach(e => {
        const stats = e.data && e.data.stats;
        const row = document.createElement('div');
        row.className = 'recent-card';
        row.innerHTML = `
          <div>
            <div class="ioc-text">${esc(e.ioc)}</div>
            <div class="ioc-time">${new Date(e.ts).toLocaleString()}</div>
          </div>
          <div style="text-align:right">
            ${stats ? badge(stats) : '<span class="badge neutral">No data</span>'}
            <div style="margin-top:6px"><a href="#" class="small-link open" data-ioc="${esc(e.ioc)}">Open</a></div>
          </div>
        `;
        recentList.appendChild(row);
      });
      recentList.querySelectorAll('.open').forEach(el => {
        el.addEventListener('click', ev => {
          ev.preventDefault();
          window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(el.dataset.ioc), '_blank');
        });
      });
    });
  }

  // panel toggles
  function openPanel() { panel.classList.add('show'); }
  function closePanel() { panel.classList.remove('show'); }
  menuBtn.addEventListener('click', () => panel.classList.toggle('show'));
  closeBtn.addEventListener('click', closePanel);
  document.addEventListener('mousedown', e => {
    if (!e.target.closest('#settingsPanel') && !e.target.closest('#menuBtn')) closePanel();
  });

  // settings actions
  saveBtn.addEventListener('click', () => {
    const key = apiInput.value.trim();
    if (!key) { toast('Enter key', 'error'); return; }
    chrome.storage.local.set({ vt_api_key: key }, () => {
      apiInput.value = '';
      keyStatus.textContent = 'API key configured';
      toast('API key saved', 'success');
    });
  });

  testBtn.addEventListener('click', () => {
    chrome.storage.local.get(['vt_api_key'], res => {
      if (!res.vt_api_key) { toast('No API key', 'error'); return; }
      chrome.runtime.sendMessage({ type: 'vt_query', ioc: '8.8.8.8' }, r => {
        if (r?.error) toast('Invalid API key or error', 'error');
        else toast('Key OK', 'success');
      });
    });
  });

  clearBtn.addEventListener('click', () => {
    chrome.storage.local.remove(['vt_api_key','vt_cache'], () => {
      toast('Cleared key & cache', 'info');
      keyStatus.textContent = 'No key configured';
      loadRecent();
    });
  });

  autoToggle.addEventListener('change', () => {
    chrome.storage.local.set({ auto_highlight: autoToggle.checked });
  });

  // View all
  viewAllBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('history.html') });
  });

  // SHIMMER / loading UI
  function showLoading() {
    searchResults.style.display = 'block';
    searchResults.innerHTML = `
      <div class="search-info">Searching VirusTotal…</div>
      <div class="shimmer"></div>
      <div class="shimmer"></div>
    `;
  }

  // search behavior
  let timer = null;
  searchBox.addEventListener('input', () => {
    const q = searchBox.value.trim();
    if (timer) clearTimeout(timer);
    if (!q) { searchResults.style.display = 'none'; return; }
    showLoading();
    timer = setTimeout(() => searchLookup(q), 420);
  });

  // searchLookup - check cache then vtQuery if needed
  async function searchLookup(q) {
    loadCache(async (entries) => {
      const match = entries.find(e => e.ioc.toLowerCase() === q.toLowerCase());
      if (match) { renderThreatResults([match]); return; }

      // Not in cache → query VT
      const vt = await vtQuery(q);
      if (!vt || vt.error) {
        searchResults.innerHTML = `<div style="padding:8px;color:#999">No data from VirusTotal</div>`;
        return;
      }

      // Save cache (store `data` as stats object returned by background)
      chrome.storage.local.get(['vt_cache'], res => {
        const cache = res.vt_cache || {};
        cache[q] = { ts: Date.now(), data: vt };
        chrome.storage.local.set({ vt_cache: cache });
      });

      renderThreatResults([{ ioc: q, ts: Date.now(), data: vt }]);
    });
  }

  // render results with threat score and scan again
  function renderThreatResults(list) {
    if (!list || !list.length) {
      searchResults.innerHTML = `<div style="padding:8px;color:#aaa">No results</div>`;
      return;
    }
    searchResults.innerHTML = '';
    list.forEach(e => {
      const s = e.data && e.data.stats ? e.data.stats : e.data; // if background returned normalized or direct
      const malicious = s.malicious || 0;
      const suspicious = s.suspicious || 0;
      const harmless = s.harmless || 0;
      const vendors = s.vendors || (s.raw && s.raw.data && s.raw.data[0] && s.raw.data[0].attributes && s.raw.data[0].attributes.last_analysis_results ? Object.keys(s.raw.data[0].attributes.last_analysis_results).length : 0);
      const date = s.date || (s.raw && s.raw.data && s.raw.data[0] && s.raw.data[0].attributes && s.raw.data[0].attributes.last_analysis_date ? new Date(s.raw.data[0].attributes.last_analysis_date * 1000).toLocaleString() : 'Unknown');

      // compute score
      const score = (malicious * 10) + (suspicious * 3);
      let scoreClass = 'score-green';
      if (score >= 50) scoreClass = 'score-orange';
      if (score >= 80) scoreClass = 'score-red';

      const card = document.createElement('div');
      card.className = 'result-card';
      card.innerHTML = `
        <div style="max-width:70%">
          <div class="search-ioc">${esc(e.ioc)}</div>
          <div class="search-meta">${malicious}/${suspicious}/${harmless}</div>
          <div class="search-meta" style="margin-top:6px;font-size:11px">Vendors: ${vendors}</div>
          <div class="search-meta" style="font-size:11px">Last Scan: ${date}</div>

          <div style="margin-top:8px;display:flex;gap:6px">
            <button class="btn btn-primary btn-open" data-ioc="${esc(e.ioc)}">Open in VT</button>
            <button class="btn btn-danger btn-rescan" data-ioc="${esc(e.ioc)}">Scan Again</button>
          </div>
        </div>

        <div style="text-align:center">
          <div class="score-wrap ${scoreClass}">${score}</div>
        </div>
      `;
      searchResults.appendChild(card);
    });

    // wire open and rescan buttons
    document.querySelectorAll('.btn-open').forEach(btn => {
      btn.addEventListener('click', ev => {
        const ioc = btn.dataset.ioc;
        window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(ioc), '_blank');
      });
    });

    document.querySelectorAll('.btn-rescan').forEach(btn => {
      btn.addEventListener('click', ev => {
        const ioc = btn.dataset.ioc;
        chrome.runtime.sendMessage({ type: 'vt_rescan', ioc }, resp => {
          toast('Rescan requested', 'info');
          // Remove local cache immediately for this ioc so next query will fetch fresh
          chrome.storage.local.get(['vt_cache'], res => {
            const cache = res.vt_cache || {};
            delete cache[ioc];
            chrome.storage.local.set({ vt_cache: cache }, () => {});
          });
        });
      });
    });

    searchResults.style.display = 'block';
  }

  // hide search results when clicking outside
  document.addEventListener('mousedown', e => {
    if (!e.target.closest('.search-wrap')) searchResults.style.display = 'none';
  });

  // init
  chrome.storage.local.get(['vt_api_key'], res => {
    keyStatus.textContent = res.vt_api_key ? 'API key configured' : 'No key configured';
  });
  loadRecent();
});

// popup.js (Enhanced v2.0 PRO)
// Tab navigation, quick search, batch scanner, setting drawer, password eye toggle, defanging & enrichment

document.addEventListener('DOMContentLoaded', () => {

  // Elements
  const panel = document.getElementById('settingsPanel');
  const menuBtn = document.getElementById('menuBtn');
  const closeBtn = document.getElementById('closeSettings');

  const apiInput = document.getElementById('apiInput');
  const togglePassBtn = document.getElementById('togglePassBtn');
  const saveBtn = document.getElementById('saveBtn');
  const testBtn = document.getElementById('testBtn');
  const clearBtn = document.getElementById('clearBtn');
  const keyStatus = document.getElementById('keyStatus');
  const autoToggle = document.getElementById('autoHighlightToggle');
  const skipPrivateToggle = document.getElementById('skipPrivateToggle');

  const tabQuickBtn = document.getElementById('tabQuickBtn');
  const tabBatchBtn = document.getElementById('tabBatchBtn');
  const tabQuickContent = document.getElementById('tabQuickContent');
  const tabBatchContent = document.getElementById('tabBatchContent');

  const searchBox = document.getElementById('searchBox');
  const searchResults = document.getElementById('searchResults');
  const recentList = document.getElementById('recentList');
  const viewAllBtn = document.getElementById('viewAllBtn');

  const apiInput = document.getElementById('apiInput');
  const togglePassBtn = document.getElementById('togglePassBtn');
  const abuseApiInput = document.getElementById('abuseApiInput');
  const toggleAbusePassBtn = document.getElementById('toggleAbusePassBtn');
  const saveBtn = document.getElementById('saveBtn');
  const testBtn = document.getElementById('testBtn');
  const clearBtn = document.getElementById('clearBtn');
  const keyStatus = document.getElementById('keyStatus');
  const abuseKeyStatus = document.getElementById('abuseKeyStatus');
  const autoToggle = document.getElementById('autoHighlightToggle');
  const skipPrivateToggle = document.getElementById('skipPrivateToggle');

  const batchInput = document.getElementById('batchInput');
  const batchScanBtn = document.getElementById('batchScanBtn');
  const batchClearBtn = document.getElementById('batchClearBtn');
  const batchResults = document.getElementById('batchResults');

  const toastRoot = document.getElementById('toast-root');

  // Password visibility toggles
  if (togglePassBtn && apiInput) {
    togglePassBtn.addEventListener('click', () => {
      if (apiInput.type === 'password') {
        apiInput.type = 'text';
        togglePassBtn.textContent = '🔒';
      } else {
        apiInput.type = 'password';
        togglePassBtn.textContent = '👁';
      }
    });
  }

  if (toggleAbusePassBtn && abuseApiInput) {
    toggleAbusePassBtn.addEventListener('click', () => {
      if (abuseApiInput.type === 'password') {
        abuseApiInput.type = 'text';
        toggleAbusePassBtn.textContent = '🔒';
      } else {
        abuseApiInput.type = 'password';
        toggleAbusePassBtn.textContent = '👁';
      }
    });
  }

  // Tab Navigation
  tabQuickBtn.addEventListener('click', () => {
    tabQuickBtn.classList.add('active');
    tabBatchBtn.classList.remove('active');
    tabQuickContent.classList.add('active');
    tabBatchContent.classList.remove('active');
  });

  tabBatchBtn.addEventListener('click', () => {
    tabBatchBtn.classList.add('active');
    tabQuickBtn.classList.remove('active');
    tabBatchContent.classList.add('active');
    tabQuickContent.classList.remove('active');
  });

  // Toast
  function toast(msg, type='info') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    toastRoot.appendChild(t);
    setTimeout(() => t.remove(), 2600);
  }

  function esc(s) { return (''+s).replace(/[&<>"]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m])); }

  function undefang(raw) {
    if (!raw) return "";
    let clean = raw.trim();
    clean = clean.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    clean = clean.replace(/\[\:\:\]/g, "::");
    clean = clean.replace(/^hxxps?:\/\//i, m => m.toLowerCase().replace('hxxp', 'http'));
    clean = clean.replace(/^\[http\]s?:\/\//i, m => m.toLowerCase().replace('[http]', 'http'));
    clean = clean.replace(/\[\/\]/g, "/");
    return clean;
  }

  // Storage Cache
  function loadCache(cb) {
    chrome.storage.local.get(['vt_cache'], res => {
      const c = res.vt_cache || {};
      const arr = Object.keys(c).map(k => ({ ioc: k, ...c[k] }));
      arr.sort((a,b) => b.ts - a.ts);
      cb(arr);
    });
  }

  function vtQuery(ioc) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'vt_query', ioc }, res => resolve(res));
    });
  }

  function badge(s) {
    if (!s) return `<span class="badge neutral">No data</span>`;
    const m = s.malicious || 0;
    const susp = s.suspicious || 0;
    if (m >= 5) return `<span class="badge bad">Malicious (${m})</span>`;
    if (m >= 1 || susp >= 1) return `<span class="badge warn">Suspicious (${m})</span>`;
    return `<span class="badge good">Clean</span>`;
  }

  function loadRecent() {
    loadCache(entries => {
      recentList.innerHTML = '';
      const last5 = entries.slice(0,5);
      if (!last5.length) {
        recentList.innerHTML = `<div class="empty">No recent lookups yet.</div>`;
        return;
      }
      last5.forEach(e => {
        const stats = e.data;
        const row = document.createElement('div');
        row.className = 'recent-card';
        row.innerHTML = `
          <div>
            <div class="ioc-text">${esc(e.ioc)}</div>
            <div class="ioc-time">${new Date(e.ts).toLocaleString()}</div>
          </div>
          <div style="text-align:right">
            ${badge(stats)}
            <div style="margin-top:4px"><a href="#" class="small-link open" data-ioc="${esc(e.ioc)}">Open</a></div>
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

  // Panel toggles
  function closePanel() { panel.classList.remove('show'); }
  menuBtn.addEventListener('click', () => panel.classList.toggle('show'));
  closeBtn.addEventListener('click', closePanel);
  document.addEventListener('mousedown', e => {
    if (!e.target.closest('#settingsPanel') && !e.target.closest('#menuBtn')) closePanel();
  });

  // Settings
  function updateKeyStatuses() {
    chrome.storage.local.get(['vt_api_key', 'abuse_api_key'], res => {
      keyStatus.innerHTML = res.vt_api_key ? '<span style="color:#00e676;font-weight:600">✓ VT Key Configured</span>' : 'VT Key: Not configured';
      if (abuseKeyStatus) {
        abuseKeyStatus.innerHTML = res.abuse_api_key ? '<span style="color:#00e676;font-weight:600">✓ AbuseIPDB Key Configured</span>' : 'AbuseIPDB Key: Optional';
      }
    });
  }

  saveBtn.addEventListener('click', () => {
    const key = apiInput.value.trim();
    const abuseKey = abuseApiInput ? abuseApiInput.value.trim() : '';

    if (!key && !abuseKey) { toast('Enter VT or AbuseIPDB API key', 'error'); return; }

    const updateObj = {};
    if (key) updateObj.vt_api_key = key;
    if (abuseKey) updateObj.abuse_api_key = abuseKey;

    chrome.storage.local.set(updateObj, () => {
      if (key) apiInput.value = '';
      if (abuseKey) abuseApiInput.value = '';
      toast('API keys saved successfully', 'success');
      updateKeyStatuses();
    });
  });

  testBtn.addEventListener('click', () => {
    chrome.storage.local.get(['vt_api_key', 'abuse_api_key'], res => {
      if (!res.vt_api_key && !res.abuse_api_key) { toast('No API keys set', 'error'); return; }
      if (res.vt_api_key) {
        chrome.runtime.sendMessage({ type: 'vt_query', ioc: '8.8.8.8' }, r => {
          if (r?.error) toast('VT: ' + r.error, 'error');
          else toast('VT Key verified active!', 'success');
        });
      }
      if (res.abuse_api_key) {
        toast('AbuseIPDB Key configured & ready', 'info');
      }
    });
  });

  clearBtn.addEventListener('click', () => {
    chrome.storage.local.remove(['vt_api_key', 'abuse_api_key', 'vt_cache'], () => {
      toast('Cleared API keys & local cache', 'info');
      updateKeyStatuses();
      loadRecent();
    });
  });

  autoToggle.addEventListener('change', () => {
    chrome.storage.local.set({ auto_highlight: autoToggle.checked });
  });

  skipPrivateToggle.addEventListener('change', () => {
    chrome.storage.local.set({ skip_private_ip: skipPrivateToggle.checked });
  });

  viewAllBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/options/history.html') });
  });

  // Quick Search
  function showLoading() {
    searchResults.style.display = 'block';
    searchResults.innerHTML = `
      <div class="search-info">Querying VirusTotal Threat Engine...</div>
      <div class="shimmer"></div>
      <div class="shimmer"></div>
    `;
  }

  let timer = null;
  searchBox.addEventListener('input', () => {
    const q = undefang(searchBox.value.trim());
    if (timer) clearTimeout(timer);
    if (!q) {
      searchResults.style.display = 'none';
      loadRecent();
      return;
    }
    showLoading();
    timer = setTimeout(() => searchLookup(q), 420);
  });

  async function searchLookup(q) {
    const vt = await vtQuery(q);
    if (!vt || vt.error) {
      searchResults.innerHTML = `<div style="padding:10px;color:#ff80ab">${vt?.error || 'No response from VirusTotal'}</div>`;
      return;
    }
    renderThreatResults([{ ioc: q, ts: Date.now(), data: vt }]);
  }

  function renderThreatResults(list) {
    if (!list || !list.length) {
      searchResults.innerHTML = `<div style="padding:8px;color:#aaa">No results</div>`;
      return;
    }
    searchResults.innerHTML = '';
    list.forEach(e => {
      const s = e.data || {};
      const malicious = s.malicious || 0;
      const suspicious = s.suspicious || 0;
      const harmless = s.harmless || 0;
      const vendors = s.vendors || 0;
      const date = s.date || 'Unknown';
      const asnMeta = s.asn ? `<div class="search-meta" style="font-size:11px">${esc(s.asn)}</div>` : '';

      const score = (malicious * 10) + (suspicious * 3);
      let scoreClass = 'score-green';
      if (score >= 50) scoreClass = 'score-orange';
      if (score >= 80) scoreClass = 'score-red';

      const card = document.createElement('div');
      card.className = 'result-card';
      card.innerHTML = `
        <div style="max-width:70%">
          <div class="search-ioc">${esc(e.ioc)}</div>
          <div class="search-meta">Stats: ${malicious}/${suspicious}/${harmless}</div>
          ${asnMeta}
          <div class="search-meta" style="font-size:11px">Vendors: ${vendors} • ${date}</div>

          <div style="margin-top:8px;display:flex;gap:6px">
            <button class="btn btn-gradient btn-open" data-ioc="${esc(e.ioc)}">Open VT</button>
            <button class="btn btn-danger btn-rescan" data-ioc="${esc(e.ioc)}">Rescan</button>
          </div>
        </div>

        <div style="text-align:center">
          <div class="score-wrap ${scoreClass}">${score}</div>
        </div>
      `;
      searchResults.appendChild(card);
    });

    document.querySelectorAll('.btn-open').forEach(btn => {
      btn.addEventListener('click', () => {
        window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(btn.dataset.ioc), '_blank');
      });
    });

    document.querySelectorAll('.btn-rescan').forEach(btn => {
      btn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'vt_rescan', ioc: btn.dataset.ioc }, () => {
          toast('Rescan requested', 'info');
        });
      });
    });

    searchResults.style.display = 'block';
  }

  // Batch IOC Scanner Logic
  batchScanBtn.addEventListener('click', async () => {
    const rawText = batchInput.value;
    if (!rawText || !rawText.trim()) {
      toast('Paste text or log content to scan', 'error');
      return;
    }

    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const defangIpRegex = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g;
    const hashRegex = /\b[a-fA-F0-9]{32,64}\b/g;

    const extracted = [];
    let m;
    while ((m = ipRegex.exec(rawText)) !== null) extracted.push(m[0]);
    while ((m = defangIpRegex.exec(rawText)) !== null) extracted.push(m[0]);
    while ((m = hashRegex.exec(rawText)) !== null) {
      if (m[0].length === 32 || m[0].length === 40 || m[0].length === 64) {
        extracted.push(m[0]);
      }
    }

    const uniqueClean = [...new Set(extracted.map(undefang))];

    if (!uniqueClean.length) {
      toast('No valid IOCs found in input text', 'error');
      return;
    }

    batchResults.style.display = 'block';
    batchResults.innerHTML = `
      <div id="batchBanner" class="batch-status-banner">
        <div class="batch-status-info">
          <div id="batchPulse" class="batch-pulse-dot"></div>
          <span id="batchStatusText">Extracted ${uniqueClean.length} IOC(s)</span>
        </div>
        <span id="batchCountBadge" class="batch-status-count">0 / ${uniqueClean.length} Done</span>
      </div>

      <table class="batch-table">
        <thead>
          <tr>
            <th>Indicator (IOC)</th>
            <th>Verdict</th>
            <th style="text-align:right">Action</th>
          </tr>
        </thead>
        <tbody id="batchTableBody"></tbody>
      </table>
    `;

    let completed = 0;
    const total = uniqueClean.length;
    const tbody = document.getElementById('batchTableBody');
    const countBadge = document.getElementById('batchCountBadge');
    const statusText = document.getElementById('batchStatusText');
    const pulseDot = document.getElementById('batchPulse');

    for (const ioc of uniqueClean) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="ioc-cell">${esc(ioc)}</td>
        <td class="status-cell"><span class="scanning-pill">⚡ Scanning...</span></td>
        <td style="text-align:right"><button class="btn btn-secondary open-vt-btn" data-ioc="${esc(ioc)}" style="padding:3px 8px;font-size:10px;">VT</button></td>
      `;
      tbody.appendChild(tr);

      tr.querySelector('.open-vt-btn').addEventListener('click', e => {
        window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(e.target.dataset.ioc), '_blank');
      });

      vtQuery(ioc).then(res => {
        completed++;
        countBadge.textContent = `${completed} / ${total} Done`;

        const cell = tr.querySelector('.status-cell');
        if (!res || res.error) {
          cell.innerHTML = `<span class="badge bad">${esc(res?.error || 'Error')}</span>`;
        } else {
          cell.innerHTML = badge(res);
        }

        if (completed === total) {
          statusText.textContent = `✓ Scan Complete (${total} IOCs)`;
          pulseDot.style.background = '#00e676';
          pulseDot.style.boxShadow = '0 0 10px #00e676';
          pulseDot.style.animation = 'none';
        }
      });
    }
    loadRecent();
  });

  batchClearBtn.addEventListener('click', () => {
    batchInput.value = '';
    batchResults.style.display = 'none';
  });

  // Init settings status
  updateKeyStatuses();
  chrome.storage.local.get(['auto_highlight', 'skip_private_ip'], res => {
    autoToggle.checked = res.auto_highlight !== false;
    skipPrivateToggle.checked = res.skip_private_ip !== false;
  });

  loadRecent();
});

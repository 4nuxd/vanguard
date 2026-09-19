// popup.js (Enhanced v4.1 Vanguard Threat Engine)
// Tab navigation, quick search with rich threat breakdown, batch scanner, setting drawer, password eye toggle, cache sanitization

document.addEventListener('DOMContentLoaded', () => {

  // DOM Elements - Clean single declaration
  const panel = document.getElementById('settingsPanel');
  const menuBtn = document.getElementById('menuBtn');
  const closeBtn = document.getElementById('closeSettings');

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

  const tabQuickBtn = document.getElementById('tabQuickBtn');
  const tabBatchBtn = document.getElementById('tabBatchBtn');
  const tabQuickContent = document.getElementById('tabQuickContent');
  const tabBatchContent = document.getElementById('tabBatchContent');

  const searchBox = document.getElementById('searchBox');
  const searchResults = document.getElementById('searchResults');
  const recentList = document.getElementById('recentList');
  const viewAllBtn = document.getElementById('viewAllBtn');

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

  function esc(s) { return (''+(s || '')).replace(/[&<>"]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m])); }

  function undefang(raw) {
    if (!raw) return "";
    let clean = raw.trim();
    clean = clean.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    clean = clean.replace(/\[\:\:\]/g, "::");
    clean = clean.replace(/^hxxps?:\/\//i, m => m.toLowerCase().replace('hxxp', 'http'));
    clean = clean.replace(/^\[http\]s?:\/\//i, m => m.toLowerCase().replace('[http]', 'http'));
    clean = clean.replace(/\[\/\]/g, "/");
    clean = clean.replace(/<[^>]*>/g, ""); // Strip any HTML tags
    return clean;
  }

  // Storage Cache with Key Sanitization & Purge
  function loadCache(cb) {
    chrome.storage.local.get(['vt_cache'], res => {
      const c = res.vt_cache || {};
      const badKeys = [];
      const arr = [];

      Object.keys(c).forEach(k => {
        if (!k || k.includes('<') || k.includes('html') || k.startsWith('http://<') || k.startsWith('https://<')) {
          badKeys.push(k);
        } else {
          arr.push({ ioc: k, ...c[k] });
        }
      });

      // Silently clean corrupted keys from local storage
      if (badKeys.length > 0) {
        badKeys.forEach(bk => delete c[bk]);
        chrome.storage.local.set({ vt_cache: c });
      }

      arr.sort((a,b) => (b.ts || 0) - (a.ts || 0));
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

  // Load Strictly Last 5 Lookups
  function loadRecent() {
    loadCache(entries => {
      recentList.innerHTML = '';
      const last5 = entries.slice(0, 5);
      if (!last5.length) {
        recentList.innerHTML = `<div class="empty" style="color:var(--text-sub);padding:8px 0;text-align:center;">No recent lookups yet.</div>`;
        return;
      }
      last5.forEach(e => {
        const stats = e.data;
        const row = document.createElement('div');
        row.className = 'recent-card';
        row.innerHTML = `
          <div>
            <div class="ioc-text">${esc(e.ioc)}</div>
            <div class="ioc-time">${e.ts ? new Date(e.ts).toLocaleString() : 'Recent'}</div>
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

  // Settings Panel Toggles
  function closePanel() { panel.classList.remove('show'); }
  if (menuBtn) menuBtn.addEventListener('click', () => panel.classList.toggle('show'));
  if (closeBtn) closeBtn.addEventListener('click', closePanel);
  document.addEventListener('mousedown', e => {
    if (panel && !e.target.closest('#settingsPanel') && !e.target.closest('#menuBtn')) closePanel();
  });

  // Settings Handlers
  function updateKeyStatuses() {
    chrome.storage.local.get(['vt_api_key', 'abuse_api_key'], res => {
      if (keyStatus) keyStatus.innerHTML = res.vt_api_key ? '<span style="color:#00e676;font-weight:600">✓ VT Key Configured</span>' : 'VT Key: Not configured';
      if (abuseKeyStatus) {
        abuseKeyStatus.innerHTML = res.abuse_api_key ? '<span style="color:#00e676;font-weight:600">✓ AbuseIPDB Key Configured</span>' : 'AbuseIPDB Key: Optional';
      }
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', () => {
      const key = apiInput ? apiInput.value.trim() : '';
      const abuseKey = abuseApiInput ? abuseApiInput.value.trim() : '';

      if (!key && !abuseKey) { toast('Enter VT or AbuseIPDB API key', 'error'); return; }

      const updateObj = {};
      if (key) updateObj.vt_api_key = key;
      if (abuseKey) updateObj.abuse_api_key = abuseKey;

      chrome.storage.local.set(updateObj, () => {
        if (key && apiInput) apiInput.value = '';
        if (abuseKey && abuseApiInput) abuseApiInput.value = '';
        toast('API keys saved successfully', 'success');
        updateKeyStatuses();
      });
    });
  }

  if (testBtn) {
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
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      chrome.storage.local.remove(['vt_api_key', 'abuse_api_key', 'vt_cache'], () => {
        toast('Cleared API keys & local cache', 'info');
        updateKeyStatuses();
        loadRecent();
      });
    });
  }

  if (autoToggle) {
    autoToggle.addEventListener('change', () => {
      chrome.storage.local.set({ auto_highlight: autoToggle.checked });
    });
  }

  if (skipPrivateToggle) {
    skipPrivateToggle.addEventListener('change', () => {
      chrome.storage.local.set({ skip_private_ip: skipPrivateToggle.checked });
    });
  }

  if (viewAllBtn) {
    viewAllBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/options/history.html') });
    });
  }

  // Quick Search Handlers
  function showLoading() {
    searchResults.style.display = 'block';
    searchResults.innerHTML = `
      <div class="search-info">Querying VirusTotal Threat Engine...</div>
      <div class="shimmer"></div>
      <div class="shimmer"></div>
    `;
  }

  let timer = null;
  if (searchBox) {
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
  }

  async function searchLookup(q) {
    const vt = await vtQuery(q);
    if (!vt || vt.error) {
      const isMissingKey = vt?.error && vt.error.toLowerCase().includes('key');
      if (isMissingKey) {
        searchResults.innerHTML = `
          <div style="padding:12px;background:rgba(255,77,77,0.1);border:1px solid rgba(255,77,77,0.3);border-radius:10px;color:#ff80ab;font-weight:600;font-size:12px;">
            <div>⚠️ VirusTotal API Key Required</div>
            <div style="font-size:11px;color:rgba(255,255,255,0.7);margin-top:4px;font-weight:400;">Please configure your VirusTotal API key in the settings panel.</div>
            <button id="searchOpenSettings" class="btn btn-secondary" style="margin-top:8px;font-size:10px;padding:4px 10px;">⚙️ Open Settings</button>
          </div>
        `;
        const openBtn = document.getElementById('searchOpenSettings');
        if (openBtn) {
          openBtn.addEventListener('click', () => {
            if (panel) panel.classList.add('show');
          });
        }
      } else {
        searchResults.innerHTML = `<div style="padding:12px;color:#ff80ab;font-weight:600;font-size:12px;">${esc(vt?.error || 'No response from VirusTotal')}</div>`;
      }
      searchResults.style.display = 'block';
      return;
    }
    renderThreatResults([{ ioc: q, ts: Date.now(), data: vt }]);
    loadRecent();
  }

  // Render Full Enriched Threat Details in Quick Search Dropdown
  function renderThreatResults(list) {
    if (!list || !list.length) {
      searchResults.innerHTML = `<div style="padding:10px;color:#aaa;text-align:center">No results found</div>`;
      searchResults.style.display = 'block';
      return;
    }
    searchResults.innerHTML = '';

    list.forEach(e => {
      const s = e.data || {};
      if (s.error) {
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'padding:12px;color:#ff80ab;font-weight:600;';
        errDiv.textContent = s.error;
        searchResults.appendChild(errDiv);
        return;
      }

      const malicious = s.malicious || 0;
      const suspicious = s.suspicious || 0;
      const harmless = s.harmless || 0;
      const undetected = s.undetected || 0;
      const vendors = s.vendors || 0;
      const date = s.date || 'Unknown';

      let scoreBadge = `<span class="badge good">Clean</span>`;
      if (malicious >= 5) scoreBadge = `<span class="badge bad">Malicious (${malicious})</span>`;
      else if (malicious >= 1 || suspicious >= 1) scoreBadge = `<span class="badge warn">Suspicious (${malicious})</span>`;

      // Verdict Breakdown Grid
      const verdictGridHtml = `
        <div class="popup-verdict-grid">
          <div class="pv-item"><span style="color:#ff6b6b">🔴 Malicious</span><strong>${malicious}</strong></div>
          <div class="pv-item"><span style="color:#ffc107">🟡 Suspicious</span><strong>${suspicious}</strong></div>
          <div class="pv-item"><span style="color:#69f0ae">🟢 Clean</span><strong>${harmless}</strong></div>
          <div class="pv-item"><span style="color:#a0a0b0">⚪ Undetected</span><strong>${undetected}</strong></div>
        </div>
      `;

      // Network / Location Details
      let netDetails = [];
      if (s.location) netDetails.push(`📍 Location: <strong>${esc(s.location)}</strong>`);
      if (s.asn) netDetails.push(`🌐 ASN: <strong>${esc(s.asn)}</strong>`);
      if (s.registrar) netDetails.push(`🏛 Registrar: <strong>${esc(s.registrar)}</strong>`);
      if (s.country && !s.location) netDetails.push(`🏳 Country: <strong>${esc(s.country)}</strong>`);
      if (s.abuseScore !== null && s.abuseScore !== undefined) {
        netDetails.push(`🛡 AbuseIPDB Score: <strong>${s.abuseScore}% (${s.abuseReports || 0} reports)</strong>`);
      }

      const netDetailsHtml = netDetails.length ? `<div class="search-net-info">${netDetails.join('<br>')}</div>` : '';

      // WHOIS Summary
      const whoisHtml = s.whois ? `
        <div class="search-whois-box">
          <div class="search-whois-title">WHOIS Summary</div>
          <pre class="search-whois-pre">${esc(s.whois)}</pre>
        </div>
      ` : '';

      const isIp = s.type === 'ip' || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(e.ioc);
      const abuseUrl = s.abuseUrl || (isIp ? `https://www.abuseipdb.com/check/${encodeURIComponent(e.ioc)}` : null);
      const abuseBtnHtml = abuseUrl ? `<button class="btn btn-secondary btn-abuse" data-url="${esc(abuseUrl)}">AbuseIPDB</button>` : '';

      const card = document.createElement('div');
      card.className = 'result-card-full';
      card.innerHTML = `
        <div class="result-header">
          <div class="result-ioc-title">${esc(e.ioc)}</div>
          ${scoreBadge}
        </div>
        ${verdictGridHtml}
        ${netDetailsHtml}
        ${whoisHtml}
        <div class="search-meta" style="margin-top:8px;">Scanned: ${vendors} vendors • Date: ${date}</div>

        <div style="margin-top:10px;display:flex;gap:6px;">
          <button class="btn btn-gradient btn-open" data-ioc="${esc(e.ioc)}" style="flex:1;">Open VT</button>
          ${abuseBtnHtml}
          <button class="btn btn-danger btn-rescan" data-ioc="${esc(e.ioc)}" style="flex:1;">Rescan</button>
        </div>
      `;
      searchResults.appendChild(card);
    });

    searchResults.querySelectorAll('.btn-open').forEach(btn => {
      btn.addEventListener('click', () => {
        window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(btn.dataset.ioc), '_blank');
      });
    });

    searchResults.querySelectorAll('.btn-abuse').forEach(btn => {
      btn.addEventListener('click', () => {
        window.open(btn.dataset.url, '_blank');
      });
    });

    searchResults.querySelectorAll('.btn-rescan').forEach(btn => {
      btn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'vt_rescan', ioc: btn.dataset.ioc }, () => {
          toast('Rescan requested', 'info');
        });
      });
    });

    searchResults.style.display = 'block';
  }

  // Batch IOC Scanner Logic with Full Enriched Data Table
  if (batchScanBtn) {
    batchScanBtn.addEventListener('click', async () => {
      const rawText = batchInput.value;
      if (!rawText || !rawText.trim()) {
        toast('Paste text or log content to scan', 'error');
        return;
      }

      const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
      const defangIpRegex = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g;
      const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;
      const hashRegex = /\b[a-fA-F0-9]{32,64}\b/g;

      const extracted = [];
      let m;
      while ((m = ipRegex.exec(rawText)) !== null) extracted.push(m[0]);
      while ((m = defangIpRegex.exec(rawText)) !== null) extracted.push(m[0]);
      while ((m = domainRegex.exec(rawText)) !== null) extracted.push(m[0]);
      while ((m = hashRegex.exec(rawText)) !== null) {
        if (m[0].length === 32 || m[0].length === 40 || m[0].length === 64) {
          extracted.push(m[0]);
        }
      }

      const uniqueClean = [...new Set(extracted.map(undefang))].filter(k => k && !k.includes('<'));

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
              <th>Location / ASN</th>
              <th>Verdict & AbuseIPDB</th>
              <th>Whois / Org</th>
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
          <td class="loc-cell" style="color:var(--text-muted);font-size:10px;">—</td>
          <td class="status-cell"><span class="scanning-pill">⚡ Scanning...</span></td>
          <td class="whois-cell" style="color:var(--text-muted);font-size:10px;">—</td>
          <td style="text-align:right" class="action-cell">
            <button class="btn btn-secondary open-vt-btn" data-ioc="${esc(ioc)}" style="padding:3px 8px;font-size:10px;">VT</button>
          </td>
        `;
        tbody.appendChild(tr);

        tr.querySelector('.open-vt-btn').addEventListener('click', e => {
          window.open("https://www.virustotal.com/gui/search/" + encodeURIComponent(e.target.dataset.ioc), '_blank');
        });

        vtQuery(ioc).then(res => {
          completed++;
          countBadge.textContent = `${completed} / ${total} Done`;

          const statusCell = tr.querySelector('.status-cell');
          const locCell = tr.querySelector('.loc-cell');
          const whoisCell = tr.querySelector('.whois-cell');
          const actionCell = tr.querySelector('.action-cell');

          if (!res || res.error) {
            statusCell.innerHTML = `<span class="badge bad">${esc(res?.error || 'Error')}</span>`;
          } else {
            let scoreText = badge(res);
            if (res.abuseScore !== null && res.abuseScore !== undefined) {
              scoreText += `<div style="font-size:9px;color:#ffab00;margin-top:2px;">Abuse: ${res.abuseScore}%</div>`;
            }
            statusCell.innerHTML = scoreText;

            const locInfo = res.location || res.asn || res.country || '—';
            locCell.innerHTML = `<div style="max-width:110px;word-break:break-word;">${esc(locInfo)}</div>`;

            const whoisSummary = res.whois ? res.whois.split('\n')[0] : (res.registrar || '—');
            whoisCell.innerHTML = `<div style="max-width:120px;word-break:break-word;">${esc(whoisSummary)}</div>`;

            if (res.abuseUrl) {
              const abuseBtn = document.createElement('button');
              abuseBtn.className = 'btn btn-secondary open-abuse-btn';
              abuseBtn.textContent = 'Abuse';
              abuseBtn.style.cssText = 'padding:3px 8px;font-size:10px;margin-left:4px;';
              abuseBtn.addEventListener('click', () => window.open(res.abuseUrl, '_blank'));
              actionCell.appendChild(abuseBtn);
            }
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
  }

  if (batchClearBtn) {
    batchClearBtn.addEventListener('click', () => {
      batchInput.value = '';
      batchResults.style.display = 'none';
    });
  }

  // Init settings status & load recent
  updateKeyStatuses();
  chrome.storage.local.get(['auto_highlight', 'skip_private_ip'], res => {
    if (autoToggle) autoToggle.checked = res.auto_highlight !== false;
    if (skipPrivateToggle) skipPrivateToggle.checked = res.skip_private_ip !== false;
  });

  loadRecent();
});

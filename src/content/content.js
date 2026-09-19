// content.js (v2.0 Viewport-Optimized Highlighting Engine)
// High-performance IntersectionObserver scanning for Universal URLs, Defanged URLs, IPs, Defanged IPs, Universal Domains, Defanged Domains, and Hashes

(() => {
  if (window.__vt_inspector_injected) return;
  window.__vt_inspector_injected = true;

  // Settings
  let skipPrivateIp = true;
  let autoHighlight = true;

  function refreshSettings(cb) {
    chrome.storage.local.get(["skip_private_ip", "auto_highlight"], res => {
      skipPrivateIp = res.skip_private_ip !== false; // default true
      autoHighlight = res.auto_highlight !== false; // default true
      if (cb) cb();
    });
  }
  refreshSettings();

  // Regular Expression Definitions
  const URL_REGEX = /\b(?:(?:https?|hxxps?|h\*\*ps?|ftp):\/\/|www\.)[^\s<>"'\)]+/gi;
  const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\(\.\)|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi;
  const DOMAIN_DEFANG_REGEX = /\b(?:[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\))){1,}[a-zA-Z]{2,24}\b/gi;
  const UNIVERSAL_DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/gi;
  const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
  const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
  const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;

  const FILE_EXT_EXCLUDE = /\.(?:js|css|html|htm|png|jpg|jpeg|gif|svg|json|md|py|cpp|c|h|java|ts|sh|exe|zip|tar|gz|woff|woff2|ttf|eot)$/i;

  // Private / Loopback IPv4 check
  function isPrivateIP(ip) {
    if (ip === "127.0.0.1" || ip === "0.0.0.0" || ip === "::1") return true;
    const parts = ip.split('.').map(Number);
    if (parts.length === 4) {
      if (parts[0] === 10) return true; // 10.0.0.0/8
      if (parts[0] === 127) return true; // 127.0.0.0/8
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
      if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    }
    return false;
  }

  // Undefang parser helper
  function undefang(raw) {
    if (!raw) return "";
    let clean = raw.trim();
    // Normalize protocols: hxxp -> http, hxxps -> https, h**p -> http, h**ps -> https
    clean = clean.replace(/^hxxps?:/i, m => m.toLowerCase().startsWith('hxxps') ? 'https:' : 'http:');
    clean = clean.replace(/^h\*\*ps?:/i, m => m.toLowerCase().startsWith('h**ps') ? 'https:' : 'http:');
    // Normalize brackets: [.], (.), [:], [::]
    clean = clean.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\[\:\:\]/g, "::").replace(/\[\:\]/g, ":");
    return clean;
  }

  // Determine if DOM element is valid for text scanning
  function isTargetContainer(node) {
    if (!node || !node.tagName) return false;
    const tag = node.tagName.toUpperCase();
    if (['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'SELECT', 'BUTTON', 'NOSCRIPT', 'SVG', 'CANVAS'].includes(tag)) return false;
    if (node.closest && (node.closest('.vt-ioc') || node.closest('.vt-tooltip') || node.closest('.popup-root') || node.closest('.dashboard-root'))) return false;
    if (node.classList && (node.classList.contains('vt-ioc') || node.classList.contains('vt-tooltip'))) return false;
    return true;
  }

  // Text Node Replacement Engine
  function wrapMatchesInNode(textNode) {
    if (!autoHighlight) return false;
    if (textNode.parentNode && textNode.parentNode.closest && textNode.parentNode.closest('.vt-ioc, .vt-tooltip, .popup-root, .dashboard-root')) return false;

    const text = textNode.nodeValue;
    if (!text || text.trim().length < 3) return false;

    // Fast check to skip text nodes without potential IOC patterns
    if (!/[a-zA-Z0-9]/.test(text)) return false;

    let hasMatch = false;

    const replaceFn = (match, type) => {
      const clean = undefang(match);

      if (type === "ip" && skipPrivateIp && isPrivateIP(clean)) {
        return match;
      }
      if (type === "domain" && FILE_EXT_EXCLUDE.test(clean) && !clean.includes('..')) {
        return match;
      }
      hasMatch = true;
      return `<span class="vt-ioc" data-ioc="${escapeAttr(clean)}" data-type="${type}">${match}</span>`;
    };

    let replaced = text;

    // 1. Process URLs & Defanged URLs first (e.g. https://..., www.4nuxd.one)
    replaced = replaced.replace(URL_REGEX, m => replaceFn(m, "url"));

    // 2. Process IPv4 & Defanged IPv4 (e.g. 160.238.72.12, 1.1.1[.]1)
    replaced = replaced.replace(IPV4_REGEX, m => replaceFn(m, "ip"));

    // 3. Process Defanged Domains & Universal Domains (e.g. 4nuxd.one, example.com)
    replaced = replaced.replace(DOMAIN_DEFANG_REGEX, m => replaceFn(m, "domain"));
    replaced = replaced.replace(UNIVERSAL_DOMAIN_REGEX, m => replaceFn(m, "domain"));

    // 4. Process Hashes (SHA256, SHA1, MD5)
    replaced = replaced.replace(SHA256_REGEX, m => replaceFn(m, "hash"));
    replaced = replaced.replace(SHA1_REGEX, m => replaceFn(m, "hash"));
    replaced = replaced.replace(MD5_REGEX, m => replaceFn(m, "hash"));

    if (hasMatch) {
      const wrapper = document.createElement('span');
      wrapper.innerHTML = replaced;
      if (textNode.parentNode) {
        textNode.parentNode.replaceChild(wrapper, textNode);
        return true;
      }
    }
    return false;
  }

  function escapeAttr(s) {
    return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // VIEWPORT-BASED HIGH-PERFORMANCE LAZY SCANNING
  const scannedElements = new WeakSet();

  const viewportObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        observer.unobserve(el);
        if (!scannedElements.has(el)) {
          scannedElements.add(el);
          scanElementText(el);
        }
      }
    });
  }, {
    rootMargin: '250px 0px 250px 0px',
    threshold: 0.01
  });

  function observeCandidate(el) {
    if (!el || scannedElements.has(el)) return;
    if (isTargetContainer(el)) {
      viewportObserver.observe(el);
    }
  }

  function scanElementText(container) {
    if (!autoHighlight || !container) return;
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const textNodes = [];
    let n;
    while ((n = walker.nextNode())) {
      if (n.parentNode && isTargetContainer(n.parentNode)) {
        textNodes.push(n);
      }
    }
    textNodes.forEach(node => {
      try { wrapMatchesInNode(node); } catch (e) {}
    });
  }

  function scanCurrentViewport() {
    if (!autoHighlight) return;
    const candidates = document.querySelectorAll('p, div, span, li, td, th, article, section, h1, h2, h3, h4, h5, h6, a, code, pre, blockquote');
    candidates.forEach(el => observeCandidate(el));
  }

  // Tooltip State & Hover Persistence Bridge
  let tooltipEl = null;
  let activeTargetEl = null;
  let isMouseOverIOC = false;
  let isMouseOverTooltip = false;
  let hideTimer = null;

  function scheduleHide() {
    hideTimer && clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      if (!isMouseOverIOC && !isMouseOverTooltip) {
        removeTooltip();
      }
    }, 250);
  }

  function removeTooltip() {
    if (tooltipEl && tooltipEl.parentNode) {
      tooltipEl.remove();
      tooltipEl = null;
    }
    activeTargetEl = null;
  }

  function createTooltip(ioc, data, targetEl) {
    if (activeTargetEl === targetEl && tooltipEl) return;
    removeTooltip();
    activeTargetEl = targetEl;

    tooltipEl = document.createElement('div');
    tooltipEl.className = 'vt-tooltip';

    // Hover persistence listeners on tooltip itself
    tooltipEl.addEventListener('mouseenter', () => {
      isMouseOverTooltip = true;
      hideTimer && clearTimeout(hideTimer);
    });

    tooltipEl.addEventListener('mouseleave', () => {
      isMouseOverTooltip = false;
      scheduleHide();
    });

    const malicious = data.malicious || 0;
    const suspicious = data.suspicious || 0;
    const harmless = data.harmless || 0;
    const undetected = data.undetected || 0;
    const vendors = data.vendors || 0;
    const date = data.date || "N/A";

    let scoreBadge = `<span class="vt-badge vt-good">Clean</span>`;
    if (malicious >= 5) scoreBadge = `<span class="vt-badge vt-bad">Malicious (${malicious})</span>`;
    else if (malicious >= 1 || suspicious >= 1) scoreBadge = `<span class="vt-badge vt-warn">Suspicious (${malicious})</span>`;

    // Detailed Verdict Grid Breakdown
    const verdictGridHtml = `
      <div class="vt-verdict-grid">
        <div class="vt-vitem"><span class="vt-vlbl" style="color:#ff6b6b">🔴 Malicious</span><strong>${malicious}</strong></div>
        <div class="vt-vitem"><span class="vt-vlbl" style="color:#ffc107">🟡 Suspicious</span><strong>${suspicious}</strong></div>
        <div class="vt-vitem"><span class="vt-vlbl" style="color:#69f0ae">🟢 Clean</span><strong>${harmless}</strong></div>
        <div class="vt-vitem"><span class="vt-vlbl" style="color:#a0a0b0">⚪ Undetected</span><strong>${undetected}</strong></div>
      </div>
    `;

    // Enriched Network, Whois & AbuseIPDB Details
    let networkDetailsHtml = '';
    if (data.location) networkDetailsHtml += `<div class="vt-row"><span>📍 Location:</span><strong>${escapeAttr(data.location)}</strong></div>`;
    if (data.asn) networkDetailsHtml += `<div class="vt-row"><span>🌐 ASN / Owner:</span><strong>${escapeAttr(data.asn)}</strong></div>`;
    if (data.registrar) networkDetailsHtml += `<div class="vt-row"><span>🏛 Registrar:</span><strong>${escapeAttr(data.registrar)}</strong></div>`;
    if (data.country && !data.location) networkDetailsHtml += `<div class="vt-row"><span>🏳 Country:</span><strong>${escapeAttr(data.country)}</strong></div>`;
    if (data.abuseScore !== null && data.abuseScore !== undefined) {
      networkDetailsHtml += `<div class="vt-row"><span>🛡 AbuseIPDB Score:</span><strong style="color:#ffab00">${data.abuseScore}% (${data.abuseReports || 0} reports)</strong></div>`;
    }
    if (data.reputation !== null && data.reputation !== undefined) {
      const repColor = data.reputation < 0 ? '#ff6b6b' : (data.reputation > 0 ? '#69f0ae' : '#ffffff');
      networkDetailsHtml += `<div class="vt-row"><span>Community Rep:</span><strong style="color:${repColor}">${data.reputation > 0 ? '+' : ''}${data.reputation}</strong></div>`;
    }
    if (data.whois) {
      networkDetailsHtml += `<div class="vt-whois-box"><div class="vt-whois-lbl">WHOIS Summary</div><pre class="vt-whois-pre">${escapeAttr(data.whois)}</pre></div>`;
    }

    const tagsHtml = (data.tags && data.tags.length)
      ? `<div class="vt-tags">${data.tags.map(t => `<span class="vt-tag">${escapeAttr(t)}</span>`).join('')}</div>`
      : '';

    // Always build AbuseIPDB URL for IP IOCs even if cached earlier
    const isIp = data.type === 'ip' || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    const abuseUrl = data.abuseUrl || (isIp ? `https://www.abuseipdb.com/check/${encodeURIComponent(ioc)}` : null);
    const abuseBtnHtml = abuseUrl
      ? `<button class="vt-btn vt-abuse" data-url="${escapeAttr(abuseUrl)}">AbuseIPDB</button>`
      : '';

    tooltipEl.innerHTML = `
      <div class="vt-header">
        <span class="vt-title">${escapeAttr(ioc)}</span>
        ${scoreBadge}
      </div>
      ${verdictGridHtml}
      ${networkDetailsHtml ? `<div class="vt-divider"></div>${networkDetailsHtml}` : ''}
      <div class="vt-row"><span>Total Vendors:</span><strong>${vendors} scanned</strong></div>
      <div class="vt-row"><span>Last Scan:</span><strong>${escapeAttr(date)}</strong></div>
      ${tagsHtml}
      <div style="margin-top:10px;display:flex;gap:6px;">
        <button class="vt-btn vt-open" style="flex:1">Open VT</button>
        ${abuseBtnHtml}
        <button class="vt-btn vt-rescan" style="flex:1">Rescan</button>
      </div>
    `;

    document.body.appendChild(tooltipEl);

    // Precise positioning calculation
    const rect = targetEl.getBoundingClientRect();
    requestAnimationFrame(() => {
      if (!tooltipEl) return;
      const ttRect = tooltipEl.getBoundingClientRect();
      let top = rect.top - ttRect.height - 8;
      if (top < 6) top = rect.bottom + 6;
      let left = rect.left;
      if (left + ttRect.width > window.innerWidth - 12) {
        left = window.innerWidth - ttRect.width - 12;
      }
      if (left < 6) left = 6;
      tooltipEl.style.top = `${top + window.scrollY}px`;
      tooltipEl.style.left = `${left + window.scrollX}px`;
    });

    // Action button handlers
    tooltipEl.querySelector('.vt-open').addEventListener('click', () => {
      window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`, '_blank');
    });

    const abuseBtn = tooltipEl.querySelector('.vt-abuse');
    if (abuseBtn) {
      abuseBtn.addEventListener('click', () => {
        window.open(abuseBtn.dataset.url, '_blank');
      });
    }

    tooltipEl.querySelector('.vt-rescan').addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'vt_rescan', ioc }, () => {
        const note = document.createElement('div');
        note.className = 'vt-rescan-note';
        note.textContent = 'Rescan requested';
        tooltipEl.appendChild(note);
        setTimeout(() => note.remove(), 1800);
      });
    });
  }

  function queryVT(ioc) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'vt_query', ioc }, res => resolve(res));
    });
  }

  // Hover Events for Enriched Tooltip with Mouse Persistence
  let hoverTimer = null;
  document.addEventListener('mouseover', e => {
    const target = e.target;
    if (!target || !target.classList || !target.classList.contains('vt-ioc')) return;

    isMouseOverIOC = true;
    hideTimer && clearTimeout(hideTimer);

    const ioc = target.dataset.ioc;
    if (!ioc) return;

    hoverTimer && clearTimeout(hoverTimer);
    hoverTimer = setTimeout(async () => {
      if (!isMouseOverIOC) return;
      const data = await queryVT(ioc);
      if (!isMouseOverIOC) return;
      if (!data || data.error) {
        createTooltip(ioc, { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, vendors: 0, date: data?.error || 'N/A' }, target);
        return;
      }
      createTooltip(ioc, data, target);
    }, 150);
  });

  document.addEventListener('mouseout', e => {
    const target = e.target;
    if (!target || !target.classList || !target.classList.contains('vt-ioc')) return;
    isMouseOverIOC = false;
    hoverTimer && clearTimeout(hoverTimer);
    scheduleHide();
  });

  // Init Settings & Observer
  refreshSettings(() => {
    scanCurrentViewport();
  });

  // Observe DOM additions (Incremental Viewport Observer)
  const mutationObserver = new MutationObserver(mutations => {
    for (const m of mutations) {
      if (m.addedNodes) {
        m.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (isTargetContainer(node)) observeCandidate(node);
            const children = node.querySelectorAll ? node.querySelectorAll('p, div, span, li, td, th, article, section, a, code, pre') : [];
            children.forEach(child => observeCandidate(child));
          }
        });
      }
    }
  });
  mutationObserver.observe(document.body, { childList: true, subtree: true });
})();

// content.js (v2.0 Viewport-Optimized Highlighting Engine)
// High-performance IntersectionObserver scanning for URLs, Defanged URLs, IPs, Defanged IPs, Domains, Defanged Domains, and Hashes

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
  const URL_REGEX = /\b(?:https?|hxxps?|h\*\*ps?):\/\/[^\s<>"'\)]+/gi;
  const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\(\.\)|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi;
  const DOMAIN_DEFANG_REGEX = /\b(?:[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\))){1,}[a-zA-Z]{2,24}\b/gi;
  const COMMON_TLD_REGEX = /\b(?:[a-zA-Z0-9-]{2,63}\.)+(?:com|org|net|io|xyz|ru|cn|info|biz|gov|edu|uk|de|jp|fr|au|co|me|ai|app|dev|cloud|online|site|tech|store|top)\b/gi;
  const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
  const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
  const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;

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
    if (['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'SELECT', 'BUTTON', 'CODE', 'PRE', 'NOSCRIPT', 'SVG', 'CANVAS'].includes(tag)) return false;
    if (node.classList && (node.classList.contains('vt-ioc') || node.classList.contains('vt-tooltip'))) return false;
    return true;
  }

  // Text Node Replacement Engine
  function wrapMatchesInNode(textNode) {
    if (!autoHighlight) return false;
    const text = textNode.nodeValue;
    if (!text || text.trim().length < 4) return false;

    // Fast check to skip text nodes without potential IOC patterns
    if (!/[a-zA-Z0-9]/.test(text)) return false;

    let hasMatch = false;

    const replaceFn = (match, type) => {
      const clean = undefang(match);

      if (type === "ip" && skipPrivateIp && isPrivateIP(clean)) {
        return match;
      }
      hasMatch = true;
      return `<span class="vt-ioc" data-ioc="${escapeAttr(clean)}" data-type="${type}">${match}</span>`;
    };

    let replaced = text;

    // 1. Process URLs & Defanged URLs first
    replaced = replaced.replace(URL_REGEX, m => replaceFn(m, "url"));

    // 2. Process IPv4 & Defanged IPv4
    replaced = replaced.replace(IPV4_REGEX, m => replaceFn(m, "ip"));

    // 3. Process Defanged Domains & Standard TLD Domains
    replaced = replaced.replace(DOMAIN_DEFANG_REGEX, m => replaceFn(m, "domain"));
    replaced = replaced.replace(COMMON_TLD_REGEX, m => replaceFn(m, "domain"));

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
    rootMargin: '200px 0px 200px 0px',
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
    const candidates = document.querySelectorAll('p, div, span, li, td, th, article, section, h1, h2, h3, h4, h5, h6, a, blockquote');
    candidates.forEach(el => observeCandidate(el));
  }

  // Tooltip Management
  let tooltipEl = null;

  function removeTooltip() {
    if (tooltipEl && tooltipEl.parentNode) {
      tooltipEl.remove();
      tooltipEl = null;
    }
  }

  function createTooltip(ioc, data, targetEl) {
    removeTooltip();
    tooltipEl = document.createElement('div');
    tooltipEl.className = 'vt-tooltip';

    const malicious = data.malicious || 0;
    const suspicious = data.suspicious || 0;
    const harmless = data.harmless || 0;
    const undetected = data.undetected || 0;
    const vendors = data.vendors || 0;
    const date = data.date || "N/A";

    let scoreBadge = `<span class="vt-badge vt-good">Clean</span>`;
    if (malicious >= 5) scoreBadge = `<span class="vt-badge vt-bad">Malicious (${malicious})</span>`;
    else if (malicious >= 1 || suspicious >= 1) scoreBadge = `<span class="vt-badge vt-warn">Suspicious (${malicious})</span>`;

    const tagsHtml = (data.tags && data.tags.length)
      ? `<div class="vt-tags">${data.tags.map(t => `<span class="vt-tag">${escapeAttr(t)}</span>`).join('')}</div>`
      : '';

    const enrichedInfo = data.asn
      ? `<div class="vt-row"><span>Network:</span><strong>${escapeAttr(data.asn)}</strong></div>`
      : '';

    tooltipEl.innerHTML = `
      <div class="vt-header">
        <span class="vt-title">${escapeAttr(ioc)}</span>
        ${scoreBadge}
      </div>
      ${enrichedInfo}
      <div class="vt-row"><span>Stats (M/S/H/U):</span><strong>${malicious}/${suspicious}/${harmless}/${undetected}</strong></div>
      <div class="vt-row"><span>Vendors:</span><strong>${vendors}</strong></div>
      <div class="vt-row"><span>Last Scan:</span><strong>${escapeAttr(date)}</strong></div>
      ${tagsHtml}
      <div style="margin-top:10px;display:flex;gap:6px;">
        <button class="vt-btn vt-open">Open in VT</button>
        <button class="vt-btn vt-rescan">Rescan</button>
      </div>
    `;

    document.body.appendChild(tooltipEl);

    // Precise position calculation
    const rect = targetEl.getBoundingClientRect();
    requestAnimationFrame(() => {
      if (!tooltipEl) return;
      const ttRect = tooltipEl.getBoundingClientRect();
      let top = rect.top - ttRect.height - 10;
      if (top < 6) top = rect.bottom + 8;
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

  // Hover Events for Enriched Tooltip
  let hoverTimer = null;
  document.addEventListener('mouseover', e => {
    const target = e.target;
    if (!target || !target.classList || !target.classList.contains('vt-ioc')) return;

    const ioc = target.dataset.ioc;
    if (!ioc) return;

    hoverTimer && clearTimeout(hoverTimer);
    hoverTimer = setTimeout(async () => {
      const data = await queryVT(ioc);
      if (!data || data.error) {
        createTooltip(ioc, { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, vendors: 0, date: data?.error || 'N/A' }, target);
        return;
      }
      createTooltip(ioc, data, target);
    }, 180);
  });

  document.addEventListener('mouseout', e => {
    const target = e.target;
    if (!target || !target.classList || !target.classList.contains('vt-ioc')) return;
    hoverTimer && clearTimeout(hoverTimer);
    setTimeout(removeTooltip, 160);
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
            const children = node.querySelectorAll ? node.querySelectorAll('p, div, span, li, td, th, article, section, a') : [];
            children.forEach(child => observeCandidate(child));
          }
        });
      }
    }
  });
  mutationObserver.observe(document.body, { childList: true, subtree: true });
})();

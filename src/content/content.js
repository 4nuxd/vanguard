// content.js (Enhanced v2.0)
// Auto-detect IPs (IPv4/IPv6), Hashes (MD5, SHA1, SHA256) & Defanged IOCs -> highlight -> enriched tooltip

(() => {
  if (window.__vt_inspector_injected) return;
  window.__vt_inspector_injected = true;

  // Configuration settings (loaded from chrome.storage.local)
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

  // Regex Patterns
  const IPv4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const IPv6_REGEX = /\b((?:[A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}|::1)\b/gi;
  const DEFANG_IP_REGEX = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g;
  const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
  const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
  const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;

  // Helper: Private / Reserved IP check
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

  // Defang parser
  function undefang(raw) {
    if (!raw) return "";
    return raw.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\[\:\:\]/g, "::");
  }

  function wrapMatchesInNode(textNode) {
    if (!autoHighlight) return false;
    const text = textNode.nodeValue;
    if (!text || text.trim().length < 4) return false;

    // Fast initial test before expensive replace
    if (!/\d|\b[a-fA-F0-9]{32}/.test(text)) return false;

    let hasMatch = false;

    // Replace function helper
    const replaceFn = (match, type) => {
      const clean = undefang(match);
      if (type === "ip" && skipPrivateIp && isPrivateIP(clean)) {
        return match;
      }
      hasMatch = true;
      return `<span class="vt-ioc vt-ip" data-ioc="${clean}">${match}</span>`;
    };

    let replaced = text;
    replaced = replaced.replace(IPv4_REGEX, m => replaceFn(m, "ip"));
    replaced = replaced.replace(DEFANG_IP_REGEX, m => replaceFn(m, "ip"));
    replaced = replaced.replace(SHA256_REGEX, m => replaceFn(m, "hash"));

    if (hasMatch) {
      const wrapper = document.createElement('span');
      wrapper.innerHTML = replaced;
      textNode.parentNode.replaceChild(wrapper, textNode);
      return true;
    }
    return false;
  }

  function highlightIOCs() {
    if (!autoHighlight) return;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(node => {
      const parentTag = node.parentNode && node.parentNode.nodeName;
      if (!parentTag) return;
      if (["SCRIPT", "STYLE", "TEXTAREA", "INPUT", "SELECT", "BUTTON", "CODE", "PRE"].includes(parentTag)) return;
      try { wrapMatchesInNode(node); } catch (e) { /* ignore safe DOM errors */ }
    });
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
      ? `<div class="vt-tags">${data.tags.map(t => `<span class="vt-tag">${t}</span>`).join('')}</div>`
      : '';

    const enrichedInfo = data.asn
      ? `<div class="vt-row"><span>Network:</span><strong>${data.asn}</strong></div>`
      : '';

    tooltipEl.innerHTML = `
      <div class="vt-header">
        <span class="vt-title">${ioc}</span>
        ${scoreBadge}
      </div>
      ${enrichedInfo}
      <div class="vt-row"><span>Stats (M/S/H/U):</span><strong>${malicious}/${suspicious}/${harmless}/${undetected}</strong></div>
      <div class="vt-row"><span>Vendors:</span><strong>${vendors}</strong></div>
      <div class="vt-row"><span>Last Scan:</span><strong>${date}</strong></div>
      ${tagsHtml}
      <div style="margin-top:10px;display:flex;gap:6px;">
        <button class="vt-btn vt-open">Open in VT</button>
        <button class="vt-btn vt-rescan">Rescan</button>
      </div>
    `;

    document.body.appendChild(tooltipEl);

    // Position calculation
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

    // Action listeners
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

  // Hover Events
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

  // Init
  refreshSettings(() => {
    try { highlightIOCs(); } catch (err) {}
  });

  // Observe DOM changes
  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length) {
        highlightIOCs();
        break;
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();

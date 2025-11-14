// content.js
// Auto-detect only IPv4 & IPv6 -> highlight -> show tooltip on hover
// Note: tooltip CSS is provided separately in tooltip.css (loaded via manifest)

(() => {
  // IPv4 regex (strict)
  const IPv4 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  // IPv6 basic pattern (covers common forms)
  const IPv6 = /\b((?:[A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}|::1)\b/gi;

  // Avoid running multiple times
  if (window.__vt_ips_injected) return;
  window.__vt_ips_injected = true;

  function wrapMatchesInNode(textNode) {
    const text = textNode.nodeValue;
    let has = false;
    IPv4.lastIndex = 0;
    IPv6.lastIndex = 0;
    if (!IPv4.test(text) && !IPv6.test(text)) return false;

    // Rebuild with spans
    const replaced = text
      .replace(IPv4, ip => {
        has = true;
        return `<span class="vt-ip" data-ip="${ip}">${ip}</span>`;
      })
      .replace(IPv6, ip => {
        has = true;
        return `<span class="vt-ip" data-ip="${ip}">${ip}</span>`;
      });

    if (has) {
      const wrapper = document.createElement('span');
      wrapper.innerHTML = replaced;
      textNode.parentNode.replaceChild(wrapper, textNode);
      return true;
    }
    return false;
  }

  function highlightIPs() {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(node => {
      // skip inside script/style elements etc
      const parentTag = node.parentNode && node.parentNode.nodeName;
      if (!parentTag) return;
      if (["SCRIPT", "STYLE", "TEXTAREA", "CODE", "PRE"].includes(parentTag)) return;
      try { wrapMatchesInNode(node); } catch (e) { /* ignore dangerous nodes */ }
    });
  }

  // Tooltip element management
  let tooltipEl = null;
  function removeTooltip() {
    if (tooltipEl && tooltipEl.parentNode) {
      tooltipEl.remove();
      tooltipEl = null;
    }
  }

  function createTooltip(ip, data, targetEl) {
    removeTooltip();
    tooltipEl = document.createElement('div');
    tooltipEl.className = 'vt-tooltip';
    tooltipEl.innerHTML = `
      <div class="vt-title">${ip}</div>
      <div class="vt-row"><span>Malicious:</span><strong>${data.malicious}</strong></div>
      <div class="vt-row"><span>Suspicious:</span><strong>${data.suspicious}</strong></div>
      <div class="vt-row"><span>Harmless:</span><strong>${data.harmless}</strong></div>
      <div class="vt-row"><span>Undetected:</span><strong>${data.undetected}</strong></div>
      <div class="vt-row"><span>Vendors:</span><strong>${data.vendors}</strong></div>
      <div class="vt-row"><span>Last Scan:</span><strong>${data.date}</strong></div>
      <div style="margin-top:8px;display:flex;gap:8px;">
        <button class="vt-btn vt-open">Open in VT</button>
        <button class="vt-btn vt-rescan">Rescan</button>
      </div>
    `;
    document.body.appendChild(tooltipEl);

    // Position: above target if possible
    const rect = targetEl.getBoundingClientRect();
    // small delay to let tooltip render size
    requestAnimationFrame(() => {
      const ttRect = tooltipEl.getBoundingClientRect();
      let top = rect.top - ttRect.height - 12;
      if (top < 6) top = rect.bottom + 8; // if not enough space above, place below
      let left = rect.left;
      if (left + ttRect.width > window.innerWidth - 8) {
        left = window.innerWidth - ttRect.width - 8;
      }
      tooltipEl.style.top = `${top + window.scrollY}px`;
      tooltipEl.style.left = `${left + window.scrollX}px`;
    });

    // button hooks
    tooltipEl.querySelector('.vt-open').addEventListener('click', () => {
      window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ip)}`, '_blank');
    });
    tooltipEl.querySelector('.vt-rescan').addEventListener('click', () => {
      // send rescan, background will remove cache
      chrome.runtime.sendMessage({ type: 'vt_rescan', ioc: ip }, resp => {
        // user feedback via small ephemeral bubble (simple)
        const note = document.createElement('div');
        note.className = 'vt-rescan-note';
        note.textContent = 'Rescan requested';
        tooltipEl.appendChild(note);
        setTimeout(() => note.remove(), 1800);
      });
    });
  }

  // ask background for VT data (caching handled there)
  function queryVT(ip) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'vt_query', ioc: ip }, res => resolve(res));
    });
  }

  // Hover handling
  let hoverTimer = null;
  document.addEventListener('mouseover', async (e) => {
    const target = e.target;
    if (!target || !target.classList) return;
    if (!target.classList.contains('vt-ip')) return;

    const ip = target.dataset.ip;
    if (!ip) return;

    // small delay to avoid flicker
    hoverTimer && clearTimeout(hoverTimer);
    hoverTimer = setTimeout(async () => {
      const data = await queryVT(ip);
      if (!data || data.error) {
        // show minimal tooltip if error
        createTooltip(ip, { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, vendors: 0, date: 'N/A' }, target);
        return;
      }
      createTooltip(ip, data, target);
    }, 160);
  });

  document.addEventListener('mouseout', (e) => {
    const target = e.target;
    if (!target || !target.classList) return;
    if (target.classList.contains('vt-ip')) {
      hoverTimer && clearTimeout(hoverTimer);
      // slight delay before removing so clicking works
      setTimeout(removeTooltip, 120);
    }
  });

  // Kick off
  try { highlightIPs(); } catch (err) { /* swallow */ }

  // Also observe DOM changes and highlight newly added content
  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length) {
        highlightIPs();
        break;
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

})();

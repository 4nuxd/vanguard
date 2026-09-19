// background.js (Enhanced v2.0 MV3 Service Worker)
// VirusTotal API wrapper + multi-IOC (IP, Domain, Hash, URL) + enrichment + cache + rescan + contextMenus

const VT_API_BASE = "https://www.virustotal.com/api/v3/";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Register Context Menus safely
function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "vt_inspect_selection",
      title: "Inspect selection with VirusTotal",
      contexts: ["selection"]
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  setupContextMenus();
});

chrome.runtime.onStartup.addListener(() => {
  setupContextMenus();
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "vt_inspect_selection" && info.selectionText) {
    const rawText = info.selectionText.trim();
    const cleanText = undefang(rawText);
    const vtUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(cleanText)}`;
    chrome.tabs.create({ url: vtUrl });
  }
});

// Helper: Defang / Un-defang IOCs
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

// Helper: Detect IOC Type & Return Clean String
function detectIOCType(ioc) {
  const clean = undefang(ioc);
  // IPv4
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(clean)) {
    return { type: "ip", clean };
  }
  // IPv6
  if (/^((?:[A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}|::1)$/i.test(clean)) {
    return { type: "ip", clean };
  }
  // Hash (MD5: 32, SHA1: 40, SHA256: 64)
  if (/^[a-fA-F0-9]{32}$/.test(clean) || /^[a-fA-F0-9]{40}$/.test(clean) || /^[a-fA-F0-9]{64}$/.test(clean)) {
    return { type: "hash", clean };
  }
  // URL
  if (/^https?:\/\//i.test(clean)) {
    return { type: "url", clean };
  }
  // Domain
  if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(clean)) {
    return { type: "domain", clean };
  }
  return { type: "unknown", clean };
}

// Helper: Base64URL encode for VT URL ID
function urlToVtId(url) {
  try {
    const b64 = btoa(url);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (e) {
    return encodeURIComponent(url);
  }
}

// Storage Helpers
async function getApiKey() {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_api_key"], res => resolve(res.vt_api_key || null));
  });
}

async function getCache(ioc) {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_cache"], res => {
      const cache = res.vt_cache || {};
      const entry = cache[ioc];
      if (!entry) return resolve(null);
      if (Date.now() - entry.ts > CACHE_TTL_MS) return resolve(null);
      resolve(entry.data);
    });
  });
}

async function saveCache(ioc, data) {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_cache"], res => {
      const cache = res.vt_cache || {};
      cache[ioc] = { ts: Date.now(), data };
      chrome.storage.local.set({ vt_cache: cache }, () => resolve(true));
    });
  });
}

// Query VT API for any IOC Type
async function vtLookup(rawIoc, apiKey) {
  const { type, clean } = detectIOCType(rawIoc);
  if (type === "unknown") {
    return { error: "Unsupported or invalid IOC format" };
  }

  let endpoint = "";
  if (type === "ip") endpoint = `${VT_API_BASE}ip_addresses/${encodeURIComponent(clean)}`;
  else if (type === "domain") endpoint = `${VT_API_BASE}domains/${encodeURIComponent(clean)}`;
  else if (type === "hash") endpoint = `${VT_API_BASE}files/${encodeURIComponent(clean)}`;
  else if (type === "url") endpoint = `${VT_API_BASE}urls/${urlToVtId(clean)}`;

  try {
    const res = await fetch(endpoint, {
      headers: { "x-apikey": apiKey }
    });

    if (res.status === 429) {
      return { error: "Rate limit reached (4 req/min for free key). Please try again shortly." };
    }
    if (res.status === 401 || res.status === 403) {
      return { error: "Invalid API Key or forbidden" };
    }
    if (res.status === 404) {
      return {
        ioc: clean,
        type,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        vendors: 0,
        date: "Not Found in VT",
        tags: [],
        raw: null
      };
    }
    if (!res.ok) {
      return { error: `VT API HTTP ${res.status}` };
    }

    const json = await res.json();
    const attr = json.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const results = attr.last_analysis_results || {};
    const vendors = Object.keys(results).length;
    const lastScanUnix = attr.last_analysis_date || null;

    // Enrichment extraction
    const asn = attr.asn ? `AS${attr.asn} (${attr.as_owner || ''})` : null;
    const network = attr.network || null;
    const registrar = attr.registrar || null;
    const country = attr.country || null;
    const whois = attr.whois ? attr.whois.trim().split('\n').slice(0, 3).join(' • ') : null;
    const tags = Array.isArray(attr.tags) ? attr.tags.slice(0, 5) : [];
    const categories = attr.categories ? Object.values(attr.categories).slice(0, 3) : [];
    const reputation = attr.reputation !== undefined ? attr.reputation : null;

    return {
      ioc: clean,
      type,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      vendors,
      date: lastScanUnix ? new Date(lastScanUnix * 1000).toLocaleString() : "Unknown",
      asn,
      network,
      registrar,
      country,
      whois,
      tags: [...new Set([...tags, ...categories])].slice(0, 5),
      reputation,
      raw: json
    };
  } catch (err) {
    return { error: "Network communication error" };
  }
}

// Message Listener
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;

  if (msg.type === "vt_query") {
    const rawIoc = msg.ioc;
    const cleanIoc = undefang(rawIoc);
    (async () => {
      const cached = await getCache(cleanIoc);
      if (cached) {
        sendResponse(cached);
        return;
      }
      const key = await getApiKey();
      if (!key) {
        sendResponse({ error: "Missing API key. Set your key in extension settings." });
        return;
      }
      const data = await vtLookup(cleanIoc, key);
      if (data && !data.error) {
        await saveCache(cleanIoc, data);
      }
      sendResponse(data);
    })();
    return true;
  }

  if (msg.type === "vt_rescan") {
    const rawIoc = msg.ioc;
    const cleanIoc = undefang(rawIoc);
    (async () => {
      const key = await getApiKey();
      if (!key) {
        sendResponse({ error: "Missing API key" });
        return;
      }
      try {
        const { type } = detectIOCType(cleanIoc);
        let endpoint = `${VT_API_BASE}ip_addresses/${encodeURIComponent(cleanIoc)}/analyse`;
        if (type === "files" || type === "hash") endpoint = `${VT_API_BASE}files/${encodeURIComponent(cleanIoc)}/analyse`;
        else if (type === "domain") endpoint = `${VT_API_BASE}domains/${encodeURIComponent(cleanIoc)}/analyse`;

        await fetch(endpoint, {
          method: "POST",
          headers: { "x-apikey": key }
        });

        // Clear cache
        chrome.storage.local.get(["vt_cache"], res => {
          const cache = res.vt_cache || {};
          delete cache[cleanIoc];
          chrome.storage.local.set({ vt_cache: cache }, () => {
            sendResponse({ ok: true });
          });
        });
      } catch (err) {
        sendResponse({ error: "Rescan error" });
      }
    })();
    return true;
  }
});

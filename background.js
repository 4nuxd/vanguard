// background.js
// VirusTotal API wrapper + cache + rescan
// MV3 service worker (type module enabled in manifest)

// Configuration
const VT_IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"; // ip endpoint
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// helper: get api key
async function getApiKey() {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_api_key"], res => resolve(res.vt_api_key || null));
  });
}

// helper: get cache entry
async function getCache(ioc) {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_cache"], res => {
      const cache = res.vt_cache || {};
      const entry = cache[ioc];
      if (!entry) return resolve(null);
      const age = Date.now() - entry.ts;
      if (age > CACHE_TTL_MS) return resolve(null);
      resolve(entry.data);
    });
  });
}

// helper: save cache entry
async function saveCache(ioc, data) {
  return new Promise(resolve => {
    chrome.storage.local.get(["vt_cache"], res => {
      const cache = res.vt_cache || {};
      cache[ioc] = { ts: Date.now(), data };
      chrome.storage.local.set({ vt_cache: cache }, () => resolve(true));
    });
  });
}

// Query VT IP endpoint and normalize returned stats
async function vtLookupIP(ip, apiKey) {
  try {
    const res = await fetch(VT_IP_ENDPOINT + encodeURIComponent(ip), {
      headers: { "x-apikey": apiKey }
    });
    if (!res.ok) {
      return { error: `VT API error ${res.status}` };
    }
    const json = await res.json();

    const stats = json.data?.attributes?.last_analysis_stats || {};
    const vendors = json.data?.attributes?.last_analysis_results
      ? Object.keys(json.data.attributes.last_analysis_results).length
      : 0;
    const lastScanUnix = json.data?.attributes?.last_analysis_date || null;

    return {
      ip,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      vendors,
      date: lastScanUnix ? new Date(lastScanUnix * 1000).toLocaleString() : "Unknown",
      raw: json
    };
  } catch (err) {
    return { error: "Network error" };
  }
}

// Message handling
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) {
    return;
  }

  // vt_query -> return cached or fetch & cache
  if (msg.type === "vt_query") {
    const ioc = msg.ioc;
    (async () => {
      // Try cache first
      const cached = await getCache(ioc);
      if (cached) {
        sendResponse(cached);
        return;
      }

      const key = await getApiKey();
      if (!key) {
        sendResponse({ error: "Missing API key" });
        return;
      }

      const data = await vtLookupIP(ioc, key);
      if (!data || data.error) {
        sendResponse(data || { error: "Unknown error" });
        return;
      }

      await saveCache(ioc, data);
      sendResponse(data);
    })();
    // return true to indicate async response
    return true;
  }

  // vt_rescan -> fire rescan request (IP rescan endpoint is not standard for ip_addresses,
  // typically VT supports file rescan; for IP, we'll call a generic analyse endpoint if available)
  if (msg.type === "vt_rescan") {
    const ioc = msg.ioc;
    (async () => {
      const key = await getApiKey();
      if (!key) {
        sendResponse({ error: "Missing API key" });
        return;
      }
      try {
        // VirusTotal doesn't have a dedicated ip rescan endpoint like files,
        // but some endpoints accept POST to request reanalysis. We'll attempt a POST to ip endpoint.
        await fetch(VT_IP_ENDPOINT + encodeURIComponent(ioc) + "/analyse", {
          method: "POST",
          headers: { "x-apikey": key }
        });
        // Remove cached entry so next hover will pull fresh
        chrome.storage.local.get(["vt_cache"], res => {
          const cache = res.vt_cache || {};
          delete cache[ioc];
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

  // support other message types if needed
});

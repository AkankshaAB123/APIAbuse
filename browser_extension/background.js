function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Keep track of URLs we've already scanned to prevent infinite loops
const scannedUrls = new Set();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only scan main frame navigations (the main URL in the URL bar)
  if (details.frameId !== 0) return;
  
  const urlObj = new URL(details.url);
  
  // Ignore local extensions and the backend itself
  if (urlObj.protocol === 'chrome-extension:' || urlObj.hostname === 'localhost') return;
  
  if (scannedUrls.has(details.url)) return;
  scannedUrls.add(details.url);
  
  // Extract query params
  const queryParams = {};
  for (const [key, value] of urlObj.searchParams.entries()) {
    queryParams[key] = value;
  }
  
  // Build the ApiSecurityEvent payload for our IDS
  const payload = {
    event_id: "EXT-NAV-" + generateUUID().substring(0, 8),
    timestamp: new Date().toISOString(),
    network: {
source_ip: "192.168.43.46",
      user_agent: navigator.userAgent
    },
    identity: {
      user_id: "browser_user",
      is_authenticated: false
    },
    request: {
      method: "GET",
      endpoint: details.url,
      query_params: queryParams,
      headers: {},
      body: { url: details.url }
    },
    response: {
      status_code: 200,
      latency_ms: 0
    },
    resource: {
      resource_type: "browser_navigation",
      is_sensitive: false
    }
  };

  try {
const response = await fetch("http://192.168.43.46:8000/events", {      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const result = await response.json();
      
      // Check detected attack types and mitigation action
      const detectors = result.detector_results || [];
      const xssDetected = detectors.some(d => d.detected && d.attack_type === "XSS");
      const malUrlDetected = detectors.some(d => d.detected && d.attack_type === "MALICIOUS_URL");
      const phishingDetected = detectors.some(d => d.detected && d.attack_type === "PHISHING");
      const isUrlBlock = result.mitigation_action === "URL_BLOCK";
      
      if (xssDetected || malUrlDetected || phishingDetected || isUrlBlock) {
        const attackLabel = (phishingDetected || isUrlBlock)
          ? "Phishing"
          : (xssDetected ? "XSS" : "Malicious URL");

        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "ThreatGuard Alert!",
          message: `Blocked a potential ${attackLabel} attack on ${urlObj.hostname}!`
        });
        
        // Block the page by redirecting to blocked.html
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`blocked.html?type=${attackLabel}&url=${encodeURIComponent(details.url)}`)
        });
        
        // Save to storage for the popup
        chrome.storage.local.get({ threats: [] }, (data) => {
          const threats = data.threats;
          threats.unshift({
            url: details.url,
            type: attackLabel,
            time: new Date().toLocaleTimeString()
          });
          chrome.storage.local.set({ threats: threats.slice(0, 10) });
        });
      }
    }
  } catch (error) {
    console.error("Failed to reach ThreatGuard backend:", error);
  }
});

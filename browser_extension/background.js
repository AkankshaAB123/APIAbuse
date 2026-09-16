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
  
  // If there are no query parameters, it's less likely to be a reflected XSS attack in a simple GET
  if (urlObj.search === '') return;
  
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
      source_ip: "127.0.0.1",
      user_agent: navigator.userAgent
    },
    identity: {
      user_id: "browser_user",
      is_authenticated: false
    },
    request: {
      method: "GET",
      endpoint: urlObj.pathname,
      query_params: queryParams,
      headers: {},
      body: null
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
    const response = await fetch("http://localhost:8000/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const result = await response.json();
      
      // Check if XSS was detected
      const detectors = result.detector_results || [];
      const xssDetected = detectors.some(d => d.detected && d.attack_type === "XSS");
      const malUrlDetected = detectors.some(d => d.detected && d.attack_type === "MALICIOUS_URL");
      
      if (xssDetected || malUrlDetected) {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "ThreatGuard Alert!",
          message: `Blocked a potential ${xssDetected ? "XSS" : "Malicious URL"} attack on ${urlObj.hostname}!`
        });
        
        // Block the page by redirecting to blocked.html
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`blocked.html?type=${xssDetected ? "XSS" : "Malicious URL"}&url=${encodeURIComponent(details.url)}`)
        });
        
        // Save to storage for the popup
        chrome.storage.local.get({ threats: [] }, (data) => {
          const threats = data.threats;
          threats.unshift({
            url: details.url,
            type: xssDetected ? "XSS" : "Malicious URL",
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

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:8000";

const AUTH_TOKEN_KEY = "threatguardToken";

/* =========================
   TOKEN STORAGE HELPERS
========================= */

export function getAuthToken() {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAuthToken(token) {
  try {
    if (token) {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  } catch {
    // ignore
  }
}

export function clearAuthSession() {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem("threatguardUser");
  } catch {
    // ignore
  }
}

/* =========================
   COMMON API REQUEST
========================= */

async function apiRequest(endpoint, options = {}) {
  const token = getAuthToken();
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  };

  // Inject Bearer token if present and not already provided
  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    // Cleanly handle expired or invalid session tokens
    if (response.status === 401 && !endpoint.includes("/auth/login")) {
      clearAuthSession();
      // Only dispatch event or redirect if running in browser window
      if (typeof window !== "undefined" && window.location.pathname !== "/login") {
        window.dispatchEvent(new CustomEvent("threatguard:session_expired"));
      }
    }

    let errorMessage = `API Error: ${response.status} ${response.statusText}`;
    try {
      const errorData = await response.json();
      if (errorData?.detail) {
        errorMessage = typeof errorData.detail === "string"
          ? errorData.detail
          : JSON.stringify(errorData.detail);
      }
    } catch {
      // Keep default message
    }

    const err = new Error(errorMessage);
    err.status = response.status;
    throw err;
  }

  return response.json();
}

/* =========================
   AUTHENTICATION API
========================= */

export async function loginUser(username, password) {
  const result = await apiRequest("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  if (result?.access_token) {
    setAuthToken(result.access_token);
  }
  return result;
}


export async function registerUser(username, password, name = "") {
  const result = await apiRequest("/auth/register", {
    method: "POST",
    body: JSON.stringify({ username, password, name }),
  });

  if (result?.access_token) {
    setAuthToken(result.access_token);
  }
  return result;
}

export async function getCurrentUserProfile() {
  return apiRequest("/auth/me");
}

/* =========================
   PROCESS SECURITY EVENT
========================= */

export async function processEvent(event, mlFeatures = null) {
  return apiRequest("/events", {
    method: "POST",
    body: JSON.stringify({
      event,
      ml_features: mlFeatures,
    }),
  });
}

/* =========================
   GET ALL THREATS
========================= */

export async function getThreats(deviceIp = null) {
  // If deviceIp is provided (e.g. for SOC staff filtering), pass it.
  // For DEVICE role users, backend will enforce its device_ip from the JWT regardless.
  const qs = deviceIp ? `?device_ip=${encodeURIComponent(deviceIp)}` : "";
  return apiRequest(`/threats${qs}`);
}

/* =========================
   GET SINGLE THREAT
========================= */

export async function getThreatById(id, deviceIp = null) {
  const qs = deviceIp ? `?device_ip=${encodeURIComponent(deviceIp)}` : "";
  return apiRequest(`/threats/${id}${qs}`);
}

/* =========================
   GET STATISTICS
========================= */

export async function getStatistics() {
  return apiRequest("/statistics");
}

/* =========================
   LAUNCH CONTROLLED LAB ATTACK
========================= */

export async function launchLabAttack(endpoint) {
  return apiRequest(endpoint, {
    method: "POST",
  });
}

export async function launchSyntheticPhishingEmail(email) {
  return apiRequest("/lab/attacks/phishing-email", {
    method: "POST",
    body: JSON.stringify(email),
  });
}

/* =========================
   EXPORT BASE URL
========================= */

export { API_BASE_URL };

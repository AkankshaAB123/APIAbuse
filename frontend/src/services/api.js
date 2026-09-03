const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:8000";


/* =========================
   COMMON API REQUEST
========================= */

async function apiRequest(endpoint, options = {}) {

  const response = await fetch(
    `${API_BASE_URL}${endpoint}`,
    {
      headers: {
        "Content-Type": "application/json",
        ...options.headers
      },
      ...options
    }
  );

  if (!response.ok) {
    let errorMessage = `API Error: ${response.status} ${response.statusText}`;

    try {
      const errorData = await response.json();

      if (errorData?.detail) {
        errorMessage += ` - ${JSON.stringify(errorData.detail)}`;
      }
    } catch {
      // Keep the default error message if response is not JSON
    }

    throw new Error(errorMessage);
  }

  return response.json();
}


/* =========================
   PROCESS SECURITY EVENT
========================= */

export async function processEvent(event, mlFeatures = null) {

  return apiRequest("/events", {
    method: "POST",
    body: JSON.stringify({
      event,
      ml_features: mlFeatures
    })
  });

}


/* =========================
   GET ALL THREATS
========================= */

export async function getThreats() {

  return apiRequest("/threats");

}


/* =========================
   GET SINGLE THREAT
========================= */

export async function getThreatById(id) {

  return apiRequest(
    `/threats/${id}`
  );

}


/* =========================
   GET STATISTICS
========================= */

export async function getStatistics() {

  return apiRequest("/statistics");

}


/* =========================
   EXPORT BASE URL
========================= */

export { API_BASE_URL };
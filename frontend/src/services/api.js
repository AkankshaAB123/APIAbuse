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
    throw new Error(
      `API Error: ${response.status} ${response.statusText}`
    );
  }

  return response.json();
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
const API_BASE = "http://localhost:8000/api";

async function fetchJson(url: string, options?: RequestInit) {
  const token = localStorage.getItem("sniff_token");
  const headers = new Headers(options?.headers || {});
  
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const detail = errData && errData.detail;
    const msg = typeof detail === "string" ? detail : (detail && detail.message) || "API request failed";
    const err: any = new Error(msg);
    if (detail && typeof detail === "object" && detail.code) err.code = detail.code;
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const api = {
  // Auth endpoints
  auth: {
    signup: (data: { username: string; email: string; password: string }) =>
      fetchJson(`${API_BASE}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    login: (data: { username_or_email: string; password: string }) =>
      fetchJson(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    googleAuth: (data: { credential?: string; email?: string; name?: string; google_id?: string; avatar_url?: string }) =>
      fetchJson(`${API_BASE}/auth/google`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    getGoogleConfig: () => fetchJson(`${API_BASE}/auth/google/config`),
    me: () => fetchJson(`${API_BASE}/auth/me`),
  },

  ownership: {
    challenge: (url: string) =>
      fetchJson(`${API_BASE}/ownership/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      }),
    verify: (url: string, method: "file" | "dns") =>
      fetchJson(`${API_BASE}/ownership/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, method }),
      }),
    status: (url: string) =>
      fetchJson(`${API_BASE}/ownership/status?url=${encodeURIComponent(url)}`),
  },
  getDashboard: () => fetchJson(`${API_BASE}/dashboard`),
  getMissions: () => fetchJson(`${API_BASE}/missions`),
  getMissionDetail: (id: string) => fetchJson(`${API_BASE}/missions/${id}`),
  getMissionTimeline: (id: string) => fetchJson(`${API_BASE}/missions/${id}/timeline`),
  startScan: (url: string, maxPages: number = 5) => fetchJson(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, max_pages: maxPages })
  }),
  getFindings: (severity?: string, category?: string, search?: string) => {
    const params = new URLSearchParams();
    if (severity && severity !== "all") params.append("severity", severity);
    if (category && category !== "all") params.append("category", category);
    if (search) params.append("search", search);
    return fetchJson(`${API_BASE}/findings?${params.toString()}`);
  },
  getReports: () => fetchJson(`${API_BASE}/reports`),
  getReportDetail: (id: string) => fetchJson(`${API_BASE}/reports/${id}`),
  getMetrics: () => fetchJson(`${API_BASE}/metrics`),
  getMemorySummary: () => fetchJson(`${API_BASE}/memory/summary`),
  searchMemory: (query: string, collection: string = "findings") => {
    const params = new URLSearchParams({ query, collection });
    return fetchJson(`${API_BASE}/memory/search?${params.toString()}`);
  },
};
export type ApiService = typeof api;

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("vigil_access_token");
}

export function setToken(access: string, refresh: string) {
  localStorage.setItem("vigil_access_token", access);
  localStorage.setItem("vigil_refresh_token", refresh);
}

export function clearToken() {
  localStorage.removeItem("vigil_access_token");
  localStorage.removeItem("vigil_refresh_token");
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401 && typeof window !== "undefined") {
    window.location.href = "/login";
  }
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

// ── Types ──────────────────────────────────────────────────
export interface Finding {
  id: string;
  title: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  scanner: string;
  scanner_rule_id?: string;
  cvss?: number;
  cwe?: string;
  owasp_category?: string;
  target_ref?: string;
  file_path?: string;
  line_start?: number;
  code_snippet?: string;
  status: string;
  created_at?: string;
  ai_triage?: {
    fp_score?: number;
    risk_score?: number;
    explanation?: string;
    remediation?: string;
    mitre_tactics?: string[];
    mitre_techniques?: string[];
    owasp_id?: string;
    triage_method?: string;
  };
}

export interface Scan {
  id: string;
  project_id: string;
  target_id: string;
  status: string;
  scan_type: string;
  progress: number;
  started_at?: string;
  finished_at?: string;
  created_at?: string;
  finding_count?: number;
  tasks?: { scanner: string; status: string; finding_count: number; duration_sec?: number }[];
}

export interface DashboardStats {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  fp_rate: number;
  by_scanner: Record<string, number>;
  by_owasp: Record<string, number>;
  recent_scans: { id: string; status: string; progress: number; created_at?: string }[];
}

// ── Auth ───────────────────────────────────────────────────
export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string; refresh_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (email: string, password: string) =>
    request("/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),

  // ── Stats ────────────────────────────────────────────────
  dashboard: () => request<DashboardStats>("/stats/dashboard"),

  // ── Scans ────────────────────────────────────────────────
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  createScan: (project_id: string, target_id: string, scanners: string[] = []) =>
    request<Scan>("/scans", {
      method: "POST",
      body: JSON.stringify({ project_id, target_id, scanners }),
    }),

  // ── Findings ─────────────────────────────────────────────
  listFindings: (params: Record<string, string> = {}) =>
    request<Finding[]>(`/findings?${new URLSearchParams(params).toString()}`),
  getFinding: (id: string) => request<Finding>(`/findings/${id}`),
  updateFinding: (id: string, status: string) =>
    request<Finding>(`/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  reTriage: (id: string) => request(`/findings/${id}/triage/re-run`, { method: "POST" }),

  // ── Repositories ─────────────────────────────────────────
  scanRepo: (repo_url: string) =>
    request<Scan>(`/repositories/scan?repo_url=${encodeURIComponent(repo_url)}`, { method: "POST" }),
  listRepos: () => request<{ id: string; name: string; type: string }[]>("/repositories"),

  // ── Projects ─────────────────────────────────────────────
  listProjects: () => request<{ id: string; name: string; type: string }[]>("/projects"),
  listTargets: (projectId: string) =>
    request<{ id: string; kind: string; value: string }[]>(`/projects/${projectId}/targets`),
};

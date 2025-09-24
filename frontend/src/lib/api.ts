// src/lib/api.ts
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

function authHeaders(token?: string) {
  const t = token ?? localStorage.getItem("dc_token") ?? "";
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function handle(res: Response) {
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${text ? ` – ${text}` : ""}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

export async function getJson<T = any>(path: string, token?: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { accept: "application/json", ...authHeaders(token) },
    credentials: "omit",
  });
  return handle(res);
}

export async function postJson<T = any>(path: string, body: unknown, token?: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders(token) },
    body: JSON.stringify(body),
    credentials: "omit",
  });
  return handle(res);
}

export async function postForm<T = any>(path: string, form: FormData, token?: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { ...authHeaders(token) },
    body: form,
    credentials: "omit",
  });
  return handle(res);
}

/* ---------- OTP ---------- */
export function requestOtp(email: string, role: "citizen" | "cert" = "citizen") {
  return postJson("/auth/request-otp", { email, role });
}
export function verifyOtp(email: string, code: string) {
  return postJson("/auth/verify-otp", { email, code });
}

/* ---------- User ---------- */
export function getWhoAmI(token?: string) {
  return getJson("/whoami", token);
}

/* ---------- Complaints ---------- */
export function listMyComplaints(token?: string) {
  return getJson("/complaints/mine", token);
}
export function listCertComplaints(token?: string) {
  return getJson("/cert/complaints", token);
}
export function getComplaint(id: number | string, token?: string) {
  return getJson(`/complaints/${id}`, token);
}

export async function createComplaint(
  file: File,
  severity: number,
  opts: { title?: string; story?: string } = {},
  token?: string
) {
  const form = new FormData();
  form.append("file", file);
  form.append("severity_code", String(severity));
  if (opts.title) form.append("title", opts.title);
  if (opts.story) form.append("story", opts.story);
  return postForm("/complaints/create", form, token);
}

export async function uploadEvidence(
  complaintId: number | string,
  file: File,
  token?: string
) {
  const form = new FormData();
  form.append("complaint_id", String(complaintId));
  form.append("file", file);
  return postForm("/evidence/upload", form, token);
}

export async function recordAnalysis(
  complaintId: number | string,
  labelCode: number,
  severityCode: number,
  analysisFile: File,
  token?: string
) {
  const form = new FormData();
  form.append("complaint_id", String(complaintId));
  form.append("label_code", String(labelCode));
  form.append("severity_code", String(severityCode));
  form.append("analysis_json", analysisFile);
  return postForm("/analysis/record", form, token);
}

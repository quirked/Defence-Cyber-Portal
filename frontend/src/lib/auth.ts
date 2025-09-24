const TOKEN_KEY = "dc_token";
const ROLE_KEY = "dc_role";

export function saveAuth(token: string, role: "citizen" | "cert") {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ROLE_KEY, role);
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRole(): "citizen" | "cert" | null {
  return (localStorage.getItem(ROLE_KEY) as any) || null;
}

export function isAuthed(): boolean {
  return !!getToken();
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
  window.location.href = "/login";
}

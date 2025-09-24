import { createContext, useContext, useEffect, useMemo, useState } from "react";
import api from "../lib/api";
import jwtDecode from "jwt-decode";

type User = { id: number; email: string; role: string };
type Decoded = { sub: string; email: string; role: string; exp: number };

type AuthCtx = {
  user: User | null;
  token: string | null;
  requestOtp: (email: string, role: "citizen" | "cert") => Promise<void>;
  verifyOtp: (email: string, code: string) => Promise<void>;
  logout: () => void;
};

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("dc_token"));
  const [user, setUser] = useState<User | null>(null);

  // on first load, try to recover user from token (so refresh doesn't log you out)
  useEffect(() => {
    if (!token) return;
    try {
      const d = jwtDecode<Decoded>(token);
      if (d.exp * 1000 < Date.now()) {
        localStorage.removeItem("dc_token");
        setToken(null);
        setUser(null);
      } else {
        // we don’t have id from token in our backend payload, but verify endpoint returns user.
        // fall back to email/role from token; id will be filled on next successful verify.
        setUser((u) => u ?? { id: 0, email: d.email, role: d.role });
      }
    } catch {
      localStorage.removeItem("dc_token");
      setToken(null);
      setUser(null);
    }
  }, [token]);

  const requestOtp = async (email: string, role: "citizen" | "cert") => {
    await api.post("/auth/request-otp", { email, role });
  };

  const verifyOtp = async (email: string, code: string) => {
    const { data } = await api.post("/auth/verify-otp", { email, code });
    if (!data?.ok) throw new Error("OTP verification failed");
    localStorage.setItem("dc_token", data.token);
    setToken(data.token);
    setUser(data.user); // {id,email,role}
  };

  const logout = () => {
    localStorage.removeItem("dc_token");
    setToken(null);
    setUser(null);
  };

  const value = useMemo(() => ({ user, token, requestOtp, verifyOtp, logout }), [user, token]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAuth = () => {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used inside <AuthProvider>");
  return v;
};

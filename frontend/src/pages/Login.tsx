import { useState } from "react";
import { requestOtp, verifyOtp } from "../lib/api";
import { saveAuth } from "../lib/auth";

export default function Login() {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"citizen" | "cert">("citizen");
  const [code, setCode] = useState("");
  const [phase, setPhase] = useState<"ask" | "otp">("ask");
  const [msg, setMsg] = useState("");

  async function sendOtp() {
    setMsg("");
    try {
      await requestOtp(email, role);
      setPhase("otp");
      setMsg("OTP sent. Check Mailpit (http://localhost:8025).");
    } catch (e: any) {
      setMsg(e.message || "Failed to request OTP");
    }
  }

  async function doLogin() {
    setMsg("");
    try {
      const json = await verifyOtp(email, code);
      if (json.ok && json.token) {
        const r = (json.user?.role || role) as "citizen" | "cert";
        saveAuth(json.token, r);
        window.location.href = r === "cert" ? "/cert" : "/citizen";
      } else {
        setMsg("Invalid response from server");
      }
    } catch (e: any) {
      setMsg(e.message || "Failed to verify OTP");
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h1>Sign in</h1>

      {phase === "ask" && (
        <>
          <label>Email</label>
          <input
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ display: "block", margin: "6px 0" }}
          />

          <label>Role</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as any)}
            style={{ display: "block", marginBottom: 12 }}
          >
            <option value="citizen">Citizen</option>
            <option value="cert">CERT</option>
          </select>

          <button onClick={sendOtp}>Send Code</button>
        </>
      )}

      {phase === "otp" && (
        <>
          <label>Enter code</label>
          <input
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            style={{ display: "block", margin: "6px 0" }}
          />
          <button onClick={doLogin}>Verify & Login</button>
        </>
      )}

      {msg && <p style={{ color: "#444" }}>{msg}</p>}
    </div>
  );
}

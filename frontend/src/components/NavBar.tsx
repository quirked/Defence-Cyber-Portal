import { Link } from "react-router-dom";
import { isAuthed, getRole, logout } from "../lib/auth";

export default function NavBar() {
  const authed = isAuthed();
  const role = getRole();

  return (
    <div style={{ padding: 8, borderBottom: "1px solid #ddd" }}>
      <Link to="/" style={{ marginRight: 12 }}>Home</Link>
      {!authed && <Link to="/login" style={{ marginRight: 12 }}>Login</Link>}
      {authed && role === "citizen" && (
        <Link to="/citizen" style={{ marginRight: 12 }}>Citizen</Link>
      )}
      {authed && role === "cert" && (
        <Link to="/cert" style={{ marginRight: 12 }}>CERT</Link>
      )}
      {authed && <button onClick={logout}>Logout</button>}
    </div>
  );
}

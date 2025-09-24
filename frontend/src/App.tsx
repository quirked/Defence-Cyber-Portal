import { BrowserRouter, Routes, Route, Navigate, Link } from "react-router-dom";
import Login from "./pages/Login";
import CitizenDashboard from "./pages/CitizenDashboard";
import CertDashboard from "./pages/CertDashboard";
import SubmitComplaint from "./pages/SubmitComplaint";
import ComplaintDetail from "./pages/ComplaintDetail";
import { isAuthed, getRole, logout } from "./lib/auth";

function Guard({ children }: { children: JSX.Element }) {
  return isAuthed() ? children : <Navigate to="/login" replace />;
}

function RoleOnly({ role, children }: { role: "citizen" | "cert"; children: JSX.Element }) {
  if (!isAuthed()) return <Navigate to="/login" replace />;
  return getRole() === role ? children : <Navigate to="/" replace />;
}

export default function App() {
  const homeDest = isAuthed() ? (getRole() === "cert" ? "/cert" : "/citizen") : "/login";

  return (
    <BrowserRouter>
      <div style={{ padding: 12, borderBottom: "1px solid #ddd" }}>
        <Link to="/">Home</Link>{" "}
        <Link to="/login">Login</Link>{" "}
        <Link to="/citizen">Citizen</Link>{" "}
        <Link to="/cert">CERT</Link>{" "}
        {isAuthed() && (
          <button
            onClick={() => {
              logout();
              window.location.href = "/";
            }}
          >
            Logout
          </button>
        )}
      </div>

      <Routes>
        <Route path="/" element={<Navigate to={homeDest} replace />} />
        <Route path="/login" element={<Login />} />

        <Route path="/citizen" element={<Guard><CitizenDashboard /></Guard>} />
        <Route path="/citizen/new" element={<Guard><SubmitComplaint /></Guard>} />
        <Route path="/complaints/:id" element={<Guard><ComplaintDetail /></Guard>} />

        <Route path="/cert" element={<RoleOnly role="cert"><CertDashboard /></RoleOnly>} />
      </Routes>
    </BrowserRouter>
  );
}

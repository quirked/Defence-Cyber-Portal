import { Link } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

export default function CitizenDashboard() {
  const { user, logout } = useAuth();
  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Citizen dashboard</h1>
        <div className="text-sm">Signed in as <b>{user?.email}</b> ({user?.role})</div>
        <button className="border rounded px-3 py-1" onClick={logout}>Log out</button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl p-4 shadow bg-white">Submitted: 0</div>
        <div className="rounded-xl p-4 shadow bg-white">In progress: 0</div>
        <div className="rounded-xl p-4 shadow bg-white">Resolved: 0</div>
      </div>
      <Link to="/submit" className="inline-block mt-4 rounded bg-emerald-600 text-white px-4 py-2">
        Submit a complaint
      </Link>
    </div>
  );
}

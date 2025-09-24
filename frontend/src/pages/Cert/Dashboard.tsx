import { useAuth } from "../../context/AuthContext";

export default function CertDashboard() {
  const { user, logout } = useAuth();
  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">CERT dashboard</h1>
        <div className="text-sm">Signed in as <b>{user?.email}</b> ({user?.role})</div>
        <button className="border rounded px-3 py-1" onClick={logout}>Log out</button>
      </div>
      <div className="rounded-xl p-4 shadow bg-white">
        {/* table will go here later */}
        <div className="text-gray-600">No items yet.</div>
      </div>
    </div>
  );
}

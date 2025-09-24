import { useEffect, useState } from "react";
import { listMyComplaints } from "../lib/api";
import { getToken } from "../lib/auth";
import { Link } from "react-router-dom";

export default function CitizenDashboard() {
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const json = await listMyComplaints(getToken() || undefined);
        setData(json);
      } catch (e: any) {
        setErr(e.message || "Failed to load");
      }
    })();
  }, []);

  if (err) return <div style={{ padding: 24 }}>Error: {err}</div>;
  if (!data) return <div style={{ padding: 24 }}>Loading…</div>;

  return (
    <div style={{ padding: 24 }}>
      <h1>Your dashboard (Citizen)</h1>

      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <div>Submitted<br />{data.counts.submitted}</div>
        <div>In progress<br />{data.counts.in_progress}</div>
        <div>Resolved<br />{data.counts.resolved}</div>
      </div>

      <Link to="/citizen/new">New complaint</Link>

      <h2 style={{ marginTop: 16 }}>Complaints</h2>
      {data.items.length === 0 ? (
        <p>No items</p>
      ) : (
        <table cellPadding={6}>
          <thead>
            <tr>
              <th>Human ID</th>
              <th>Title</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((r: any) => (
              <tr key={r.id}>
                <td><Link to={`/complaints/${r.id}`}>{r.human_id || r.id}</Link></td>
                <td>{r.title}</td>
                <td>{r.status}</td>
                <td>{r.severity ?? "-"}</td>
                <td>{new Date(r.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

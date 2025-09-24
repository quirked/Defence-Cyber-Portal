import { useEffect, useState } from "react";
import { listCertComplaints } from "../lib/api";
import { getToken } from "../lib/auth";
import { Link } from "react-router-dom";

export default function CertDashboard() {
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const json = await listCertComplaints(getToken() || undefined);
        setRows(json.items);
      } catch (e: any) {
        setErr(e.message || "Failed to load");
      }
    })();
  }, []);

  if (err) return <div style={{ padding: 24 }}>Error: {err}</div>;
  if (!rows) return <div style={{ padding: 24 }}>Loading…</div>;

  return (
    <div style={{ padding: 24 }}>
      <h1>CERT workload</h1>
      <table cellPadding={6}>
        <thead>
          <tr>
            <th>Human ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Label</th>
            <th>Severity</th>
            <th>Reporter</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><Link to={`/complaints/${r.id}`}>{r.human_id || r.id}</Link></td>
              <td>{r.title}</td>
              <td>{r.status}</td>
              <td>{r.label_code ?? "-"}</td>
              <td>{r.severity_code ?? "-"}</td>
              <td>{r.reporter_email}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import { getToken, getRole } from "../lib/auth";
import { listMyComplaints, listCertComplaints } from "../lib/api";
import { Link } from "react-router-dom";

type Item = { id:number; title:string; status:string; severity_initial:number; created_at:string; label_code?:number };

export default function Dashboard() {
  const role = getRole();
  const [items, setItems] = useState<Item[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    const t = getToken()!;
    const p = role === "cert" ? listCertComplaints(t) : listMyComplaints(t);
    p.then((r:any) => setItems(r.items || [])).catch((e:any)=>setErr(String(e)));
  }, [role]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const it of items) c[it.status] = (c[it.status]||0) + 1;
    return c;
  }, [items]);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">{role === "cert" ? "CERT Dashboard" : "My Dashboard"}</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {["submitted","in_progress","resolved"].map(s=>(
          <div key={s} className="border rounded p-4">
            <div className="text-sm uppercase text-gray-500">{s.replace("_"," ")}</div>
            <div className="text-3xl font-bold">{counts[s] || 0}</div>
          </div>
        ))}
      </div>

      {role !== "cert" && (
        <Link to="/submit" className="inline-block px-4 py-2 bg-emerald-600 text-white rounded">+ New Complaint</Link>
      )}

      {err && <pre className="text-red-600">{err}</pre>}

      <div className="border rounded">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-black/5">
              <th className="p-2 text-left">ID</th>
              <th className="p-2 text-left">Title</th>
              <th className="p-2">Status</th>
              <th className="p-2">Severity</th>
              {role==="cert" && <th className="p-2">AI label</th>}
              <th className="p-2"></th>
            </tr>
          </thead>
          <tbody>
            {items.map(it=>(
              <tr key={it.id} className="border-t">
                <td className="p-2">{it.id}</td>
                <td className="p-2">{it.title}</td>
                <td className="p-2 text-center">{it.status}</td>
                <td className="p-2 text-center">{it.severity_initial}</td>
                {role==="cert" && <td className="p-2 text-center">{it.label_code ?? "-"}</td>}
                <td className="p-2 text-right">
                  <Link to={`/complaints/${it.id}`} className="underline">View</Link>
                </td>
              </tr>
            ))}
            {items.length===0 && <tr><td className="p-4 text-center text-gray-500" colSpan={role==="cert"?6:5}>No items</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import { useState } from "react";
import { postFormAuth } from "../lib/api";

export default function AddEvidence() {
  const [cid, setCid] = useState(localStorage.getItem("last_cid") || "");
  const [file, setFile] = useState<File|null>(null);
  const [resp, setResp] = useState<any>(null);
  const [err, setErr] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setResp(null);
    if (!cid) return setErr("Complaint ID is required.");
    if (!file) return setErr("Attach a file.");

    const form = new FormData();
    form.append("complaint_id", cid);
    form.append("file", file);

    try {
      const json = await postFormAuth("/evidence/upload", form);
      setResp(json);
    } catch (e:any) {
      setErr(e.message || String(e));
    }
  }

  return (
    <div className="p-4 max-w-2xl">
      <h1 className="text-2xl font-bold mb-4">Add Evidence</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <input className="p-2 w-full" placeholder="Complaint ID"
               value={cid} onChange={e=>setCid(e.target.value)} />
        <input type="file" onChange={e=>setFile(e.target.files?.[0] || null)} />
        <button className="px-4 py-2 bg-emerald-600 rounded">Upload</button>
      </form>
      {err && <div className="mt-3 p-2 border border-red-500">{err}</div>}
      {resp && <pre className="mt-3 p-2 border overflow-auto">{JSON.stringify(resp, null, 2)}</pre>}
    </div>
  );
}

import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getComplaint, postForm } from "../lib/api";
import { getToken, getRole } from "../lib/auth";

export default function ComplaintDetail() {
  const { id } = useParams();
  const [data, setData] = useState<any>(null);
  const [file, setFile] = useState<File | null>(null);
  const [msg, setMsg] = useState("");

  async function load() {
    setMsg("");
    const json = await getComplaint(Number(id), getToken() || undefined);
    setData(json);
  }

  useEffect(() => {
    load().catch((e) => setMsg(e.message || "Failed to load"));
  }, [id]);

  async function uploadEvidence() {
    if (!file) return;
    const form = new FormData();
    form.append("complaint_id", String(id));
    form.append("file", file);
    await postForm("/evidence/upload", form, getToken() || undefined);
    setFile(null);
    await load();
  }

  if (!data) return <div style={{ padding: 24 }}>Loading…</div>;
  const c = data.complaint;

  return (
    <div style={{ padding: 24 }}>
      <h1>
        Complaint {c.human_id ? `#${c.human_id}` : `#${c.id}`}
      </h1>

      <p><b>Status:</b> {c.status} &nbsp; <b>Severity:</b> {c.severity ?? "-"}</p>
      <p><b>Title:</b> {c.title}</p>
      <p><b>Story:</b> {c.story}</p>

      <h3>Evidence</h3>
      {data.evidence.length === 0 ? <p>No evidence yet.</p> : (
        <ul>
          {data.evidence.map((e: any) => (
            <li key={e.id}>{e.object_name} (sha256 {e.sha256.slice(0,8)}…)</li>
          ))}
        </ul>
      )}
      {getRole() === "citizen" && (
        <div style={{ marginTop: 8 }}>
          <input type="file" onChange={(ev) => setFile(ev.target.files?.[0] || null)} />
          <button onClick={uploadEvidence} style={{ marginLeft: 8 }}>Upload</button>
        </div>
      )}

      <h3 style={{ marginTop: 20 }}>Conversation</h3>
      <p>(Thread UI can go here later)</p>
    </div>
  );
}

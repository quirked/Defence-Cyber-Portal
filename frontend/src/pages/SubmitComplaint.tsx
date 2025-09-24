import { FormEvent, useState } from "react";
import { createComplaint } from "../lib/api";
import { useNavigate } from "react-router-dom";

export default function SubmitComplaint() {
  const nav = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [story, setStory] = useState("");
  const [severity, setSeverity] = useState(1);
  const [msg, setMsg] = useState<string | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) { setMsg("Please attach evidence file"); return; }
    try {
      const j = await createComplaint(file, severity, { title, story });
      setMsg("Submitted!");
      nav(`/complaints/${j.complaint_id}`); // go to detail, not dashboard
    } catch (err: any) {
      setMsg("Failed: " + String(err));
    }
  };

  return (
    <div className="card" style={{ padding: 24 }}>
      <h2>Submit complaint</h2>
      <form onSubmit={onSubmit}>
        <div style={{marginBottom:10}}>
          <label>Title</label>
          <input value={title} onChange={e=>setTitle(e.target.value)} />
        </div>
        <div style={{marginBottom:10}}>
          <label>Story</label>
          <textarea rows={5} value={story} onChange={e=>setStory(e.target.value)} />
        </div>
        <div style={{marginBottom:10}}>
          <label>Severity (1-5)</label>
          <input type="number" min={1} max={5} value={severity} onChange={e=>setSeverity(parseInt(e.target.value||"1"))}/>
        </div>
        <div style={{marginBottom:10}}>
          <label>Evidence file</label>
          <input type="file" onChange={e=>setFile(e.target.files?.[0]||null)} />
        </div>
        <button type="submit">Submit</button>
      </form>
      {msg && <div style={{marginTop:10}}>{msg}</div>}
    </div>
  );
}

import { useState } from "react";
import { postForm } from "../lib/api";
import { getToken } from "../lib/auth";

export default function NewComplaint() {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [story, setStory] = useState("");
  const [severity, setSeverity] = useState(1);
  const [msg, setMsg] = useState("");

  async function submit() {
    if (!file) { setMsg("Pick a file"); return; }
    const form = new FormData();
    form.append("file", file);
    form.append("title", title);
    form.append("story", story);
    form.append("severity_code", String(severity));
    try {
      const json = await postForm("/complaints/create", form, getToken() || undefined);
      setMsg(`Submitted as ${json.human_id || json.complaint_id}`);
    } catch (e: any) {
      setMsg(e.message || "Submit failed");
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h1>New complaint</h1>
      <div><input placeholder="Title" value={title} onChange={(e)=>setTitle(e.target.value)} /></div>
      <div><textarea placeholder="Story" value={story} onChange={(e)=>setStory(e.target.value)} /></div>
      <div>
        Severity:
        <select value={severity} onChange={(e)=>setSeverity(Number(e.target.value))}>
          <option value={1}>Low</option>
          <option value={2}>Medium</option>
          <option value={3}>High</option>
        </select>
      </div>
      <div style={{ margin: "8px 0" }}>
        <input type="file" onChange={(e)=>setFile(e.target.files?.[0] || null)} />
      </div>
      <button onClick={submit}>Submit</button>
      {msg && <p>{msg}</p>}
    </div>
  );
}

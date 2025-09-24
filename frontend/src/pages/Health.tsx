import { useEffect, useState } from "react";
import { getJson } from "../lib/api";

export default function Health() {
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    getJson("/health")
      .then(setData)
      .catch(e => setErr(String(e)));
  }, []);

  return (
    <div className="p-6 space-y-3">
      <h1 className="text-2xl font-bold">Health</h1>
      {err && <pre className="text-red-600">{err}</pre>}
      <pre className="bg-black/5 p-3 rounded">{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}

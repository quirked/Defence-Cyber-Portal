// src/pages/Home.tsx
import { useEffect, useState } from "react";
import { getJSON } from "../lib/api";

type Health = {
  service: string;
  status: {
    db: string;
    minio: string;
    rpc: string;
    contract: string;
  };
};

function Badge({ ok }: { ok: boolean }) {
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-xs font-medium ${
        ok ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
      }`}
    >
      {ok ? "ok" : "error"}
    </span>
  );
}

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getJSON<Health>("/health")
      .then(setHealth)
      .catch((e) => setErr(String(e)));
  }, []);

  return (
    <main className="max-w-5xl mx-auto px-4 py-6">
      <h1 className="text-2xl font-bold mb-4 text-emerald-700">System Health</h1>
      {err && <div className="text-red-700 bg-red-50 p-3 rounded-lg">{err}</div>}
      {!health ? (
        <div className="text-slate-500">Loading…</div>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(health.status).map(([k, v]) => {
            const ok = String(v).startsWith("ok");
            return (
              <div key={k} className="border rounded-xl p-4 bg-white">
                <div className="flex items-center justify-between">
                  <div className="font-semibold capitalize">{k}</div>
                  <Badge ok={ok} />
                </div>
                <div className="text-xs text-slate-600 mt-2 break-all">{String(v)}</div>
              </div>
            );
          })}
        </div>
      )}
      <div className="mt-6 text-sm text-slate-500">
        API Base: <code>{import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"}</code>
      </div>
    </main>
  );
}

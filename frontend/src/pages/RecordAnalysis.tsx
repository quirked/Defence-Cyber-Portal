import { useEffect, useState } from "react";
import { postForm } from "../lib/api";

type AnalysisResp = {
  complaint_id: number;
  analysis_sha256: string;
  analysis_object: string;
  txHash: string;
  blockNumber: number;
};

export default function RecordAnalysis() {
  const [complaintId, setComplaintId] = useState<string>("");
  const [labelCode, setLabelCode] = useState<number>(1);     // e.g. 1 = phishing
  const [severityCode, setSeverityCode] = useState<number>(1);
  const [jsonText, setJsonText] = useState<string>(
    JSON.stringify(
      {
        model: "demo-v1",
        label: "phishing",
        confidence: 0.97,
        notes: "manual smoke test",
      },
      null,
      2
    )
  );

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resp, setResp] = useState<AnalysisResp | null>(null);

  useEffect(() => {
    const last = localStorage.getItem("lastComplaintId");
    if (last) setComplaintId(last);
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResp(null);

    if (!complaintId) {
      setError("Please enter a complaint ID.");
      return;
    }

    try {
      // Validate JSON before sending
      JSON.parse(jsonText);
    } catch {
      setError("Analysis JSON is not valid JSON.");
      return;
    }

    try {
      setLoading(true);
      const form = new FormData();
      form.append("complaint_id", complaintId);
      form.append("label_code", String(labelCode));
      form.append("severity_code", String(severityCode));

      // backend expects a file field named analysis_json
      const blob = new Blob([jsonText], { type: "application/json" });
      const file = new File([blob], "analysis.json", { type: "application/json" });
      form.append("analysis_json", file);

      const json = (await postForm("/analysis/record", form)) as AnalysisResp;
      setResp(json);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Record Analysis</h1>

      <form onSubmit={onSubmit} className="space-y-4">
        <div className="grid md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Complaint ID</label>
            <input
              type="text"
              value={complaintId}
              onChange={(e) => setComplaintId(e.target.value)}
              className="w-full rounded-xl border border-neutral-700 bg-neutral-900 p-2"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Label code</label>
            <select
              value={labelCode}
              onChange={(e) => setLabelCode(Number(e.target.value))}
              className="w-full rounded-xl border border-neutral-700 bg-neutral-900 p-2"
            >
              <option value={1}>Phishing</option>
              <option value={2}>Malware</option>
              <option value={3}>Fraud</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Severity</label>
            <select
              value={severityCode}
              onChange={(e) => setSeverityCode(Number(e.target.value))}
              className="w-full rounded-xl border border-neutral-700 bg-neutral-900 p-2"
            >
              <option value={1}>Low</option>
              <option value={2}>Medium</option>
              <option value={3}>High</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Analysis JSON</label>
          <textarea
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            rows={12}
            className="w-full rounded-xl border border-neutral-700 bg-neutral-900 p-3 font-mono text-sm"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="rounded-2xl px-4 py-2 font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50"
        >
          {loading ? "Recording..." : "Record Analysis"}
        </button>
      </form>

      {error && (
        <div className="mt-4 p-3 border border-red-600 rounded-xl text-red-300">
          {error}
        </div>
      )}

      {resp && (
        <div className="mt-6 p-4 border border-neutral-700 rounded-2xl">
          <h2 className="font-semibold mb-2">Recorded ✓</h2>
          <div className="text-sm space-y-1">
            <div><span className="font-mono">complaint_id</span>: {resp.complaint_id}</div>
            <div><span className="font-mono">analysis_sha256</span>: {resp.analysis_sha256}</div>
            <div><span className="font-mono">analysis_object</span>: {resp.analysis_object}</div>
            <div><span className="font-mono">txHash</span>: {resp.txHash}</div>
            <div><span className="font-mono">blockNumber</span>: {resp.blockNumber}</div>
          </div>
        </div>
      )}
    </div>
  );
}

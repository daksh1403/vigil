"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export default function ReportsPage() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: api.listScans });

  const download = async (scanId: string, fmt: string) => {
    const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
    const token = localStorage.getItem("vigil_access_token");
    const res = await fetch(`${API_BASE}/scans/${scanId}/report?fmt=${fmt}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    window.open(data.path, "_blank");
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-gray-500">Generate SARIF / HTML / JSON reports from completed scans</p>
      </div>
      <div className="card">
        <div className="space-y-2">
          {scans?.filter((s) => s.status === "completed").map((s) => (
            <div key={s.id} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
              <span className="font-mono text-xs text-gray-400">{s.id.slice(0, 8)}</span>
              <div className="flex gap-2">
                <button className="btn-ghost text-xs" onClick={() => download(s.id, "sarif")}>SARIF</button>
                <button className="btn-ghost text-xs" onClick={() => download(s.id, "html")}>HTML</button>
                <button className="btn-ghost text-xs" onClick={() => download(s.id, "json")}>JSON</button>
              </div>
            </div>
          ))}
          {scans?.filter((s) => s.status === "completed").length === 0 && (
            <p className="text-sm text-gray-500">No completed scans to report on.</p>
          )}
        </div>
      </div>
    </div>
  );
}

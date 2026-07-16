"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import Link from "next/link";
import { useState } from "react";

export default function ScansPage() {
  const { data: scans, isLoading } = useQuery({ queryKey: ["scans"], queryFn: api.listScans });
  const { data: projects } = useQuery({ queryKey: ["projects"], queryFn: api.listProjects });
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState("");
  const [projectId, setProjectId] = useState("");

  const targets = useQuery({
    queryKey: ["targets", projectId],
    queryFn: () => api.listTargets(projectId),
    enabled: !!projectId,
  });

  const createScan = useMutation({
    mutationFn: () => api.createScan(projectId, targetId, []),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scans"] }); setTargetId(""); },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Scans</h1>
        <p className="text-sm text-gray-500">Launch and monitor security scans</p>
      </div>

      <div className="card">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">New Scan</h3>
        <div className="flex flex-wrap gap-3">
          <select className="input max-w-xs" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            <option value="">Select project…</option>
            {projects?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select className="input max-w-xs" value={targetId} onChange={(e) => setTargetId(e.target.value)} disabled={!projectId}>
            <option value="">Select target…</option>
            {targets.data?.map((t) => <option key={t.id} value={t.id}>{t.kind}: {t.value}</option>)}
          </select>
          <button
            className="btn-primary disabled:opacity-40"
            disabled={!projectId || !targetId}
            onClick={() => createScan.mutate()}
          >
            Start Scan
          </button>
        </div>
      </div>

      <div className="card">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">Scan History</h3>
        {isLoading && <p className="text-sm text-gray-500">Loading…</p>}
        <div className="space-y-2">
          {scans?.map((s) => (
            <Link
              key={s.id}
              href={`/scans/${s.id}`}
              className="block rounded-md border border-border px-4 py-3 hover:bg-bg-soft"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-gray-400">{s.id.slice(0, 8)}</span>
                <span className={`badge ${scanStatusClass(s.status)}`}>{s.status}</span>
              </div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-bg-soft">
                <div className="h-full bg-accent transition-all" style={{ width: `${s.progress}%` }} />
              </div>
              <div className="mt-2 flex justify-between text-xs text-gray-500">
                <span>{s.scan_type}</span>
                <span>{s.finding_count ?? 0} findings</span>
                {s.created_at && <span>{new Date(s.created_at).toLocaleString()}</span>}
              </div>
            </Link>
          ))}
          {scans?.length === 0 && <p className="text-sm text-gray-500">No scans yet.</p>}
        </div>
      </div>
    </div>
  );
}

function scanStatusClass(s: string) {
  if (s === "completed") return "bg-green-900/60 text-green-200";
  if (s === "running" || s === "pending") return "bg-blue-900/60 text-blue-200";
  if (s === "failed") return "bg-red-900/60 text-red-200";
  return "bg-gray-800 text-gray-400";
}

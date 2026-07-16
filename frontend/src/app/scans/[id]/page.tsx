"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useParams } from "next/navigation";
import Link from "next/link";

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) => (q.state.data?.status === "running" || q.state.data?.status === "pending" ? 3000 : false),
  });

  if (isLoading) return <div className="text-gray-500">Loading…</div>;
  if (!scan) return <div className="text-red-400">Scan not found.</div>;

  return (
    <div className="space-y-6">
      <div>
        <Link href="/scans" className="text-xs text-gray-500 hover:text-accent">← Scans</Link>
        <div className="mt-1 flex items-center gap-3">
          <h1 className="text-2xl font-bold">Scan {scan.id.slice(0, 8)}</h1>
          <span className={`badge ${scan.status === "completed" ? "bg-green-900/60 text-green-200" : "bg-blue-900/60 text-blue-200"}`}>
            {scan.status}
          </span>
        </div>
      </div>

      <div className="card">
        <div className="mb-2 flex items-center justify-between text-sm">
          <span className="text-gray-300">Progress</span>
          <span className="tabular-nums text-gray-400">{scan.progress}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-bg-soft">
          <div className="h-full bg-accent transition-all" style={{ width: `${scan.progress}%` }} />
        </div>
      </div>

      <div className="card">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">Scanner Tasks</h3>
        <div className="space-y-2">
          {scan.tasks?.map((t, i) => (
            <div key={i} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
              <span className="font-mono text-gray-300">{t.scanner}</span>
              <span className="text-gray-500">{t.status}</span>
              <span className="text-gray-400">{t.finding_count} findings</span>
              <span className="text-gray-600">{t.duration_sec ? `${t.duration_sec}s` : "—"}</span>
            </div>
          ))}
          {(!scan.tasks || scan.tasks.length === 0) && <p className="text-sm text-gray-500">No tasks yet.</p>}
        </div>
      </div>

      {scan.finding_count != null && scan.finding_count > 0 && (
        <div className="card">
          <Link href={`/findings?scan_id=${scan.id}`} className="text-sm text-accent hover:underline">
            View {scan.finding_count} findings →
          </Link>
        </div>
      )}
    </div>
  );
}

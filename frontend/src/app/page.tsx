"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { StatCard } from "@/components/StatCard";
import { SeverityChart } from "@/components/SeverityChart";
import Link from "next/link";

export default function DashboardPage() {
  const { data, isLoading } = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard });

  if (isLoading) return <div className="text-gray-500">Loading dashboard…</div>;
  if (!data) return <div className="text-red-400">Failed to load dashboard.</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-sm text-gray-500">Security posture overview across all projects</p>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard label="Critical" value={data.critical} tone="critical" />
        <StatCard label="High" value={data.high} tone="high" />
        <StatCard label="Medium" value={data.medium} tone="medium" />
        <StatCard label="Low" value={data.low} tone="low" />
        <StatCard label="FP rate" value={`${(data.fp_rate * 100).toFixed(0)}%`} tone="info" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card">
          <h3 className="mb-4 text-sm font-semibold text-gray-300">Findings by Severity</h3>
          <SeverityChart data={{
            critical: data.critical, high: data.high, medium: data.medium, low: data.low, info: data.info,
          }} />
        </div>

        <div className="card">
          <h3 className="mb-4 text-sm font-semibold text-gray-300">Findings by Scanner</h3>
          <div className="space-y-2">
            {Object.entries(data.by_scanner).map(([scanner, count]) => (
              <div key={scanner} className="flex items-center justify-between text-sm">
                <span className="text-gray-400">{scanner}</span>
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-32 overflow-hidden rounded-full bg-bg-soft">
                    <div
                      className="h-full bg-accent"
                      style={{ width: `${Math.min(100, (count / Math.max(...Object.values(data.by_scanner))) * 100)}%` }}
                    />
                  </div>
                  <span className="w-8 text-right tabular-nums">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-300">Recent Scans</h3>
          <Link href="/scans" className="text-xs text-accent hover:underline">View all →</Link>
        </div>
        <div className="space-y-2">
          {data.recent_scans.length === 0 && <p className="text-sm text-gray-500">No scans yet.</p>}
          {data.recent_scans.map((s) => (
            <Link
              key={s.id}
              href={`/scans/${s.id}`}
              className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm hover:bg-bg-soft"
            >
              <span className="font-mono text-xs text-gray-400">{s.id.slice(0, 8)}</span>
              <span className="text-gray-300">{s.status}</span>
              <span className="text-gray-500">{s.progress}%</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

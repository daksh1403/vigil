"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import Link from "next/link";
import { useState } from "react";

export default function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [scanner, setScanner] = useState("");
  const params: Record<string, string> = {};
  if (severity) params.severity = severity;
  if (scanner) params.scanner = scanner;

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", params],
    queryFn: () => api.listFindings(params),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        <p className="text-sm text-gray-500">Normalized vulnerabilities across all scanners</p>
      </div>

      <div className="flex gap-3">
        <select className="input max-w-[160px]" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input max-w-[160px]" value={scanner} onChange={(e) => setScanner(e.target.value)}>
          <option value="">All scanners</option>
          {["nuclei", "semgrep", "trivy", "gitleaks", "bandit", "osv-scanner", "pip-audit"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="card overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead className="border-b border-border text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Title</th>
              <th className="px-4 py-3 text-left">Scanner</th>
              <th className="px-4 py-3 text-left">CVSS</th>
              <th className="px-4 py-3 text-left">Risk</th>
              <th className="px-4 py-3 text-left">CWE</th>
              <th className="px-4 py-3 text-left">Status</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && <tr><td colSpan={7} className="px-4 py-6 text-gray-500">Loading…</td></tr>}
            {findings?.map((f) => (
              <tr key={f.id} className="border-b border-border/50 hover:bg-bg-soft">
                <td className="px-4 py-3"><span className={`sev-${f.severity}`}>{f.severity}</span></td>
                <td className="px-4 py-3">
                  <Link href={`/findings/${f.id}`} className="text-gray-200 hover:text-accent">{f.title}</Link>
                </td>
                <td className="px-4 py-3 text-gray-400">{f.scanner}</td>
                <td className="px-4 py-3 tabular-nums text-gray-400">{f.cvss ?? "—"}</td>
                <td className="px-4 py-3 tabular-nums">
                  {f.ai_triage?.risk_score != null ? (
                    <span className={riskClass(f.ai_triage.risk_score)}>{f.ai_triage.risk_score}</span>
                  ) : "—"}
                </td>
                <td className="px-4 py-3 text-gray-400">{f.cwe ?? "—"}</td>
                <td className="px-4 py-3 text-gray-400">{f.status}</td>
              </tr>
            ))}
            {findings?.length === 0 && <tr><td colSpan={7} className="px-4 py-6 text-gray-500">No findings.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function riskClass(r: number) {
  if (r >= 8) return "text-red-400";
  if (r >= 6) return "text-orange-400";
  if (r >= 4) return "text-blue-400";
  return "text-gray-400";
}

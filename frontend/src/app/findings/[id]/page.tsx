"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useParams } from "next/navigation";
import { AIPanel } from "@/components/AIPanel";

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const { data: finding, isLoading } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.getFinding(id),
  });

  const updateStatus = useMutation({
    mutationFn: (status: string) => api.updateFinding(id, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });

  if (isLoading) return <div className="text-gray-500">Loading…</div>;
  if (!finding) return <div className="text-red-400">Finding not found.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span className={`sev-${finding.severity}`}>{finding.severity.toUpperCase()}</span>
            <h1 className="text-xl font-bold">{finding.title}</h1>
          </div>
          <div className="mt-2 flex flex-wrap gap-3 text-xs text-gray-500">
            <span>Scanner: {finding.scanner}</span>
            {finding.scanner_rule_id && <span>· Rule: {finding.scanner_rule_id}</span>}
            {finding.cvss != null && <span>· CVSS: {finding.cvss}</span>}
            {finding.cwe && <span>· {finding.cwe}</span>}
            {finding.owasp_category && <span>· OWASP {finding.owasp_category}</span>}
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={() => updateStatus.mutate("confirmed")}>Confirm</button>
          <button className="btn-ghost" onClick={() => updateStatus.mutate("false_positive")}>False Positive</button>
          <button className="btn-ghost" onClick={() => updateStatus.mutate("ignored")}>Ignore</button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="card lg:col-span-2">
          <h3 className="mb-2 text-sm font-semibold text-gray-300">Description</h3>
          <p className="text-sm text-gray-400">{finding.description || "No description provided."}</p>

          {(finding.target_ref || finding.file_path) && (
            <div className="mt-4">
              <h3 className="mb-1 text-sm font-semibold text-gray-300">Location</h3>
              <div className="text-xs text-gray-500">
                {finding.file_path && <div>{finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}</div>}
                {finding.target_ref && <div className="font-mono">{finding.target_ref}</div>}
              </div>
            </div>
          )}

          {finding.code_snippet && (
            <div className="mt-4">
              <h3 className="mb-1 text-sm font-semibold text-gray-300">Evidence</h3>
              <pre className="overflow-x-auto rounded-md border border-border bg-bg p-3 text-xs text-gray-300">
                {finding.code_snippet}
              </pre>
            </div>
          )}
        </div>

        <div className="lg:col-span-1">
          <AIPanel finding={finding} />
        </div>
      </div>
    </div>
  );
}

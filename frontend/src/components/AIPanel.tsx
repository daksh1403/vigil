"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Finding } from "@/lib/api";
import { Brain, ShieldAlert, ShieldCheck, Wrench, Target } from "lucide-react";

interface Props {
  finding: Finding;
}

export function AIPanel({ finding }: Props) {
  const qc = useQueryClient();
  const ai = finding.ai_triage;
  const retriage = useMutation({
    mutationFn: () => api.reTriage(finding.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", finding.id] }),
  });

  const risk = ai?.risk_score;
  const riskTone = risk == null ? "text-gray-500" : risk >= 8 ? "text-red-400" : risk >= 6 ? "text-orange-400" : risk >= 4 ? "text-blue-400" : "text-gray-400";

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-accent" />
          <h3 className="text-sm font-semibold text-gray-300">AI Triage</h3>
        </div>
        <span className="text-[10px] uppercase text-gray-600">{ai?.triage_method || "—"}</span>
      </div>

      <div className="grid grid-cols-2 gap-3 text-center">
        <div className="rounded-md border border-border bg-bg-soft p-2">
          <div className={`text-xl font-bold tabular-nums ${riskTone}`}>{risk ?? "—"}</div>
          <div className="text-[10px] uppercase text-gray-500">Risk Score</div>
        </div>
        <div className="rounded-md border border-border bg-bg-soft p-2">
          <div className="text-xl font-bold tabular-nums text-gray-300">
            {ai?.fp_score != null ? `${(ai.fp_score * 100).toFixed(0)}%` : "—"}
          </div>
          <div className="text-[10px] uppercase text-gray-500">FP Probability</div>
        </div>
      </div>

      {ai?.mitre_tactics && ai.mitre_tactics.length > 0 && (
        <div>
          <div className="mb-1 flex items-center gap-1 text-xs text-gray-500">
            <Target className="h-3 w-3" /> MITRE ATT&CK
          </div>
          <div className="flex flex-wrap gap-1">
            {[...ai.mitre_tactics, ...(ai.mitre_techniques || [])].map((t) => (
              <span key={t} className="rounded bg-bg-soft px-1.5 py-0.5 text-[10px] font-mono text-accent">{t}</span>
            ))}
          </div>
        </div>
      )}

      {ai?.explanation && (
        <div>
          <div className="mb-1 flex items-center gap-1 text-xs text-gray-500">
            <ShieldAlert className="h-3 w-3" /> What it means
          </div>
          <p className="text-xs leading-relaxed text-gray-400">{ai.explanation}</p>
        </div>
      )}

      {ai?.remediation && (
        <div>
          <div className="mb-1 flex items-center gap-1 text-xs text-gray-500">
            <Wrench className="h-3 w-3" /> How to fix
          </div>
          <p className="text-xs leading-relaxed text-gray-400">{ai.remediation}</p>
        </div>
      )}

      <button
        className="btn-ghost w-full justify-center text-xs"
        onClick={() => retriage.mutate()}
        disabled={retriage.isPending}
      >
        {retriage.isPending ? "Re-triaging…" : "Re-run AI Triage"}
      </button>
    </div>
  );
}

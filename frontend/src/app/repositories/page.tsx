"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useState } from "react";
import Link from "next/link";

export default function RepositoriesPage() {
  const { data: repos, isLoading } = useQuery({ queryKey: ["repos"], queryFn: api.listRepos });
  const qc = useQueryClient();
  const [url, setUrl] = useState("");

  const scan = useMutation({
    mutationFn: () => api.scanRepo(url),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["repos"] }); setUrl(""); },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Repositories</h1>
        <p className="text-sm text-gray-500">Scan a GitHub repository for SAST, SCA, secrets & SBOM</p>
      </div>

      <div className="card">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">Scan a Repository</h3>
        <div className="flex gap-3">
          <input
            className="input"
            placeholder="https://github.com/owner/repo.git"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button className="btn-primary whitespace-nowrap" disabled={!url || scan.isPending} onClick={() => scan.mutate()}>
            {scan.isPending ? "Starting…" : "Scan Repo"}
          </button>
        </div>
      </div>

      <div className="card">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">Scanned Repositories</h3>
        {isLoading && <p className="text-sm text-gray-500">Loading…</p>}
        <div className="space-y-2">
          {repos?.map((r) => (
            <Link
              key={r.id}
              href={`/scans`}
              className="flex items-center justify-between rounded-md border border-border px-4 py-3 hover:bg-bg-soft"
            >
              <span className="font-medium text-gray-200">{r.name}</span>
              <span className="text-xs text-gray-500">{r.type}</span>
            </Link>
          ))}
          {repos?.length === 0 && <p className="text-sm text-gray-500">No repositories scanned yet.</p>}
        </div>
      </div>
    </div>
  );
}

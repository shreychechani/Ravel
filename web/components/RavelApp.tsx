"use client";

import { useEffect, useState } from "react";

import { fetchReport, reachOf, rescan, type Report } from "@/lib/report";
import { CodeGraph } from "./CodeGraph";
import { FindingDetail } from "./FindingDetail";
import { FindingList, type ReachFilter } from "./FindingList";
import { ScannerStrip, Summary } from "./Summary";

const FILTERS: ReachFilter[] = ["all", "reachable", "unknown", "unreachable"];

export function RavelApp() {
  const [report, setReport] = useState<Report | null>(null);
  const [canRescan, setCanRescan] = useState(false);
  const [busy, setBusy] = useState<string | null>("Loading scan…");
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ReachFilter>("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<"findings" | "graph">("findings");
  const [graphFocus, setGraphFocus] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((h) => setCanRescan(Boolean(h.can_rescan)))
      .catch(() => setCanRescan(false));
    fetchReport()
      .then(setReport)
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(null));
  }, []);

  const run = (triage: boolean) => {
    setBusy(triage ? "Asking the model about reachable findings…" : "Rescanning…");
    setError(null);
    rescan(triage)
      .then(setReport)
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(null));
  };

  const q = query.trim().toLowerCase();
  const shown =
    report?.findings.filter(
      (f) =>
        (filter === "all" || reachOf(f) === filter) &&
        (!q ||
          [f.rule_id, f.file, f.node_name, f.cwe, f.message, f.package]
            .filter(Boolean)
            .some((s) => s!.toLowerCase().includes(q))),
    ) ?? [];
  const current = shown.find((f) => f.id === selected) ?? shown[0] ?? null;
  const count = (r: ReachFilter) => (r === "all" ? report?.findings.length : report?.findings.filter((f) => reachOf(f) === r).length) ?? 0;

  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-5 px-6 py-6">
      <header className="flex flex-wrap items-center gap-4">
        <div className="flex items-baseline gap-3">
          <span className="text-3xl font-bold tracking-tight">Ravel</span>
          <span className="text-sm text-muted">which warnings actually matter</span>
        </div>
        {report && (
          <span className="rounded-full bg-paper-2 px-3 py-1 font-mono text-sm">{report.repo}</span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {busy && <span className="text-sm text-muted">{busy}</span>}
          <button
            disabled={!canRescan || !!busy}
            onClick={() => run(false)}
            className="rounded-full border border-ink px-4 py-2 text-sm font-semibold disabled:opacity-40"
            title={canRescan ? "Scan the repository again" : "This report was loaded from a file"}
          >
            Rescan
          </button>
          <button
            disabled={!canRescan || !!busy}
            onClick={() => run(true)}
            className="rounded-full bg-ink px-4 py-2 text-sm font-semibold text-paper disabled:opacity-40"
            title="Send only reachable / unknown findings to the LLM, with their traced paths"
          >
            Run AI review
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-real bg-real-soft px-4 py-3 text-sm text-real">{error}</div>
      )}

      {report && (
        <>
          <Summary report={report} />
          <ScannerStrip report={report} />

          <nav className="flex gap-1 border-b border-line">
            {(
              [
                ["findings", `Findings · ${report.findings.length}`],
                ["graph", "Code graph"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`-mb-px rounded-t-xl border px-4 py-2 text-sm font-semibold ${
                  tab === key ? "border-line border-b-paper bg-paper text-ink" : "border-transparent text-muted hover:text-ink"
                }`}
              >
                {label}
              </button>
            ))}
          </nav>

          {tab === "graph" && (
            <CodeGraph
              report={report}
              focus={graphFocus}
              onOpenFinding={(id) => {
                setFilter("all");
                setQuery("");
                setSelected(id);
                setTab("findings");
              }}
            />
          )}

          {tab === "findings" && (
          <div className="grid gap-5 lg:grid-cols-[minmax(320px,420px)_1fr]">
            <aside className="flex flex-col gap-3">
              <div className="flex flex-wrap gap-1.5">
                {FILTERS.map((r) => (
                  <button
                    key={r}
                    onClick={() => setFilter(r)}
                    className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                      filter === r ? "border-ink bg-ink text-paper" : "border-line bg-card text-ink"
                    }`}
                  >
                    {r} · {count(r)}
                  </button>
                ))}
              </div>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search rule, file, function, CWE…"
                className="rounded-xl border border-line bg-card px-3 py-2 text-sm outline-none focus:border-ink"
              />
              <div className="max-h-[calc(100vh-330px)] overflow-y-auto pr-1">
                <FindingList findings={shown} selected={current?.id ?? null} onSelect={setSelected} />
              </div>
            </aside>
            <main className="min-w-0 rounded-2xl border border-line bg-paper p-1">
              {current ? (
                <FindingDetail
                  report={report}
                  finding={current}
                  onShowInGraph={(nodeId) => {
                    setGraphFocus(nodeId);
                    setTab("graph");
                  }}
                />
              ) : (
                <p className="p-6 text-sm text-muted">Select a finding to see its path and evidence.</p>
              )}
            </main>
          </div>
          )}
        </>
      )}
    </div>
  );
}

import { reachOf, type Finding, type Report } from "@/lib/report";
import { ReachBadge, SeverityBadge, VerdictBadge } from "./Badges";
import { PathGraph } from "./PathGraph";

function explain(report: Report, f: Finding): string {
  const r = reachOf(f);
  const ev = f.static_evidence;
  const start = ev?.path.length ? report.nodes[ev.path[0]]?.name : undefined;
  if (f.package && !f.anchors.length) return "No code in the repo imports this package, so there is nothing to trace from.";
  if (r === "reachable")
    return `Untrusted input can reach this code: a fully resolved call path starts at the web route ${start ?? "?"}${
      ev && ev.blast_radius > 1 ? `, and ${ev.blast_radius} different entry points reach it` : ""
    }.`;
  if (r === "unknown")
    return ev?.path.length
      ? "A path exists only through a call Ravel could not resolve, so it is marked unknown rather than safe."
      : "Ravel could not place this on the code graph, or found no entry points, so it is unknown rather than safe.";
  return `No call path leads here from any of the ${report.entry_points.length} untrusted entry points, even through unresolved calls.`;
}

function Code({ f }: { f: Finding }) {
  if (!f.code) return null;
  const [lo, hi] = f.code.highlight;
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-[#1e1f29]">
      <div className="border-b border-white/10 px-3 py-1.5 font-mono text-[11px] text-[#b8c2d6]">{f.code.file}</div>
      <pre className="max-h-64 overflow-auto py-2 text-[12px] leading-5">
        {f.code.lines.map((line, i) => {
          const n = f.code!.start_line + i;
          const hot = n >= lo && n <= hi;
          return (
            <div key={n} className={`flex px-3 ${hot ? "bg-[#b85a12]/35" : ""}`}>
              <span className="w-10 shrink-0 select-none pr-3 text-right text-[#6b7280]">{n}</span>
              <code className="whitespace-pre text-[#e6e8ee]">{line || " "}</code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

export function FindingDetail({
  report,
  finding: f,
  onShowInGraph,
}: {
  report: Report;
  finding: Finding;
  onShowInGraph?: (nodeId: string) => void;
}) {
  const reviewed = f.verdict && f.verdict !== "unreachable";
  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xl font-bold">{f.rule_id}</span>
          <SeverityBadge severity={f.severity} />
          <ReachBadge reach={reachOf(f)} />
          {f.cwe && <span className="rounded-full bg-paper-2 px-2 py-0.5 text-xs font-semibold">{f.cwe}</span>}
          <span className="text-xs text-muted">via {f.source}</span>
        </div>
        <p className="text-base">{f.message}</p>
        <p className="font-mono text-xs text-muted">
          {f.package ? `${f.package} ${f.package_version ?? ""} — ${f.file}` : `${f.file}:${f.line} · ${f.node_name ?? ""}`}
        </p>
      </header>

      <section className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-muted">Why it is ranked here</h3>
          {onShowInGraph && !f.package && (
            <button
              onClick={() => onShowInGraph(f.node_id)}
              className="ml-auto rounded-full border border-ink px-3 py-1 text-xs font-semibold hover:bg-ink hover:text-paper"
            >
              Show in code graph
            </button>
          )}
        </div>
        <p className="text-sm">{explain(report, f)}</p>
        <PathGraph report={report} finding={f} />
      </section>

      <section className="flex flex-col gap-2 rounded-xl border border-line bg-card p-4">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-muted">AI review</h3>
          <VerdictBadge verdict={f.verdict} />
          {reviewed && f.confidence !== null && (
            <span className="ml-auto text-xs text-muted">confidence {(f.confidence * 100).toFixed(0)}%</span>
          )}
        </div>
        {reviewed && f.confidence !== null && (
          <div className="h-1.5 w-full rounded-full bg-paper-2">
            <div className="h-1.5 rounded-full bg-ink" style={{ width: `${f.confidence * 100}%` }} />
          </div>
        )}
        <p className="text-sm">
          {f.reasoning ??
            (reachOf(f) === "unreachable"
              ? "Not sent to the model: reachability already showed no attacker can get here."
              : "Not reviewed yet. Use “Run AI review” to ask the model, with the traced path as context.")}
        </p>
      </section>

      {f.package && (
        <section className="flex flex-col gap-1 text-sm">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-muted">Advisory</h3>
          <p>
            {f.aliases.join(" · ") || f.rule_id}
            {f.fixed_in ? ` — fixed in ${f.fixed_in}` : ""}
          </p>
          {f.via.length > 0 && <p className="text-muted">Pulled in by: {f.via.join(", ")}</p>}
        </section>
      )}

      <Code f={f} />

      {f.callers.length > 0 && (
        <section className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-muted">Called from</h3>
          <ul className="flex flex-wrap gap-2">
            {f.callers.map((c) => (
              <li key={c} className="rounded-lg border border-line bg-card px-2 py-1 font-mono text-xs">
                {report.nodes[c]?.name ?? c}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

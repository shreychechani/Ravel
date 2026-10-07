import { pct, reachOf, type Report } from "@/lib/report";

function Stat({ label, value, note, tone }: { label: string; value: string; note?: string; tone?: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1 rounded-2xl border border-line bg-card px-5 py-4">
      <span className="text-xs font-semibold uppercase tracking-wider text-muted">{label}</span>
      <span className={`text-3xl font-bold leading-none ${tone ?? "text-ink"}`}>{value}</span>
      {note && <span className="text-xs text-muted">{note}</span>}
    </div>
  );
}

export function Summary({ report }: { report: Report }) {
  const counts = { reachable: 0, unknown: 0, unreachable: 0 };
  for (const f of report.findings) counts[reachOf(f)]++;
  const total = report.findings.length;
  const cov = report.graph.coverage;
  const covTone = cov.ratio >= 0.8 ? "text-safe" : cov.ratio >= 0.6 ? "text-unknown" : "text-real";
  const ts = report.triage_stats;

  return (
    <section className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      <div className="col-span-2 flex flex-col justify-between gap-3 rounded-2xl bg-ink px-6 py-4 text-paper">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#f0a35e]">
          Scanner warnings → what can be reached
        </span>
        <div className="flex items-end gap-4">
          <span className="text-4xl font-bold leading-none">{total}</span>
          <span className="pb-1 text-2xl text-[#b8c2d6]">→</span>
          <span className="text-4xl font-bold leading-none text-[#f0a35e]">{counts.reachable}</span>
          <span className="pb-1 text-sm text-[#dde3ee]">
            reachable · {counts.unknown} unknown · {counts.unreachable} unreachable
          </span>
        </div>
      </div>
      <Stat
        label="Graph coverage"
        value={pct(cov.ratio)}
        tone={covTone}
        note={`${cov.internal + cov.external} of ${cov.total} call sites resolved`}
      />
      <Stat
        label="Mapped to code"
        value={pct(report.mapping.ratio)}
        note={`${report.entry_points.length} untrusted entry points`}
      />
      <Stat
        label="AI review"
        value={ts ? `${ts.real_count} real` : "off"}
        tone={ts ? "text-real" : "text-muted"}
        note={
          ts
            ? `${ts.false_positive_count} false positive · ${ts.needs_review_count} review · ${ts.tokens_used ?? 0} tokens`
            : "only reachable findings would be sent"
        }
      />
    </section>
  );
}

export function ScannerStrip({ report }: { report: Report }) {
  const tone = (s: string) =>
    s === "ok" ? "border-safe text-safe" : s === "not_configured" ? "border-unknown text-unknown" : "border-unreach text-unreach";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="font-semibold text-muted">Scanners:</span>
      {report.scanners.map((s) => (
        <span key={s.source} className={`rounded-full border bg-card px-2 py-0.5 ${tone(s.status)}`}>
          {s.source} · {s.status.replace("_", " ")}
        </span>
      ))}
      {report.not_integrated.map((s) => (
        <span key={s} className="rounded-full border border-dashed border-unreach px-2 py-0.5 text-unreach">
          {s} · not integrated
        </span>
      ))}
      <span className="ml-auto max-w-[45%] truncate text-muted" title={report.graph.environment}>
        Python env: {report.graph.environment}
      </span>
    </div>
  );
}

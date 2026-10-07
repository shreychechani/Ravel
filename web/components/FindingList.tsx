import { reachOf, type Finding, type Reach } from "@/lib/report";
import { ReachBadge, SeverityBadge, VerdictBadge } from "./Badges";

export type ReachFilter = Reach | "all";

export function FindingList({
  findings,
  selected,
  onSelect,
}: {
  findings: Finding[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  if (!findings.length) {
    return <p className="p-6 text-sm text-muted">No findings match these filters.</p>;
  }
  return (
    <ol className="flex flex-col gap-2">
      {findings.map((f, i) => {
        const active = f.id === selected;
        return (
          <li key={f.id}>
            <button
              onClick={() => onSelect(f.id)}
              className={`flex w-full flex-col gap-1.5 rounded-xl border px-3 py-2.5 text-left transition ${
                active ? "border-ink bg-card shadow-md" : "border-line bg-card hover:border-muted"
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="w-6 text-xs tabular-nums text-muted">{i + 1}</span>
                <span className="font-mono text-sm font-semibold">{f.rule_id}</span>
                <SeverityBadge severity={f.severity} />
                <span className="ml-auto">
                  <ReachBadge reach={reachOf(f)} />
                </span>
              </div>
              <div className="flex items-center gap-2 pl-8">
                <span className="truncate text-sm">
                  {f.package ? `${f.package} ${f.package_version ?? ""}` : (f.node_name ?? f.file)}
                </span>
                <span className="ml-auto">
                  <VerdictBadge verdict={f.verdict} />
                </span>
              </div>
              <span className="truncate pl-8 font-mono text-xs text-muted">
                {f.package ? f.file : `${f.file}:${f.line}`}
                {f.cwe ? ` · ${f.cwe}` : ""}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

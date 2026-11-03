import { useState } from "react";

import {
  URGENCY_LABEL,
  URGENCY_STYLE,
  type DeprecatedApi,
  type Evidence,
  type PackageEntry,
  type Report,
  type Urgency,
} from "@/lib/report";
import { ReachBadge, SeverityBadge } from "./Badges";

const pill = "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap";

const WHY: Record<Urgency, string> = {
  urgent: "A known advisory, and code reachable from a web route calls into this package.",
  check:
    "A known advisory. Route code uses this package through calls Ravel could not resolve, so it may be exposed: unknown, not safe.",
  routine: "Known advisories, but no untrusted entry point reaches the code that uses this package.",
  migrate: "No known advisory, but the repo calls APIs this package itself marks as deprecated.",
  ok: "No known advisory and no deprecated calls.",
};

function UrgencyBadge({ urgency }: { urgency: Urgency }) {
  return <span className={`${pill} ${URGENCY_STYLE[urgency]}`}>{URGENCY_LABEL[urgency]}</span>;
}

/** Display names for node ids, from the whole-graph view when the report has it. */
function useNames(report: Report) {
  const names = new Map<string, string>();
  for (const n of report.graph_view?.nodes ?? []) names.set(n.id, n.name);
  for (const [id, n] of Object.entries(report.nodes)) names.set(id, n.name);
  return (id: string) => names.get(id) ?? id.split("::").slice(1).join("::") ?? id;
}

function PathLine({ ev, name }: { ev: Evidence; name: (id: string) => string }) {
  if (!ev.path.length) return null;
  return (
    <span className="font-mono text-xs text-muted">
      {ev.path.map((id, i) => (
        <span key={`${id}-${i}`}>
          {i > 0 && <span className="px-1">→</span>}
          <span className={i === 0 ? "font-semibold text-ink" : ""}>{name(id)}</span>
        </span>
      ))}
    </span>
  );
}

function Api({
  api,
  name,
  onShowInGraph,
}: {
  api: DeprecatedApi;
  name: (id: string) => string;
  onShowInGraph?: (nodeId: string) => void;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-line bg-paper px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-semibold">{api.symbol}</span>
        <ReachBadge reach={api.reach.reachable} />
        {api.conditional && (
          <span className={`${pill} border-unknown text-unknown`} title="The library warns only for some arguments or states">
            only some calls
          </span>
        )}
        <span className="ml-auto text-xs text-muted">
          {api.kind === "decorator" ? "@" : ""}
          {api.category ?? "deprecated"}
        </span>
      </div>
      {api.message && <p className="text-sm">“{api.message}”</p>}
      <ul className="flex flex-col gap-1">
        {api.calls.map((c) => (
          <li key={`${c.node_id}:${c.line}`} className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono">
              {c.node_id.split("::")[0]}:{c.line}
            </span>
            <span className="text-muted">in {name(c.node_id)}</span>
            <PathLine ev={c} name={name} />
            {onShowInGraph && (
              <button onClick={() => onShowInGraph(c.node_id)} className="ml-auto text-graph hover:underline">
                show in graph
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function PackageCard({
  pkg,
  name,
  onShowInGraph,
}: {
  pkg: PackageEntry;
  name: (id: string) => string;
  onShowInGraph?: (nodeId: string) => void;
}) {
  const [open, setOpen] = useState(pkg.urgency === "urgent");
  const worst = pkg.advisories.map((a) => a.severity).sort((a, b) => order(a) - order(b))[0];
  const version = pkg.stdlib ? `Python stdlib` : (pkg.version ?? pkg.declared ?? "version unknown");
  const usage = pkg.via.length
    ? `runs under ${pkg.via.join(", ")}`
    : pkg.users.length
      ? `${pkg.references} reference${pkg.references === 1 ? "" : "s"} in ${pkg.files} file${pkg.files === 1 ? "" : "s"}`
      : "not imported by repo code";
  return (
    <li className="rounded-2xl border border-line bg-card">
      <button onClick={() => setOpen(!open)} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left">
        <span className="text-lg font-bold">{pkg.name}</span>
        <span className="font-mono text-sm text-muted">
          {version}
          {pkg.declared && pkg.version && pkg.declared !== pkg.version ? ` (pinned ${pkg.declared})` : ""}
        </span>
        <UrgencyBadge urgency={pkg.urgency} />
        {pkg.advisories.length > 0 && (
          <span className="flex items-center gap-1.5 text-sm">
            {pkg.advisories.length} advisor{pkg.advisories.length === 1 ? "y" : "ies"}
            {worst && <SeverityBadge severity={worst} />}
          </span>
        )}
        {pkg.deprecated.length > 0 && (
          <span className="text-sm">
            {pkg.deprecated.length} deprecated API{pkg.deprecated.length === 1 ? "" : "s"}
          </span>
        )}
        <span className="ml-auto text-sm text-muted">{usage}</span>
        <span className="text-muted">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="flex flex-col gap-3 border-t border-line px-4 py-3">
          <p className="text-sm text-muted">
            {pkg.via.length && pkg.advisories.length
              ? `The repo never imports it, but ${pkg.via.join(", ")} requires it, so it runs wherever that does. ` +
                WHY[pkg.urgency].replace("this package", pkg.via.join(", "))
              : WHY[pkg.urgency]}
          </p>
          {pkg.advisories.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-semibold">Upgrade to:</span>
              <span className="font-mono">{pkg.upgrade_to ?? "no fixed release listed"}</span>
              {pkg.unfixed > 0 && pkg.upgrade_to && (
                <span className="text-real">+{pkg.unfixed} advisory without a fix</span>
              )}
              {pkg.pin_is_stale && (
                <span className={`${pill} border-safe text-safe`}>installed {pkg.version} already has the fix: update the pin</span>
              )}
            </div>
          )}
          {pkg.usage.path.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-semibold">Used from:</span>
              <ReachBadge reach={pkg.usage.reachable} />
              <PathLine ev={pkg.usage} name={name} />
            </div>
          )}
          {pkg.deprecated.map((api) => (
            <Api key={api.symbol} api={api} name={name} onShowInGraph={onShowInGraph} />
          ))}
          {pkg.advisories.length > 0 && (
            <details className="text-sm">
              <summary className="cursor-pointer font-semibold">Advisories ({pkg.advisories.length})</summary>
              <ul className="mt-2 flex flex-col gap-1">
                {pkg.advisories.map((a) => (
                  <li key={a.finding_id} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-semibold">{a.id}</span>
                    <SeverityBadge severity={a.severity} />
                    <span className="min-w-0 flex-1 truncate" title={a.summary}>
                      {a.summary}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </li>
  );
}

const SEVERITIES = ["critical", "high", "medium", "low"];
const order = (s: string) => (SEVERITIES.includes(s) ? SEVERITIES.indexOf(s) : 9);

export function Dependencies({
  report,
  onShowInGraph,
}: {
  report: Report;
  onShowInGraph?: (nodeId: string) => void;
}) {
  const name = useNames(report);
  const deps = report.dependencies;
  if (!deps) {
    return <p className="p-6 text-sm text-muted">This report predates the dependency report — rescan to see it.</p>;
  }
  const s = deps.summary;
  const check = deps.deprecation_check;
  const listed = deps.packages.filter((p) => p.urgency !== "ok");
  const quiet = deps.packages.filter((p) => p.urgency === "ok");
  return (
    <div className="flex flex-col gap-4">
      <section className="flex flex-wrap items-center gap-2">
        {(["urgent", "check", "routine", "migrate"] as const).map((u) => (
          <span key={u} className={`${pill} px-3 py-1 text-sm ${URGENCY_STYLE[u]}`}>
            {s[u]} · {URGENCY_LABEL[u]}
          </span>
        ))}
        <span className="text-sm text-muted">
          {s.deprecated_calls} deprecated call{s.deprecated_calls === 1 ? "" : "s"}:{" "}
          {s.deprecated_calls_by_reach.reachable} reachable · {s.deprecated_calls_by_reach.unknown} unknown ·{" "}
          {s.deprecated_calls_by_reach.unreachable} unreachable
        </span>
      </section>

      <div className="flex flex-col gap-1 rounded-xl border border-line bg-paper-2 px-4 py-2.5 text-xs text-muted">
        <span>
          <b>Advisories:</b>{" "}
          {deps.osv.status === "ok"
            ? `offline OSV database (${deps.osv.detail ?? "date unknown"})`
            : `not checked — OSV ${deps.osv.status.replace("_", " ")}${deps.osv.detail ? `: ${deps.osv.detail}` : ""}`}
          . {deps.upgrade_note}
        </span>
        <span>
          <b>Deprecations:</b> read from the libraries&apos; own markers on {check.external_calls_checked} resolved
          external calls{check.without_source ? ` (${check.without_source} without source)` : ""}.{" "}
          {check.unresolved_calls > 0 && (
            <span className="text-unknown">
              {check.unresolved_calls} unresolved call site{check.unresolved_calls === 1 ? "" : "s"} could hide more.{" "}
            </span>
          )}
          Stdlib judged against Python {check.stdlib_python}.
        </span>
      </div>

      {listed.length ? (
        <ol className="flex flex-col gap-2">
          {listed.map((p) => (
            <PackageCard key={p.name} pkg={p} name={name} onShowInGraph={onShowInGraph} />
          ))}
        </ol>
      ) : (
        <p className="rounded-2xl border border-line bg-card p-6 text-sm">
          No package needs action: no known advisories and no deprecated calls.
        </p>
      )}

      {quiet.length > 0 && (
        <p className="text-xs text-muted">
          Nothing to do for: {quiet.map((p) => `${p.name}${p.version ? ` ${p.version}` : ""}`).join(", ")}
        </p>
      )}
    </div>
  );
}

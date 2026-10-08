"use client";

// The code knowledge graph, laid out like Arcflow (sidebar · canvas with
// folder hulls · tabbed right panel · status bar), carrying Ravel's evidence:
// which nodes are untrusted entry points, which hold warnings, and what an
// attacker can reach.

import { select } from "d3-selection";
import { zoom, zoomIdentity, type ZoomBehavior } from "d3-zoom";
import { useEffect, useMemo, useRef, useState } from "react";

import { attackSurface, buildLayout, PALETTE, type Level, type VNode } from "@/lib/graphLayout";
import { pct, reachOf, type Report } from "@/lib/report";
import { ReachBadge } from "./Badges";

type ColorBy = "folder" | "risk" | "kind";
type Tab = "details" | "warnings" | "entries";

const CONTROL =
  "grid h-8 w-8 place-items-center rounded-lg border border-line bg-card text-sm shadow-sm hover:border-ink";

const folderOf = (file: string) => (file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "(root)");

function riskColor(n: VNode, surface: Set<string>): string {
  if (n.worstReach === "reachable") return "#b3261e";
  if (n.worstReach === "unknown") return "#c99a06";
  if (n.entry) return "#b85a12";
  if (n.worstReach === "unreachable") return "#6b7280";
  if (n.members.some((m) => surface.has(m))) return "#f0a35e";
  return "#cfc8b8";
}

const KIND_COLOR: Record<string, string> = {
  function: "#2f5fb3",
  class: "#6a4c93",
  file: "#14213d",
  unknown: "#c99a06",
};

function Tile({ value, label }: { value: string | number; label: string }) {
  return (
    <div className="flex flex-col items-center rounded-xl border border-line bg-card py-2.5">
      <span className="text-2xl font-bold text-graph">{value}</span>
      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">{label}</span>
    </div>
  );
}

export function CodeGraph({
  report,
  focus,
  onOpenFinding,
}: {
  report: Report;
  focus: string | null;
  onOpenFinding: (findingId: string) => void;
}) {
  const view = report.graph_view;
  // The tab remounts on each visit, so a "Show in code graph" focus seeds the state.
  const [level, setLevel] = useState<Level>("functions");
  const [colorBy, setColorBy] = useState<ColorBy>("folder");
  const [showUnknown, setShowUnknown] = useState(false);
  const [selected, setSelected] = useState<string | null>(focus);
  const [tab, setTab] = useState<Tab>(focus ? "details" : "warnings");
  const [query, setQuery] = useState("");
  const [openFolders, setOpenFolders] = useState<Set<string>>(new Set());

  const layout = useMemo(() => buildLayout(report, level, showUnknown), [report, level, showUnknown]);
  const surface = useMemo(() => attackSurface(report), [report]);
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  const fitTo = (b: [number, number, number, number], max = 1.6) => {
    const svg = svgRef.current;
    if (!svg || !zoomRef.current) return;
    const { width, height } = svg.getBoundingClientRect();
    const k = Math.min(max, (0.9 * width) / Math.max(1, b[2] - b[0]), (0.9 * height) / Math.max(1, b[3] - b[1]));
    const t = zoomIdentity
      .translate(width / 2 - (k * (b[0] + b[2])) / 2, height / 2 - (k * (b[1] + b[3])) / 2)
      .scale(k);
    select(svg).call(zoomRef.current.transform, t);
  };

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || !layout) return;
    const z = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.05, 6])
      .on("zoom", (e) => gRef.current?.setAttribute("transform", e.transform.toString()));
    zoomRef.current = z;
    select(svg).call(z).on("dblclick.zoom", null);
    const target = focus ? layout.nodes.find((n) => n.members.includes(focus)) : undefined;
    if (target) fitTo([target.x - 260, target.y - 180, target.x + 260, target.y + 180]);
    else fitTo(layout.bounds);
    // fitTo only reads refs; re-run when the picture changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  if (!view || !layout) {
    return <p className="p-6 text-sm text-muted">This report has no code graph (made by an older Ravel). Rescan to see it.</p>;
  }

  const byId = new Map(layout.nodes.map((n) => [n.id, n]));
  const selectedNode = selected ? layout.nodes.find((n) => n.id === selected || n.members.includes(selected)) : undefined;
  const neighbours = new Set<string>();
  if (selectedNode) {
    neighbours.add(selectedNode.id);
    for (const l of layout.links) {
      if (l.source === selectedNode.id) neighbours.add(l.target);
      if (l.target === selectedNode.id) neighbours.add(l.source);
    }
  }
  const folders = [...new Set(view.nodes.filter((n) => n.kind === "file").map((n) => folderOf(n.file)))].sort();
  const folderColor = (folder: string) => PALETTE[Math.max(0, folders.indexOf(folder)) % PALETTE.length];
  const fill = (n: VNode) =>
    colorBy === "risk" ? riskColor(n, surface) : colorBy === "kind" ? KIND_COLOR[n.kind] ?? "#2f5fb3" : folderColor(folderOf(n.file || n.group));
  const hullColor = (group: string) => folderColor(group);

  const files = view.nodes.filter((n) => n.kind === "file");
  const fns = view.nodes.filter((n) => n.kind === "function" || n.kind === "class");
  const calls = view.edges.filter((e) => e.kind === "calls");
  const entries = view.nodes.filter((n) => n.entry_point);
  const loc = files.reduce((t, n) => t + n.end_line, 0);
  const reachable = report.findings.filter((f) => reachOf(f) === "reachable");
  const findingById = new Map(report.findings.map((f) => [f.id, f]));
  const showLabels = layout.nodes.length <= 160;

  function zoomBy(k: number) {
    if (svgRef.current && zoomRef.current) select(svgRef.current).call(zoomRef.current.scaleBy, k);
  }

  const pick = (graphId: string) => {
    const node = view.nodes.find((n) => n.id === graphId);
    if (node && node.kind !== "file" && level === "files") setLevel("functions");
    setSelected(graphId);
    setTab("details");
  };
  const zoomToNode = (graphId: string) => {
    pick(graphId);
    const n = layout.nodes.find((v) => v.id === graphId || v.members.includes(graphId));
    if (n) fitTo([n.x - 260, n.y - 180, n.x + 260, n.y + 180]);
  };

  const q = query.trim().toLowerCase();
  const matches = q ? view.nodes.filter((n) => n.kind !== "unknown" && n.name.toLowerCase().includes(q)).slice(0, 8) : [];
  const graphNode = selected ? view.nodes.find((n) => n.id === selected) : undefined;
  const callers = graphNode ? calls.filter((e) => e.dst === graphNode.id).map((e) => e.src) : [];
  const callees = graphNode ? calls.filter((e) => e.src === graphNode.id).map((e) => e.dst) : [];
  const nameOf = (id: string) => view.nodes.find((n) => n.id === id)?.name ?? id.replace("unknown::", "");

  return (
    <div className="flex flex-col overflow-hidden rounded-2xl border border-line bg-card">
      <div className="grid h-[calc(100vh-300px)] min-h-[600px] grid-cols-[250px_1fr_330px]">
        {/* ── Left sidebar ─────────────────────────────────────────── */}
        <aside className="flex min-h-0 flex-col gap-4 overflow-y-auto border-r border-line bg-paper p-4">
          <div className="flex items-center gap-3 rounded-xl border border-line bg-card p-3">
            <div className="relative grid h-14 w-14 place-items-center">
              <svg viewBox="0 0 36 36" className="absolute inset-0 -rotate-90">
                <circle cx="18" cy="18" r="15" fill="none" stroke="#ece8df" strokeWidth="4" />
                <circle
                  cx="18" cy="18" r="15" fill="none" stroke="#b3261e" strokeWidth="4" strokeLinecap="round"
                  strokeDasharray={`${(94.2 * reachable.length) / Math.max(1, report.findings.length)} 94.2`}
                />
              </svg>
              <span className="text-lg font-bold text-real">{reachable.length}</span>
            </div>
            <div className="min-w-0">
              <div className="truncate font-mono text-sm font-semibold">{report.repo}</div>
              <div className="text-xs text-muted">of {report.findings.length} warnings reachable</div>
            </div>
          </div>

          <section>
            <h4 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted">Color by</h4>
            <div className="grid grid-cols-3 gap-1">
              {(["folder", "risk", "kind"] as const).map((c) => (
                <button
                  key={c}
                  onClick={() => setColorBy(c)}
                  className={`rounded-lg py-1.5 text-xs font-semibold capitalize ${colorBy === c ? "bg-ink text-paper" : "bg-card text-ink hover:bg-paper-2"}`}
                >
                  {c}
                </button>
              ))}
            </div>
          </section>

          <section className="grid grid-cols-2 gap-2">
            <Tile value={files.length} label="Files" />
            <Tile value={fns.length} label="Functions" />
            <Tile value={calls.length} label="Calls" />
            <Tile value={entries.length} label="Entry points" />
          </section>

          <section className="flex flex-col gap-1.5">
            <div className="flex justify-between text-xs">
              <span className="font-semibold">{loc.toLocaleString()} lines of Python</span>
              <span className="text-muted">{pct(report.graph.coverage.ratio)} resolved</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-paper-2">
              <div className="h-2 rounded-full bg-safe" style={{ width: pct(report.graph.coverage.ratio) }} />
            </div>
            <span className="text-[11px] text-muted">call sites resolved; the rest are kept as “unresolved”, never dropped</span>
          </section>

          <section className="flex flex-col gap-1">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find a function or file…"
              className="rounded-lg border border-line bg-card px-2 py-1.5 text-sm outline-none focus:border-ink"
            />
            {matches.map((n) => (
              <button key={n.id} onClick={() => { zoomToNode(n.id); setQuery(""); }} className="truncate text-left font-mono text-xs hover:underline">
                {n.name} <span className="text-muted">{n.kind === "file" ? "" : n.file}</span>
              </button>
            ))}
          </section>

          <section className="flex flex-col gap-0.5 text-sm">
            <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">Explorer</h4>
            {folders.map((folder) => {
              const inFolder = files.filter((f) => folderOf(f.file) === folder);
              const open = openFolders.has(folder);
              return (
                <div key={folder}>
                  <button
                    onClick={() => setOpenFolders((s) => { const t = new Set(s); if (open) t.delete(folder); else t.add(folder); return t; })}
                    className="flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-left hover:bg-paper-2"
                  >
                    <span className="w-3 text-xs text-muted">{open ? "▾" : "▸"}</span>
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: folderColor(folder) }} />
                    <span className="truncate font-mono text-xs">{folder}</span>
                    <span className="ml-auto text-[11px] text-muted">{inFolder.length}</span>
                  </button>
                  {open &&
                    inFolder.map((f) => (
                      <button key={f.id} onClick={() => zoomToNode(f.id)} className="block w-full truncate rounded py-0.5 pl-8 text-left font-mono text-xs hover:bg-paper-2">
                        {f.file.slice(f.file.lastIndexOf("/") + 1)}
                        {f.findings.length + view.nodes.filter((n) => n.file === f.file && n.kind !== "file" && n.findings.length).length > 0 && (
                          <span className="ml-1 text-real">●</span>
                        )}
                      </button>
                    ))}
                </div>
              );
            })}
          </section>
        </aside>

        {/* ── Canvas ───────────────────────────────────────────────── */}
        <div className="relative min-w-0 bg-[radial-gradient(#e2ddd2_1px,transparent_1px)] [background-size:18px_18px]">
          <svg ref={svgRef} className="h-full w-full cursor-grab" onClick={(e) => e.target === svgRef.current && setSelected(null)}>
            <defs>
              <marker id="arrow" viewBox="0 -5 10 10" refX="10" markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0,-4L10,0L0,4" fill="#9a9384" />
              </marker>
            </defs>
            <g ref={gRef}>
              {layout.hulls.map((h) => (
                <g key={h.group}>
                  <path d={h.path} fill={hullColor(h.group)} fillOpacity={0.06} stroke={hullColor(h.group)} strokeOpacity={0.35} strokeWidth={2} strokeLinejoin="round" />
                  <text x={h.labelX} y={h.labelY} textAnchor="middle" fill={hullColor(h.group)} fontSize={11} fontWeight={600} className="font-mono" opacity={0.85}>
                    {h.group.length > 34 ? `…${h.group.slice(-33)}` : h.group}
                  </text>
                </g>
              ))}
              {layout.links.map((l, i) => {
                const a = byId.get(l.source);
                const b = byId.get(l.target);
                if (!a || !b) return null;
                const touches = selectedNode && (l.source === selectedNode.id || l.target === selectedNode.id);
                const hot = colorBy === "risk" && a.members.some((m) => surface.has(m)) && b.members.some((m) => surface.has(m));
                const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
                const ex = b.x - ((b.x - a.x) / len) * (b.r + 3);
                const ey = b.y - ((b.y - a.y) / len) * (b.r + 3);
                return (
                  <line
                    key={i} x1={a.x} y1={a.y} x2={ex} y2={ey}
                    stroke={!l.resolved ? "#c99a06" : touches ? "#14213d" : hot ? "#e08a3c" : "#a8a294"}
                    strokeWidth={touches ? 2.2 : Math.min(3, 0.9 + Math.sqrt(l.count) * 0.4)}
                    strokeDasharray={l.resolved ? (l.kind === "imports" ? "2 3" : undefined) : "5 4"}
                    strokeOpacity={selectedNode && !touches ? 0.12 : 0.7}
                    markerEnd="url(#arrow)"
                  />
                );
              })}
              {layout.nodes.map((n) => {
                const dim = selectedNode && !neighbours.has(n.id);
                const isSel = selectedNode?.id === n.id;
                return (
                  <g
                    key={n.id}
                    transform={`translate(${n.x},${n.y})`}
                    opacity={dim ? 0.18 : 1}
                    className="cursor-pointer"
                    onClick={() => { setSelected(n.id === selected ? null : n.id); setTab("details"); }}
                  >
                    <title>{`${n.name}\n${n.kind === "file" ? `${n.fnCount} functions` : `${n.file}:${n.line}`}${n.findings.length ? `\n${n.findings.length} warning(s)` : ""}${n.entry ? "\nentry point" : ""}`}</title>
                    {n.worstReach === "reachable" && <circle r={n.r + 8} fill="none" stroke="#b3261e" strokeWidth={2.2} />}
                    {n.entry && <circle r={n.r + 4.5} fill="none" stroke="#b85a12" strokeWidth={1.6} strokeDasharray="3 2" />}
                    <circle r={n.r} fill={fill(n)} stroke={isSel ? "#14213d" : "#ffffff"} strokeWidth={isSel ? 3 : 1.5} />
                    {n.findings.length > 0 && (
                      <g transform={`translate(${n.r * 0.75},${-n.r * 0.75})`}>
                        <circle r={6.5} fill={n.worstReach === "reachable" ? "#b3261e" : n.worstReach === "unknown" ? "#c99a06" : "#6b7280"} />
                        <text textAnchor="middle" dy={3} fontSize={8} fontWeight={700} fill="#fff">{n.findings.length}</text>
                      </g>
                    )}
                    {(showLabels || n.entry || n.findings.length > 0 || isSel || neighbours.has(n.id)) && (
                      <text
                        textAnchor="middle" dy={n.r + 13} fontSize={9.5} fontWeight={500} className="font-mono"
                        fill="#14213d" stroke="#f7f5f0" strokeWidth={3} paintOrder="stroke"
                      >
                        {n.label}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          <div className="absolute left-3 top-3 flex gap-1">
            <button onClick={() => zoomBy(1.3)} title="Zoom in" className={CONTROL}>+</button>
            <button onClick={() => zoomBy(1 / 1.3)} title="Zoom out" className={CONTROL}>−</button>
            <button onClick={() => fitTo(layout.bounds)} title="Fit" className={CONTROL}>⤢</button>
          </div>

          <select
            value={level}
            onChange={(e) => { setLevel(e.target.value as Level); setSelected(null); }}
            className="absolute left-1/2 top-3 -translate-x-1/2 rounded-lg border border-line bg-card px-3 py-1.5 text-sm shadow-sm"
          >
            <option value="functions">Functions graph</option>
            <option value="files">Files graph</option>
          </select>

          <div className="absolute right-3 top-3 max-h-[40%] w-48 overflow-y-auto rounded-xl border border-line bg-card/95 p-2 text-[11px] shadow-sm">
            {colorBy === "folder" ? (
              <>
                <div className="mb-1 font-semibold uppercase tracking-wider text-muted">Folders</div>
                {folders.slice(0, 12).map((f) => (
                  <div key={f} className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: folderColor(f) }} /><span className="truncate font-mono">{f}</span></div>
                ))}
              </>
            ) : colorBy === "risk" ? (
              <>
                <div className="mb-1 font-semibold uppercase tracking-wider text-muted">Risk</div>
                {[["#b3261e", "Reachable warning"], ["#c99a06", "Unknown"], ["#b85a12", "Untrusted entry point"], ["#f0a35e", "Attack surface"], ["#6b7280", "Unreachable warning"], ["#cfc8b8", "Not reachable"]].map(([c, t]) => (
                  <div key={t} className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />{t}</div>
                ))}
              </>
            ) : (
              <>
                <div className="mb-1 font-semibold uppercase tracking-wider text-muted">Kind</div>
                {Object.entries(KIND_COLOR).map(([k, c]) => (
                  <div key={k} className="flex items-center gap-1.5 capitalize"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />{k}</div>
                ))}
              </>
            )}
            <div className="mt-1.5 border-t border-line pt-1.5 text-muted">
              <div><span className="text-reach">┅◯</span> entry point · <span className="text-real">◯</span> reachable warning</div>
            </div>
          </div>

          <div className="absolute bottom-3 left-3 flex gap-1.5 text-xs">
            {[`${layout.nodes.length} ${level === "files" ? "files" : "functions"}`, `${layout.links.length} links`, `${entries.length} entry pts`].map((c) => (
              <span key={c} className="rounded-lg border border-line bg-card px-2.5 py-1 font-semibold shadow-sm">{c}</span>
            ))}
            {level === "functions" && (
              <label className="flex items-center gap-1.5 rounded-lg border border-line bg-card px-2.5 py-1 shadow-sm">
                <input type="checkbox" checked={showUnknown} onChange={(e) => setShowUnknown(e.target.checked)} className="accent-[#14213d]" />
                unresolved calls
              </label>
            )}
          </div>
        </div>

        {/* ── Right panel ──────────────────────────────────────────── */}
        <aside className="flex min-h-0 flex-col border-l border-line">
          <nav className="flex border-b border-line text-xs font-semibold">
            {([["details", "Details"], ["warnings", `Warnings · ${reachable.length}`], ["entries", `Entry points · ${entries.length}`]] as const).map(([k, t]) => (
              <button key={k} onClick={() => setTab(k)} className={`flex-1 px-2 py-2.5 ${tab === k ? "border-b-2 border-ink text-ink" : "text-muted hover:text-ink"}`}>
                {t}
              </button>
            ))}
          </nav>
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4 text-sm">
            {tab === "details" &&
              (selectedNode ? (
                <>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">
                    {selectedNode.entry ? "untrusted entry point" : selectedNode.kind}
                  </div>
                  <div className="break-all font-mono text-base font-bold">{selectedNode.name}</div>
                  <div className="font-mono text-xs text-muted">
                    {selectedNode.kind === "file" ? `${selectedNode.fnCount} functions/classes` : `${selectedNode.file}:${selectedNode.line}`}
                  </div>
                  <p>
                    {selectedNode.entry
                      ? "Untrusted input enters here."
                      : selectedNode.members.some((m) => surface.has(m))
                        ? "Reachable from an untrusted entry point."
                        : "Not reachable from any untrusted entry point over resolved calls."}
                  </p>
                  {selectedNode.findings.length > 0 && (
                    <div className="flex flex-col gap-1.5">
                      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-muted">Warnings here</h4>
                      {selectedNode.findings.map((fid) => {
                        const f = findingById.get(fid);
                        return f ? (
                          <button key={fid} onClick={() => onOpenFinding(fid)} className="flex items-center gap-2 rounded-lg border border-line px-2 py-1.5 text-left hover:border-ink">
                            <span className="font-mono text-xs font-semibold">{f.rule_id}</span>
                            <ReachBadge reach={reachOf(f)} />
                            <span className="truncate text-xs text-muted">{f.message}</span>
                          </button>
                        ) : null;
                      })}
                    </div>
                  )}
                  {level === "functions" && callers.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-xs text-muted">Called by</span>
                      {callers.map((c) => <button key={c} onClick={() => zoomToNode(c)} className="rounded-md border border-line px-1.5 py-0.5 font-mono text-xs hover:border-ink">{nameOf(c)}</button>)}
                    </div>
                  )}
                  {level === "functions" && callees.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-xs text-muted">Calls</span>
                      {callees.map((c) => <button key={c} onClick={() => zoomToNode(c)} className="rounded-md border border-line px-1.5 py-0.5 font-mono text-xs hover:border-ink">{nameOf(c)}</button>)}
                    </div>
                  )}
                  {selectedNode.kind === "file" && (
                    <div className="flex flex-col gap-1">
                      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-muted">Defines</h4>
                      {selectedNode.members.slice(1).map((m) => (
                        <button key={m} onClick={() => zoomToNode(m)} className="truncate text-left font-mono text-xs hover:underline">{nameOf(m)}</button>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-muted">Click a circle to see what it is, who calls it, what it calls and the warnings on it.</p>
              ))}

            {tab === "warnings" &&
              (reachable.length ? (
                reachable.map((f) => (
                  <button key={f.id} onClick={() => zoomToNode(f.node_id)} className="flex flex-col gap-1 rounded-xl border border-line p-2.5 text-left hover:border-ink">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold">{f.rule_id}</span>
                      <ReachBadge reach="reachable" />
                      <span className="ml-auto text-[11px] text-muted">{f.cwe}</span>
                    </div>
                    <span className="font-mono text-xs">{f.node_name ?? f.file}</span>
                    <span className="truncate text-[11px] text-muted">{f.message}</span>
                  </button>
                ))
              ) : (
                <p className="text-muted">No warning is reachable from an untrusted entry point.</p>
              ))}

            {tab === "entries" &&
              entries.map((n) => (
                <button key={n.id} onClick={() => zoomToNode(n.id)} className="flex items-center gap-2 rounded-lg border border-line px-2 py-1.5 text-left hover:border-ink">
                  <span className="h-3 w-3 shrink-0 rounded-full border-2 border-dashed border-reach" />
                  <span className="truncate font-mono text-xs">{n.name}</span>
                  <span className="ml-auto truncate text-[11px] text-muted">{n.file}</span>
                </button>
              ))}
          </div>
        </aside>
      </div>

      <footer className="flex items-center gap-4 border-t border-line bg-paper px-4 py-1.5 text-xs text-muted">
        <span className="flex items-center gap-1.5 font-semibold text-safe"><span className="h-2 w-2 rounded-full bg-safe" /> Live</span>
        <span>{files.length} files</span>
        <span>{fns.length} functions</span>
        <span>{report.findings.length} warnings</span>
        <span className="text-real">{reachable.length} reachable</span>
        <span>{fns.filter((n) => surface.has(n.id)).length}/{fns.length} functions on the attack surface</span>
        <span className="ml-auto">{loc.toLocaleString()} lines of Python</span>
      </footer>
    </div>
  );
}

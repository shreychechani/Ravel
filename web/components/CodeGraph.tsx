"use client";

import dagre from "@dagrejs/dagre";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useEffect, useMemo, useState } from "react";

import { type Finding, type GraphEdge, type GraphNode, type Report } from "@/lib/report";
import { ReachBadge } from "./Badges";

const W = 210;
const H = 54;

interface Data extends Record<string, unknown> {
  node: GraphNode;
  inSurface: boolean;
  dim: boolean;
  selected: boolean;
}

// Fill/border by what the node is and what is wrong with it.
function nodeClass(d: Data): string {
  const n = d.node;
  if (n.kind === "unknown") return "border-dashed border-unknown bg-unknown-soft";
  if (n.kind === "file") return "border-ink bg-paper-2";
  if (n.worst_reach === "reachable") return "border-real bg-real-soft";
  if (n.entry_point) return "border-reach bg-reach-soft";
  if (n.worst_reach === "unknown") return "border-unknown bg-unknown-soft";
  if (d.inSurface) return "border-reach bg-card";
  return "border-line bg-card";
}

function tag(n: GraphNode): string {
  if (n.kind === "unknown") return "unresolved call";
  if (n.entry_point) return "web route · untrusted";
  return n.kind;
}

function GraphNodeView({ data }: NodeProps<Node<Data>>) {
  const n = data.node;
  return (
    <div
      className={`relative rounded-xl border-2 px-3 py-1.5 transition ${nodeClass(data)} ${
        data.selected ? "shadow-[0_0_0_3px_#14213d]" : ""
      }`}
      style={{ width: W, opacity: data.dim ? 0.25 : 1 }}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div className="text-[9px] font-semibold uppercase tracking-wider text-muted">{tag(n)}</div>
      <div className="truncate font-mono text-[13px] font-semibold text-ink">{n.name}</div>
      {n.kind !== "unknown" && (
        <div className="truncate font-mono text-[10px] text-muted">
          {n.file}
          {n.kind !== "file" ? `:${n.line}` : ""}
        </div>
      )}
      {n.findings.length > 0 && (
        <span
          className={`absolute -right-2 -top-2 rounded-full px-1.5 text-[11px] font-bold text-white ${
            n.worst_reach === "reachable" ? "bg-real" : n.worst_reach === "unknown" ? "bg-unknown" : "bg-unreach"
          }`}
          title={`${n.findings.length} warning(s)`}
        >
          {n.findings.length}
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}

const nodeTypes = { code: GraphNodeView, file: FileBox };

const EDGE_STYLE: Record<string, { stroke: string; dash?: string }> = {
  calls: { stroke: "#14213d" },
  inherits: { stroke: "#6a4c93", dash: "2 4" },
  imports: { stroke: "#2f5fb3", dash: "1 4" },
  defines: { stroke: "#c9c3b5" },
};

/** Everything an untrusted entry point can reach over resolved edges (the engine's view). */
function attackSurface(nodes: GraphNode[], edges: GraphEdge[]): Set<string> {
  const out = new Map<string, string[]>();
  for (const e of edges) {
    if (!e.resolved) continue;
    out.set(e.src, [...(out.get(e.src) ?? []), e.dst]);
  }
  const seen = new Set(nodes.filter((n) => n.entry_point).map((n) => n.id));
  const queue = [...seen];
  while (queue.length) {
    for (const next of out.get(queue.pop()!) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}

interface Options {
  byFile: boolean;
  files: boolean;
  unknown: boolean;
  isolated: boolean;
}

function visible(report: Report, opt: Options) {
  const view = report.graph_view!;
  const kinds = new Set(["calls", "inherits", ...(opt.files ? ["defines", "imports"] : [])]);
  let nodes = view.nodes.filter(
    (n) => (n.kind !== "file" || opt.files) && (n.kind !== "unknown" || opt.unknown),
  );
  let ids = new Set(nodes.map((n) => n.id));
  const edges = view.edges.filter((e) => kinds.has(e.kind) && ids.has(e.src) && ids.has(e.dst));
  if (!opt.isolated) {
    const linked = new Set(edges.flatMap((e) => [e.src, e.dst]));
    nodes = nodes.filter((n) => linked.has(n.id) || n.entry_point || n.findings.length > 0);
    ids = new Set(nodes.map((n) => n.id));
  }
  return { nodes, edges: edges.filter((e) => ids.has(e.src) && ids.has(e.dst)) };
}

const PAD = 28; // inside a file box
const HEAD = 34; // file box title
const GAP = 48; // between boxes

interface Box {
  key: string;
  label: string | null; // file path when grouped by file
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Cluster key: the node's file (unknown targets join their first caller's file), or one cluster. */
function clusters(nodes: GraphNode[], edges: GraphEdge[], byFile: boolean): Map<string, string> {
  const key = new Map<string, string>();
  if (!byFile) {
    for (const n of nodes) key.set(n.id, "all");
    return key;
  }
  for (const n of nodes) if (n.kind !== "unknown") key.set(n.id, n.file);
  for (const e of edges) if (!key.has(e.dst) && key.has(e.src)) key.set(e.dst, key.get(e.src)!);
  for (const n of nodes) if (!key.has(n.id)) key.set(n.id, "(unresolved)");
  return key;
}

interface Sized {
  key: string;
  w: number;
  h: number;
}

/** Shelf-pack rectangles, tallest first, into rows about `aspect` times wider than tall. */
function pack(items: Sized[], gap: number, aspect: number): Map<string, { x: number; y: number }> {
  const sorted = [...items].sort((a, b) => b.h - a.h || a.key.localeCompare(b.key));
  const area = sorted.reduce((t, b) => t + (b.w + gap) * (b.h + gap), 0);
  const rowWidth = Math.max(Math.sqrt(area * aspect), ...sorted.map((b) => b.w));
  const out = new Map<string, { x: number; y: number }>();
  let x = 0;
  let y = 0;
  let rowH = 0;
  for (const b of sorted) {
    if (x > 0 && x + b.w > rowWidth) {
      x = 0;
      y += rowH + gap;
      rowH = 0;
    }
    out.set(b.key, { x, y });
    x += b.w + gap;
    rowH = Math.max(rowH, b.h);
  }
  return out;
}

/** Inside one cluster: dagre per connected group, then pack the groups. */
function layoutCluster(members: GraphNode[], edges: GraphEdge[]) {
  const ids = new Set(members.map((n) => n.id));
  const inner = edges.filter((e) => ids.has(e.src) && ids.has(e.dst));
  const parent = new Map(members.map((n) => [n.id, n.id]));
  const find = (x: string): string => (parent.get(x) === x ? x : find(parent.get(x)!));
  for (const e of inner) parent.set(find(e.src), find(e.dst));
  const comps = new Map<string, GraphNode[]>();
  for (const n of members) comps.set(find(n.id), [...(comps.get(find(n.id)) ?? []), n]);

  const local = new Map<string, { x: number; y: number }>();
  const sized: Sized[] = [];
  for (const [root, group] of comps) {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 16, ranksep: 56 });
    g.setDefaultEdgeLabel(() => ({}));
    group.forEach((n) => g.setNode(n.id, { width: W, height: H }));
    inner.forEach((e) => parent.has(e.src) && find(e.src) === root && g.setEdge(e.src, e.dst));
    dagre.layout(g);
    let w = 0;
    let h = 0;
    for (const n of group) {
      const p = g.node(n.id);
      local.set(n.id, { x: p.x - W / 2, y: p.y - H / 2 });
      w = Math.max(w, p.x + W / 2);
      h = Math.max(h, p.y + H / 2);
    }
    sized.push({ key: root, w, h });
  }
  const at = pack(sized, 20, 1.4);
  const positions = new Map<string, { x: number; y: number }>();
  let w = 0;
  let h = 0;
  for (const n of members) {
    const o = at.get(find(n.id))!;
    const p = local.get(n.id)!;
    const pos = { x: o.x + p.x, y: o.y + p.y };
    positions.set(n.id, pos);
    w = Math.max(w, pos.x + W);
    h = Math.max(h, pos.y + H);
  }
  return { positions, w, h };
}

/** Clusters (files) laid out inside, then packed into a screen-shaped canvas. */
function layout(nodes: GraphNode[], edges: GraphEdge[], byFile: boolean) {
  const key = clusters(nodes, edges, byFile);
  const groups = new Map<string, GraphNode[]>();
  for (const n of nodes) groups.set(key.get(n.id)!, [...(groups.get(key.get(n.id)!) ?? []), n]);
  const pad = byFile ? PAD : 0;
  const head = byFile ? HEAD : 0;

  const inner = new Map<string, ReturnType<typeof layoutCluster>>();
  for (const [k, members] of groups) inner.set(k, layoutCluster(members, edges));
  const sized = [...inner].map(([k, c]) => ({ key: k, w: c.w + 2 * pad, h: c.h + 2 * pad + head }));
  const at = pack(sized, GAP, 1.6);

  const boxes: Box[] = sized.map((b) => ({ ...b, ...at.get(b.key)!, label: byFile ? b.key : null }));
  const positions = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    const o = at.get(key.get(n.id)!)!;
    const p = inner.get(key.get(n.id)!)!.positions.get(n.id)!;
    positions.set(n.id, { x: o.x + pad + p.x, y: o.y + pad + head + p.y });
  }
  return { positions, boxes };
}

function FileBox({ data }: NodeProps<Node<{ label: string; w: number; h: number }>>) {
  return (
    <div
      className="rounded-2xl border-2 border-dashed border-[#c9c3b5] bg-[#f3f0e8]/70"
      style={{ width: data.w, height: data.h }}
    >
      <div className="truncate px-4 pt-2 font-mono text-sm font-semibold text-muted">{data.label}</div>
    </div>
  );
}

/** Frame a node together with its callers and callees. */
function Focus({ ids }: { ids: string[] }) {
  const flow = useReactFlow();
  const key = ids.join("|");
  useEffect(() => {
    if (key) flow.fitView({ nodes: key.split("|").map((id) => ({ id })), duration: 400, maxZoom: 1, padding: 0.3 });
  }, [key, flow]);
  return null;
}

function Toggle({ on, set, label }: { on: boolean; set: (v: boolean) => void; label: string }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm">
      <input type="checkbox" checked={on} onChange={(e) => set(e.target.checked)} className="accent-[#14213d]" />
      {label}
    </label>
  );
}

function NodeLink({ report, id, onSelect }: { report: Report; id: string; onSelect: (id: string) => void }) {
  const n = report.graph_view!.nodes.find((x) => x.id === id);
  return (
    <button onClick={() => onSelect(id)} className="rounded-md border border-line bg-card px-2 py-0.5 font-mono text-xs hover:border-ink">
      {n?.name ?? id}
    </button>
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
  // The tab remounts on every visit, so the focus from "Show in code graph" seeds the state.
  // A module-level warning sits on a file node, so the file layer starts on for it.
  const focusIsFile = report.graph_view?.nodes.find((n) => n.id === focus)?.kind === "file";
  const [opt, setOpt] = useState<Options>({ byFile: true, files: focusIsFile, unknown: true, isolated: false });
  const [surfaceOn, setSurfaceOn] = useState(true);
  const [selected, setSelected] = useState<string | null>(focus);
  const [zoomTo, setZoomTo] = useState<string | null>(focus); // jumps zoom; clicks don't
  const [query, setQuery] = useState("");
  const jump = (id: string) => {
    setSelected(id);
    setZoomTo(id);
  };

  const view = report.graph_view;
  const surface = useMemo(() => (view ? attackSurface(view.nodes, view.edges) : new Set<string>()), [view]);
  const shown = useMemo(() => (view ? visible(report, opt) : { nodes: [], edges: [] }), [report, view, opt]);
  const { positions, boxes } = useMemo(
    () => layout(shown.nodes, shown.edges, opt.byFile),
    [shown, opt.byFile],
  );

  if (!view) {
    return <p className="p-6 text-sm text-muted">This report has no code graph (made by an older Ravel). Rescan to see it.</p>;
  }

  const neighbours = new Set<string>();
  if (selected) {
    neighbours.add(selected);
    for (const e of shown.edges) {
      if (e.src === selected) neighbours.add(e.dst);
      if (e.dst === selected) neighbours.add(e.src);
    }
  }
  const fileBoxes: Node[] = boxes
    .filter((b) => b.label !== null)
    .map((b) => ({
      id: `box::${b.key}`,
      type: "file",
      position: { x: b.x, y: b.y },
      data: { label: b.label, w: b.w, h: b.h },
      selectable: false,
      zIndex: -1,
    }));
  const codeNodes: Node<Data>[] = shown.nodes.map((n) => ({
    id: n.id,
    type: "code",
    position: positions.get(n.id)!,
    data: {
      node: n,
      inSurface: surfaceOn && surface.has(n.id),
      dim: selected !== null && !neighbours.has(n.id),
      selected: n.id === selected,
    },
  }));
  const nodes: Node[] = [...fileBoxes, ...codeNodes];
  const edges: Edge[] = shown.edges.map((e, i) => {
    const s = EDGE_STYLE[e.kind] ?? EDGE_STYLE.calls;
    const touches = selected !== null && (e.src === selected || e.dst === selected);
    const hot = surfaceOn && e.kind === "calls" && e.resolved && surface.has(e.src) && surface.has(e.dst);
    const stroke = !e.resolved ? "#8a6d00" : hot ? "#b85a12" : s.stroke;
    return {
      id: `e${i}`,
      source: e.src,
      target: e.dst,
      style: {
        stroke,
        strokeWidth: touches ? 3 : hot ? 2 : 1.3,
        strokeDasharray: e.resolved ? s.dash : "6 4",
        opacity: selected !== null && !touches ? 0.15 : 1,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
    };
  });

  const fns = view.nodes.filter((n) => n.kind === "function" || n.kind === "class");
  const reachableFns = fns.filter((n) => surface.has(n.id)).length;
  const calls = view.edges.filter((e) => e.kind === "calls");
  const node = selected ? view.nodes.find((n) => n.id === selected) : undefined;
  const callers = node ? calls.filter((e) => e.dst === node.id).map((e) => e.src) : [];
  const callees = node ? calls.filter((e) => e.src === node.id).map((e) => e.dst) : [];
  const byId = new Map(report.findings.map((f) => [f.id, f] as [string, Finding]));
  const q = query.trim().toLowerCase();
  const matches = q ? view.nodes.filter((n) => n.name.toLowerCase().includes(q)).slice(0, 8) : [];

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
      <div className="h-[calc(100vh-300px)] min-h-[520px] overflow-hidden rounded-2xl border border-line bg-card">
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.05}
            nodesDraggable={false}
            nodesConnectable={false}
            fitViewOptions={{ maxZoom: 1 }}
            onNodeClick={(_, n) => n.type === "code" && setSelected(n.id === selected ? null : n.id)}
            onPaneClick={() => setSelected(null)}
          >
            <Background gap={22} color="#e2ddd2" />
            <Controls showInteractive={false} />
            <Focus
              ids={
                zoomTo
                  ? [zoomTo, ...shown.edges.flatMap((e) => (e.src === zoomTo ? [e.dst] : e.dst === zoomTo ? [e.src] : []))]
                  : []
              }
            />
          </ReactFlow>
        </ReactFlowProvider>
      </div>

      <aside className="flex flex-col gap-4 text-sm">
        <section className="rounded-2xl border border-line bg-card p-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">The knowledge graph</h3>
          <p>
            <b>{fns.length}</b> functions/classes · <b>{calls.length}</b> calls ·{" "}
            <b>{view.nodes.filter((n) => n.entry_point).length}</b> web entry points
          </p>
          <p className="mt-1">
            Attack surface: <b className="text-reach">{reachableFns}</b> of {fns.length} reachable from untrusted input.
          </p>
          <p className="mt-1 text-muted">
            {pctText(report.graph.coverage.ratio)} of call sites resolved; the rest are drawn as dashed “unresolved”.
          </p>
        </section>

        <section className="flex flex-col gap-2 rounded-2xl border border-line bg-card p-4">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Find a function, class or file…"
            className="rounded-lg border border-line bg-paper px-2 py-1.5 outline-none focus:border-ink"
          />
          {matches.map((n) => (
            <button key={n.id} onClick={() => { jump(n.id); setQuery(""); }} className="truncate text-left font-mono text-xs hover:underline">
              {n.name} <span className="text-muted">{n.file}</span>
            </button>
          ))}
          <Toggle on={surfaceOn} set={setSurfaceOn} label="Highlight what attackers can reach" />
          <Toggle on={opt.byFile} set={(v) => setOpt({ ...opt, byFile: v })} label="Group by file" />
          <Toggle on={opt.files} set={(v) => setOpt({ ...opt, files: v })} label="Show files, imports and definitions" />
          <Toggle on={opt.unknown} set={(v) => setOpt({ ...opt, unknown: v })} label="Show unresolved calls" />
          <Toggle on={opt.isolated} set={(v) => setOpt({ ...opt, isolated: v })} label="Show unconnected functions" />
        </section>

        {node ? (
          <section className="flex flex-col gap-2 rounded-2xl border border-ink bg-card p-4">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">{tag(node)}</div>
            <div className="font-mono text-base font-bold">{node.name}</div>
            {node.kind !== "unknown" && (
              <div className="font-mono text-xs text-muted">
                {node.file}
                {node.kind !== "file" ? `:${node.line}–${node.end_line}` : ""}
              </div>
            )}
            <p>
              {surface.has(node.id)
                ? node.entry_point
                  ? "Untrusted input enters here."
                  : "Reachable from an untrusted entry point."
                : "Not reachable from any untrusted entry point over resolved calls."}
            </p>
            {node.findings.length > 0 && (
              <div className="flex flex-col gap-1">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">Warnings here</h4>
                {node.findings.map((fid) => {
                  const f = byId.get(fid);
                  return f ? (
                    <button key={fid} onClick={() => onOpenFinding(fid)} className="flex items-center gap-2 text-left hover:underline">
                      <span className="font-mono font-semibold">{f.rule_id}</span>
                      <ReachBadge reach={f.static_evidence?.reachable ?? "unknown"} />
                      <span className="truncate text-xs text-muted">{f.message}</span>
                    </button>
                  ) : null;
                })}
              </div>
            )}
            {callers.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-xs text-muted">Called by</span>
                {callers.map((c) => <NodeLink key={c} report={report} id={c} onSelect={jump} />)}
              </div>
            )}
            {callees.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-xs text-muted">Calls</span>
                {callees.map((c) => <NodeLink key={c} report={report} id={c} onSelect={jump} />)}
              </div>
            )}
          </section>
        ) : (
          <section className="rounded-2xl border border-line bg-card p-4 text-muted">
            Click a node to see what calls it, what it calls, and the warnings on it.
          </section>
        )}

        <section className="grid grid-cols-2 gap-2 rounded-2xl border border-line bg-card p-4 text-xs">
          <Legend box="border-reach bg-reach-soft" text="Web entry point" />
          <Legend box="border-real bg-real-soft" text="Reachable warning" />
          <Legend box="border-reach bg-card" text="Attack surface" />
          <Legend box="border-line bg-card" text="Not reachable" />
          <Legend box="border-dashed border-unknown bg-unknown-soft" text="Unresolved call" />
          <Legend box="border-ink bg-paper-2" text="File" />
        </section>
      </aside>
    </div>
  );
}

const pctText = (x: number) => `${(x * 100).toFixed(1)}%`;

function Legend({ box, text }: { box: string; text: string }) {
  return (
    <span className="flex items-center gap-2">
      <span className={`inline-block h-3.5 w-5 rounded border-2 ${box}`} />
      {text}
    </span>
  );
}

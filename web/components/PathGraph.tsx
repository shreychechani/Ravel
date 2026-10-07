"use client";

import dagre from "@dagrejs/dagre";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { type Finding, type Report } from "@/lib/report";

type Role = "entry" | "call" | "flagged" | "caller" | "unknown" | "package";

interface Data extends Record<string, unknown> {
  title: string;
  sub: string;
  role: Role;
}

const W = 230;
const H = 64;

const ROLE_STYLE: Record<Role, { box: string; tag: string }> = {
  entry: { box: "border-reach bg-reach-soft", tag: "web route · untrusted" },
  call: { box: "border-graph bg-card", tag: "function" },
  flagged: { box: "border-real bg-real-soft", tag: "flagged code" },
  caller: { box: "border-line bg-card opacity-70", tag: "other caller" },
  unknown: { box: "border-unknown border-dashed bg-unknown-soft", tag: "unresolved call" },
  package: { box: "border-ink bg-paper-2", tag: "vulnerable package" },
};

function GraphNode({ data }: NodeProps<Node<Data>>) {
  const s = ROLE_STYLE[data.role];
  return (
    <div className={`rounded-xl border-2 px-3 py-2 shadow-sm ${s.box}`} style={{ width: W }}>
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">{s.tag}</div>
      <div className="truncate font-mono text-sm font-semibold text-ink">{data.title}</div>
      <div className="truncate font-mono text-[11px] text-muted">{data.sub}</div>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}

const nodeTypes = { ravel: GraphNode };

function label(report: Report, id: string): { title: string; sub: string } {
  if (id.startsWith("unknown::")) return { title: id.slice("unknown::".length) || "?", sub: "could not resolve" };
  const n = report.nodes[id];
  return n ? { title: n.name, sub: `${n.file}:${n.line}` } : { title: id, sub: "" };
}

function layout(nodes: Node<Data>[], edges: Edge[]): Node<Data>[] {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 28, ranksep: 70 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: W, height: H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return { ...n, position: { x: p.x - W / 2, y: p.y - H / 2 } };
  });
}

function build(report: Report, f: Finding): { nodes: Node<Data>[]; edges: Edge[] } {
  const nodes = new Map<string, Node<Data>>();
  const edges: Edge[] = [];
  const entries = new Set(report.entry_points.map((e) => e.node_id));
  const add = (id: string, role: Role) => {
    if (!nodes.has(id)) nodes.set(id, { id, type: "ravel", position: { x: 0, y: 0 }, data: { ...label(report, id), role } });
  };
  const arrow = { type: MarkerType.ArrowClosed, width: 16, height: 16 };

  if (f.package) {
    const pkg = `package::${f.package}`;
    nodes.set(pkg, {
      id: pkg,
      type: "ravel",
      position: { x: 0, y: 0 },
      data: { title: `${f.package} ${f.package_version ?? ""}`, sub: f.fixed_in ? `fixed in ${f.fixed_in}` : f.file, role: "package" },
    });
    f.anchors.slice(0, 8).forEach((a) => {
      add(a, entries.has(a) ? "entry" : "call");
      edges.push({ id: `${a}->${pkg}`, source: a, target: pkg, label: "imports", markerEnd: arrow });
    });
    return { nodes: layout([...nodes.values()], edges), edges };
  }

  const path = f.static_evidence?.path ?? [];
  path.forEach((id, i) => {
    const role: Role = id.startsWith("unknown::")
      ? "unknown"
      : i === path.length - 1
        ? "flagged"
        : i === 0 && entries.has(id)
          ? "entry"
          : "call";
    add(id, role);
  });
  f.path_hops.forEach((h, i) =>
    edges.push({
      id: `hop-${i}`,
      source: h.src,
      target: h.dst,
      label: h.resolved ? undefined : "unresolved",
      style: h.resolved ? { stroke: "#14213d", strokeWidth: 2 } : { stroke: "#8a6d00", strokeWidth: 2, strokeDasharray: "6 4" },
      markerEnd: { ...arrow, color: h.resolved ? "#14213d" : "#8a6d00" },
    }),
  );
  if (!path.length) add(f.node_id, "flagged");
  const target = path.length ? path[path.length - 1] : f.node_id;
  f.callers
    .filter((c) => !path.includes(c))
    .slice(0, 6)
    .forEach((c) => {
      add(c, entries.has(c) ? "entry" : "caller");
      edges.push({ id: `caller-${c}`, source: c, target, style: { stroke: "#9aa3b2" }, markerEnd: { ...arrow, color: "#9aa3b2" } });
    });
  return { nodes: layout([...nodes.values()], edges), edges };
}

export function PathGraph({ report, finding }: { report: Report; finding: Finding }) {
  const { nodes, edges } = build(report, finding);
  return (
    <div className="h-[300px] w-full overflow-hidden rounded-xl border border-line bg-card">
      <ReactFlow
        key={finding.id}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background gap={20} color="#e2ddd2" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

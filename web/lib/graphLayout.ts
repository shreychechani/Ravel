// The code graph as Arcflow draws it (view taxonomy only — reference/Arcflow's
// renderer-d3.js), rebuilt for Ravel: circles grouped into hulls, pulled toward
// a centre per group. PRODUCT.md §5 rules out d3-force because a live
// simulation jitters between renders, so the simulation is run to a fixed
// number of ticks once, from deterministic start positions (d3-force's own RNG
// is a seeded LCG): the same report always gives the same picture.

import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import { polygonHull } from "d3-polygon";

import type { GraphEdge, GraphNode, Report } from "./report";

export type Level = "files" | "functions";

export interface VNode extends SimulationNodeDatum {
  id: string;
  name: string;
  label: string;
  group: string; // the folder: one hull per folder, as in Arcflow
  kind: string;
  file: string;
  line: number;
  r: number;
  entry: boolean;
  findings: string[];
  worstReach: GraphNode["worst_reach"];
  fnCount: number; // files level: functions/classes defined in the file
  members: string[]; // files level: the graph-node ids folded into this file
  x: number;
  y: number;
}

export interface VLink {
  source: string;
  target: string;
  kind: string;
  resolved: boolean;
  count: number;
}

export interface Hull {
  group: string;
  path: string;
  labelX: number;
  labelY: number;
  bounds: [number, number, number, number];
}

export interface Layout {
  nodes: VNode[];
  links: VLink[];
  hulls: Hull[];
  groups: string[];
  bounds: [number, number, number, number];
}

const folderOf = (file: string) => (file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "(root)");
const baseName = (s: string) => s.slice(s.lastIndexOf("/") + 1);
const short = (s: string) => (s.length <= 16 ? s : `${s.slice(0, 15)}…`);

const REACH_ORDER = { reachable: 0, unknown: 1, unreachable: 2 } as const;
function worst(a: VNode["worstReach"], b: VNode["worstReach"]): VNode["worstReach"] {
  if (!a) return b;
  if (!b) return a;
  return REACH_ORDER[a] <= REACH_ORDER[b] ? a : b;
}

/** Files level: one circle per file, calls and imports folded into file-to-file links. */
function filesGraph(view: NonNullable<Report["graph_view"]>): { nodes: VNode[]; links: VLink[] } {
  const fileOf = new Map<string, string>();
  const byFile = new Map<string, VNode>();
  for (const n of view.nodes) {
    if (n.kind !== "file") continue;
    byFile.set(n.file, {
      id: n.id, name: n.file, label: short(baseName(n.file)), group: folderOf(n.file), kind: "file",
      file: n.file, line: 1, r: 0, entry: n.entry_point, findings: [...n.findings],
      worstReach: n.worst_reach, fnCount: 0, members: [n.id], x: 0, y: 0,
    });
  }
  for (const n of view.nodes) {
    if (n.kind === "unknown") continue;
    const f = byFile.get(n.file);
    if (!f) continue;
    fileOf.set(n.id, f.id);
    if (n.kind === "file") continue;
    f.fnCount += 1;
    f.members.push(n.id);
    f.entry ||= n.entry_point;
    f.findings.push(...n.findings);
    f.worstReach = worst(f.worstReach, n.worst_reach);
  }
  const counts = new Map<string, VLink>();
  for (const e of view.edges) {
    if (e.kind !== "calls" && e.kind !== "imports" && e.kind !== "inherits") continue;
    const a = fileOf.get(e.src);
    const b = fileOf.get(e.dst);
    if (!a || !b || a === b) continue;
    const key = `${a}->${b}`;
    const l = counts.get(key) ?? { source: a, target: b, kind: e.kind, resolved: true, count: 0 };
    l.count += 1;
    if (e.kind === "calls") l.kind = "calls";
    counts.set(key, l);
  }
  const nodes = [...byFile.values()];
  for (const n of nodes) n.r = 7 + 2.4 * Math.sqrt(n.fnCount);
  return { nodes, links: [...counts.values()] };
}

/** Functions level: one circle per function/class, grouped by folder. */
function functionsGraph(
  view: NonNullable<Report["graph_view"]>,
  showUnknown: boolean,
): { nodes: VNode[]; links: VLink[] } {
  const keep = (n: GraphNode) => n.kind === "function" || n.kind === "class" || (showUnknown && n.kind === "unknown");
  const nodes: VNode[] = [];
  const ids = new Set<string>();
  const callerFile = new Map<string, string>();
  for (const e of view.edges) {
    const src = view.nodes.find((n) => n.id === e.src);
    if (src && !callerFile.has(e.dst)) callerFile.set(e.dst, src.file);
  }
  for (const n of view.nodes) {
    if (!keep(n)) continue;
    ids.add(n.id);
    const file = n.kind === "unknown" ? (callerFile.get(n.id) ?? "(unresolved)") : n.file;
    nodes.push({
      id: n.id, name: n.name, label: short(n.name.slice(n.name.lastIndexOf(".") + 1)), group: folderOf(file),
      kind: n.kind, file: n.file, line: n.line, r: 0, entry: n.entry_point, findings: n.findings,
      worstReach: n.worst_reach, fnCount: 0, members: [n.id], x: 0, y: 0,
    });
  }
  const links: VLink[] = view.edges
    .filter((e) => (e.kind === "calls" || e.kind === "inherits") && ids.has(e.src) && ids.has(e.dst) && e.src !== e.dst)
    .map((e: GraphEdge) => ({ source: e.src, target: e.dst, kind: e.kind, resolved: e.resolved, count: 1 }));
  const degree = new Map<string, number>();
  for (const l of links) {
    degree.set(l.source, (degree.get(l.source) ?? 0) + 1);
    degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
  }
  for (const n of nodes) {
    n.r = n.kind === "unknown" ? 4 : Math.min(15, 5 + 1.8 * Math.sqrt(degree.get(n.id) ?? 0)) + (n.findings.length ? 2 : 0);
  }
  return { nodes, links };
}

/** Group centres: shelf-pack one square per group, sized by how much it holds. */
function centres(nodes: VNode[]): Map<string, { x: number; y: number }> {
  const area = new Map<string, number>();
  const room = nodes.length < 60 ? 70 : 26;
  for (const n of nodes) area.set(n.group, (area.get(n.group) ?? 0) + (2 * n.r + room) ** 2);
  const boxes = [...area]
    .map(([g, a]) => ({ g, side: Math.sqrt(a) * 1.25 + 80 }))
    .sort((a, b) => b.side - a.side || a.g.localeCompare(b.g));
  const total = boxes.reduce((t, b) => t + b.side * b.side, 0);
  const rowWidth = Math.max(Math.sqrt(total * 1.7), ...boxes.map((b) => b.side));
  const out = new Map<string, { x: number; y: number }>();
  let x = 0;
  let y = 0;
  let rowH = 0;
  for (const b of boxes) {
    if (x > 0 && x + b.side > rowWidth) {
      x = 0;
      y += rowH;
      rowH = 0;
    }
    out.set(b.g, { x: x + b.side / 2, y: y + b.side / 2 });
    x += b.side;
    rowH = Math.max(rowH, b.side);
  }
  return out;
}

function hullFor(group: string, members: VNode[]): Hull | null {
  const pad = 22;
  const pts: [number, number][] = [];
  for (const n of members) {
    const p = n.r + pad;
    pts.push([n.x - p, n.y - p], [n.x + p, n.y - p], [n.x - p, n.y + p], [n.x + p, n.y + p]);
  }
  const hull = polygonHull(pts);
  if (!hull) return null;
  const xs = hull.map((p) => p[0]);
  const ys = hull.map((p) => p[1]);
  return {
    group,
    path: `M${hull.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("L")}Z`,
    labelX: members.reduce((t, n) => t + n.x, 0) / members.length,
    labelY: Math.min(...ys) - 8,
    bounds: [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)],
  };
}

export function buildLayout(report: Report, level: Level, showUnknown: boolean): Layout | null {
  const view = report.graph_view;
  if (!view) return null;
  const { nodes, links } = level === "files" ? filesGraph(view) : functionsGraph(view, showUnknown);
  const centre = centres(nodes);

  // Deterministic start: each group's members on a sunflower spiral round its centre.
  const seen = new Map<string, number>();
  for (const n of [...nodes].sort((a, b) => a.id.localeCompare(b.id))) {
    const i = seen.get(n.group) ?? 0;
    seen.set(n.group, i + 1);
    const c = centre.get(n.group)!;
    const a = i * 2.39996;
    const rad = 14 * Math.sqrt(i + 0.5);
    n.x = c.x + rad * Math.cos(a);
    n.y = c.y + rad * Math.sin(a);
  }

  type SimLink = SimulationLinkDatum<VNode> & VLink;
  const simLinks: SimLink[] = links.map((l) => ({ ...l }));
  // Small graphs get room for every label; big ones pack tighter.
  const room = nodes.length < 60 ? 34 : 14;
  const sim = forceSimulation<VNode>(nodes)
    .force("link", forceLink<VNode, SimLink>(simLinks).id((d) => d.id).distance(60 + room).strength(0.05))
    .force("charge", forceManyBody<VNode>().strength(-40 - 2 * room).distanceMax(160 + 4 * room))
    .force("collide", forceCollide<VNode>().radius((d) => d.r + room))
    .force("x", forceX<VNode>((d) => centre.get(d.group)!.x).strength(0.18))
    .force("y", forceY<VNode>((d) => centre.get(d.group)!.y).strength(0.18))
    .stop();
  for (let i = 0; i < 260; i++) sim.tick();

  const groups = [...new Set(nodes.map((n) => n.group))].sort();
  const hulls = groups
    .map((g) => hullFor(g, nodes.filter((n) => n.group === g)))
    .filter((h): h is Hull => h !== null);
  const xs = hulls.flatMap((h) => [h.bounds[0], h.bounds[2]]);
  const ys = hulls.flatMap((h) => [h.bounds[1] - 16, h.bounds[3]]);
  return {
    nodes,
    links,
    hulls,
    groups,
    bounds: xs.length ? [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)] : [0, 0, 1, 1],
  };
}

/** Everything an untrusted entry point reaches over resolved edges, on the full graph. */
export function attackSurface(report: Report): Set<string> {
  const view = report.graph_view;
  if (!view) return new Set();
  const out = new Map<string, string[]>();
  for (const e of view.edges) if (e.resolved) out.set(e.src, [...(out.get(e.src) ?? []), e.dst]);
  const seen = new Set(view.nodes.filter((n) => n.entry_point).map((n) => n.id));
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

export const PALETTE = [
  "#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#8b5cf6",
  "#06b6d4", "#ec4899", "#84cc16", "#f97316", "#6366f1",
];

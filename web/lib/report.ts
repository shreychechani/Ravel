// Shape of the report `ravel scan --json` writes and `ravel serve` returns
// (ravel/report.py). Keep in step with REPORT_VERSION there.

export type Reach = "reachable" | "unknown" | "unreachable";
export type Verdict = "real" | "false_positive" | "needs_review" | "unreachable";

export interface NodeInfo {
  id: string;
  kind: string;
  name: string;
  file: string;
  line: number;
  end_line: number;
}

export interface Hop {
  src: string;
  dst: string;
  resolved: boolean;
  kind: string;
}

export interface Snippet {
  file: string;
  start_line: number;
  lines: string[];
  highlight: [number, number];
}

export interface Finding {
  id: string;
  source: string;
  node_id: string;
  rule_id: string;
  raw_severity: string;
  cwe: string | null;
  static_evidence: { reachable: Reach; path: string[]; blast_radius: number } | null;
  verdict: Verdict | null;
  confidence: number | null;
  reasoning: string | null;
  file: string;
  line: number;
  end_line: number;
  severity: string;
  message: string;
  package: string | null;
  package_version: string | null;
  fixed_in: string | null;
  aliases: string[];
  anchors: string[];
  via: string[];
  node_name: string | null;
  path_hops: Hop[];
  callers: string[];
  code: Snippet | null;
}

export interface GraphNode extends NodeInfo {
  entry_point: boolean;
  findings: string[];
  worst_reach: Reach | null;
}

export interface GraphEdge {
  src: string;
  dst: string;
  kind: "calls" | "imports" | "defines" | "inherits" | string;
  resolved: boolean;
}

export interface Report {
  report_version: number;
  repo: string;
  graph: {
    nodes: number;
    edges: number;
    coverage: { ratio: number; total: number; internal: number; external: number; unresolved: number };
    environment: string;
  };
  entry_points: { node_id: string; kind: string; trust: string }[];
  nodes: Record<string, NodeInfo>;
  scanners: { source: string; status: string; version: string | null; detail: string | null }[];
  not_integrated: string[];
  mapping: { total: number; ratio: number; to_def: number; to_file: number; to_package: number };
  cross_scanner_duplicates: number;
  findings: Finding[];
  graph_view?: { nodes: GraphNode[]; edges: GraphEdge[] };
  triage_stats?: {
    survivors_evaluated: number;
    llm_calls: number;
    cached_hits: number;
    real_count: number;
    false_positive_count: number;
    needs_review_count: number;
    budget_exhausted: number;
    tokens_used?: number;
    token_limit?: number;
  };
}

export const reachOf = (f: Finding): Reach => f.static_evidence?.reachable ?? "unknown";

export const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

export const REACH_STYLE: Record<Reach, string> = {
  reachable: "bg-reach-soft text-reach border-reach",
  unknown: "bg-unknown-soft text-unknown border-unknown",
  unreachable: "bg-unreach-soft text-unreach border-unreach",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  real: "Real",
  false_positive: "False positive",
  needs_review: "Needs review",
  unreachable: "Skipped (unreachable)",
};

export const VERDICT_STYLE: Record<Verdict, string> = {
  real: "bg-real-soft text-real border-real",
  false_positive: "bg-safe-soft text-safe border-safe",
  needs_review: "bg-unknown-soft text-unknown border-unknown",
  unreachable: "bg-unreach-soft text-unreach border-unreach",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export async function fetchReport(): Promise<Report> {
  const res = await fetch("/api/report");
  if (!res.ok) throw new Error(`report request failed (${res.status})`);
  return res.json();
}

export async function rescan(triage: boolean): Promise<Report> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ triage }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `scan failed (${res.status})`);
  }
  return res.json();
}

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

export type Urgency = "urgent" | "check" | "routine" | "migrate" | "ok";

export interface Evidence {
  reachable: Reach;
  path: string[];
  blast_radius: number;
}

export interface DeprecatedApi {
  symbol: string;
  kind: "decorator" | "warning" | "module";
  category: string | null;
  message: string | null;
  conditional: boolean; // only some calls / arguments trigger it
  reach: Evidence;
  calls: ({ node_id: string; line: number } & Evidence)[];
}

export interface PackageEntry {
  name: string;
  modules: string[];
  version: string | null; // installed in the scanned environment
  declared: string | null; // pinned in a manifest, as OSV read it
  stdlib: boolean;
  urgency: Urgency;
  references: number;
  files: number;
  users: string[];
  usage: Evidence;
  via: string[];
  advisories: {
    finding_id: string;
    id: string;
    aliases: string[];
    severity: string;
    summary: string;
    fixed_in: string | null;
    reachable: Reach;
  }[];
  upgrade_to: string | null;
  unfixed: number;
  pin_is_stale: boolean;
  deprecated: DeprecatedApi[];
}

export interface Dependencies {
  summary: {
    packages: number;
    urgent: number;
    check: number;
    routine: number;
    migrate: number;
    ok: number;
    deprecated_apis: number;
    deprecated_calls: number;
    deprecated_calls_by_reach: Record<Reach, number>;
  };
  osv: { status: string; detail: string | null };
  deprecation_check: {
    external_calls_checked: number;
    without_source: number;
    unresolved_calls: number;
    stdlib_python: string;
  };
  upgrade_note: string;
  packages: PackageEntry[];
}

export interface Report {
  report_version: number;
  repo: string;
  target?: string | null; // what the user opened: a git URL or a folder
  ref?: string | null;
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
  dependencies?: Dependencies; // report_version >= 3
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

export const URGENCY_STYLE: Record<Urgency, string> = {
  urgent: "bg-real-soft text-real border-real",
  check: "bg-unknown-soft text-unknown border-unknown",
  routine: "bg-unreach-soft text-unreach border-unreach",
  migrate: "bg-graph-soft text-graph border-graph",
  ok: "bg-safe-soft text-safe border-safe",
};

export const URGENCY_LABEL: Record<Urgency, string> = {
  urgent: "Upgrade now",
  check: "Check",
  routine: "Routine upgrade",
  migrate: "Migration work",
  ok: "Nothing to do",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/** The current report, or null when the server has no repo open yet. */
export async function fetchReport(): Promise<Report | null> {
  const res = await fetch("/api/report");
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`report request failed (${res.status})`);
  return res.json();
}

async function post(url: string, body: unknown): Promise<Report> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? `request failed (${res.status})`);
  }
  return res.json();
}

/** Clone (for a URL) or read (for a folder), index and scan another repository. */
export function openRepo(target: string, ref?: string, venv?: string): Promise<Report> {
  return post("/api/open", { target, ref: ref || null, venv: venv || null });
}

export function rescan(triage: boolean): Promise<Report> {
  return post("/api/scan", { triage });
}

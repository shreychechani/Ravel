import { REACH_STYLE, VERDICT_LABEL, VERDICT_STYLE, type Reach, type Verdict } from "@/lib/report";

const base = "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap";

export function ReachBadge({ reach }: { reach: Reach }) {
  return <span className={`${base} ${REACH_STYLE[reach]}`}>{reach}</span>;
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <span className={`${base} border-line text-muted`}>not reviewed</span>;
  return <span className={`${base} ${VERDICT_STYLE[verdict]}`}>{VERDICT_LABEL[verdict]}</span>;
}

const SEV: Record<string, string> = {
  critical: "bg-real text-white border-real",
  high: "bg-real-soft text-real border-real",
  medium: "bg-reach-soft text-reach border-reach",
  low: "bg-unreach-soft text-unreach border-unreach",
  info: "bg-unreach-soft text-unreach border-unreach",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`${base} ${SEV[severity] ?? SEV.info}`}>{severity}</span>;
}

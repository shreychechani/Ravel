"""Evaluation harness — does reachability beat raw scanner output? (BUILD-PLAN §2–3)

One command scores every ``eval/ground_truth/*_vulns.toml`` repo:

    uv run python -m eval.run                     # reachability only
    uv run python -m eval.run --triage --llm-provider ollama --model llama3.2:3b

Each repo is checked out at its pinned commit (or used from ``eval/fixtures``),
given a virtualenv with its pinned requirements — call resolution, and so
coverage, needs them — and run through the real ``scan_repo`` pipeline. Then
every method below is scored against the same ground truth:

- **keep-all** — raw scanner output, the baseline to beat;
- **severity** — keep critical/high/medium only, the obvious cheap filter;
- **random-N** — keep as many findings as Ravel, at random (seeded, averaged);
- **ravel** — keep reachable + unknown (unknown is never dropped, §6);
- **ravel+triage** — also drop what the LLM calls a false positive (``--triage``).

A finding hits a truth case when it is in the case's file and function with
one of the CWEs the case accepts. Precision is reported next to recall,
always (§6): *recall retained* is the share of the cases the scanners found
that a method keeps; *end-to-end recall* counts the cases no scanner found
too. Coverage is printed per repo; below 60% a repo's numbers are void (§9).

The Phase 3 checkpoint passes when Ravel's pooled precision is at least 3x
keep-all's while it retains at least 85% of the detected cases (§10).

Network: only to clone a pinned repo or install its requirements the first
time (``$RAVEL_EVAL_CACHE``, default ``~/.cache/ravel/eval``). Scanned code is
never executed.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.hashing import content_hash
from ravel.core.logging import configure_logging, get_logger
from ravel.scanners.normalize import LocatedFinding
from ravel.scanners.run import ScanReport, scan_repo
from ravel.triage.cache import TriageCache
from ravel.triage.provider import TokenBudget, create_provider
from rich.console import Console
from rich.table import Table

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
TRUTH_DIR = HERE / "ground_truth"
PRECISION_GATE = 3.0
RECALL_GATE = 0.85
COVERAGE_FLOOR = 0.60
RANDOM_DRAWS = 1000
KEEP_SEVERITIES = frozenset({"critical", "high", "medium"})

log = get_logger("eval.run")


@dataclass(frozen=True)
class TruthCase:
    id: str
    file: str
    function: str  # "" = anywhere in the file (templates, module level)
    cwes: frozenset[str]
    cls: str


@dataclass(frozen=True)
class RepoSpec:
    name: str
    truth: tuple[TruthCase, ...]
    requirements: tuple[str, ...]
    url: str | None = None
    sha: str | None = None
    subdir: str = ""
    local: str | None = None


def load_spec(path: Path) -> RepoSpec:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    repo = data["repo"]
    truth = tuple(
        TruthCase(
            id=t["id"],
            file=t["file"],
            function=t.get("function", ""),
            cwes=frozenset(t["cwes"]),
            cls=t["class"],
        )
        for t in data.get("truth", [])
    )
    if not repo.get("local") and not (repo.get("url") and repo.get("sha")):
        raise ValueError(f"{path}: [repo] needs local, or url + sha")
    return RepoSpec(
        name=repo["name"],
        truth=truth,
        requirements=tuple(repo.get("requirements", [])),
        url=repo.get("url"),
        sha=repo.get("sha"),
        subdir=repo.get("subdir", ""),
        local=repo.get("local"),
    )


def default_cache() -> Path:
    return Path(os.environ.get("RAVEL_EVAL_CACHE", "~/.cache/ravel/eval")).expanduser()


def checkout(spec: RepoSpec, cache: Path) -> Path:
    """The repo's source tree at its pinned commit (cloned once, then reused)."""
    if spec.local:
        return (REPO_ROOT / spec.local).resolve()
    assert spec.url and spec.sha
    dest = cache / "repos" / f"{spec.name}-{spec.sha[:12]}"
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        log.info("cloning %s at %s", spec.url, spec.sha[:12])
        subprocess.run(["git", "clone", "--quiet", spec.url, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", "--quiet", spec.sha], check=True)
    head = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != spec.sha:
        raise RuntimeError(f"{dest} is at {head}, expected the pinned {spec.sha}")
    return dest / spec.subdir if spec.subdir else dest


def ensure_venv(spec: RepoSpec, cache: Path) -> Path | None:
    """A virtualenv holding the repo's pinned requirements, keyed by their hash."""
    if not spec.requirements:
        return None
    uv = shutil.which("uv")
    if uv is None:
        log.warning("uv not found: %s scanned without its dependencies", spec.name)
        return None
    key = content_hash("\n".join(sorted(spec.requirements)))[:16]
    venv = cache / "venvs" / f"{spec.name}-{key}"
    if not (venv / "pyvenv.cfg").is_file():
        log.info("building a virtualenv for %s", spec.name)
        subprocess.run([uv, "venv", "--quiet", "--python", "3.12", str(venv)], check=True)
        subprocess.run(
            [
                uv,
                "pip",
                "install",
                "--quiet",
                "--python",
                str(venv / "bin" / "python"),
                *spec.requirements,
            ],
            check=True,
        )
    return venv


def hits(lf: LocatedFinding, case: TruthCase) -> bool:
    if lf.raw.package is not None or lf.raw.rel_path != case.file:
        return False
    if case.function and (lf.node is None or lf.node.qualified_name != case.function):
        return False
    return lf.finding.cwe in case.cwes


@dataclass
class Score:
    """One method on one repo (or pooled): what it kept and what that covered."""

    kept: float = 0.0
    true_pos: float = 0.0
    cases_hit: float = 0.0  # truth cases with at least one kept hit
    detected: int = 0  # truth cases any scanner found
    truth: int = 0

    def add(self, other: Score) -> None:
        self.kept += other.kept
        self.true_pos += other.true_pos
        self.cases_hit += other.cases_hit
        self.detected += other.detected
        self.truth += other.truth

    @property
    def precision(self) -> float | None:
        return self.true_pos / self.kept if self.kept else None

    @property
    def recall_retained(self) -> float | None:
        return self.cases_hit / self.detected if self.detected else None

    @property
    def recall_end_to_end(self) -> float | None:
        return self.cases_hit / self.truth if self.truth else None


def _score(kept: list[LocatedFinding], truth: tuple[TruthCase, ...], detected: int) -> Score:
    tp = sum(1 for lf in kept if any(hits(lf, c) for c in truth))
    hit = sum(1 for c in truth if any(hits(lf, c) for lf in kept))
    return Score(kept=len(kept), true_pos=tp, cases_hit=hit, detected=detected, truth=len(truth))


def _reach(lf: LocatedFinding) -> str:
    ev = lf.finding.static_evidence
    return ev.reachable.value if ev else "unknown"


Method = Callable[[list[LocatedFinding]], list[LocatedFinding]]

METHODS: dict[str, Method] = {
    "keep-all": lambda fs: fs,
    "severity": lambda fs: [lf for lf in fs if lf.raw.severity.value in KEEP_SEVERITIES],
    "ravel": lambda fs: [lf for lf in fs if _reach(lf) != "unreachable"],
    "ravel+triage": lambda fs: [
        lf for lf in fs if _reach(lf) != "unreachable" and lf.finding.verdict != "false_positive"
    ],
}


@dataclass
class RepoResult:
    name: str
    coverage: float
    findings: int
    scores: dict[str, Score] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.coverage >= COVERAGE_FLOOR


def score_report(
    name: str, report: ScanReport, truth: tuple[TruthCase, ...], *, triage: bool, seed: int
) -> RepoResult:
    findings = report.findings
    detected = sum(1 for c in truth if any(hits(lf, c) for lf in findings))
    result = RepoResult(name, report.graph.coverage.ratio, len(findings))
    for method, keep in METHODS.items():
        if method == "ravel+triage" and not triage:
            continue
        result.scores[method] = _score(keep(findings), truth, detected)

    # random-N: as many findings as Ravel keeps, drawn uniformly, averaged.
    n = int(result.scores["ravel"].kept)
    rng = random.Random(seed)
    avg = Score(detected=detected, truth=len(truth))
    for _ in range(RANDOM_DRAWS):
        s = _score(rng.sample(findings, n), truth, detected)
        avg.kept += s.kept / RANDOM_DRAWS
        avg.true_pos += s.true_pos / RANDOM_DRAWS
        avg.cases_hit += s.cases_hit / RANDOM_DRAWS
    result.scores["random-N"] = avg
    return result


def pooled(results: list[RepoResult]) -> dict[str, Score]:
    out: dict[str, Score] = {}
    for r in results:
        if not r.valid:
            continue
        for method, s in r.scores.items():
            out.setdefault(method, Score()).add(s)
    return out


def checkpoint(pool: dict[str, Score]) -> tuple[bool, float | None]:
    base, ours = pool["keep-all"].precision, pool["ravel"].precision
    factor = ours / base if base and ours is not None else None
    retained = pool["ravel"].recall_retained
    passed = factor is not None and factor >= PRECISION_GATE and (retained or 0) >= RECALL_GATE
    return passed, factor


def triage_checkpoint(pool: dict[str, Score]) -> bool | None:
    """Does triage add anything over reachability alone? (§10: if not, ship it disabled.)

    It must raise precision without losing any recall retained.
    """
    if "ravel+triage" not in pool:
        return None
    base, tri = pool["ravel"], pool["ravel+triage"]
    gained = (tri.precision or 0) > (base.precision or 0)
    kept_recall = (tri.recall_retained or 0) >= (base.recall_retained or 0)
    return gained and kept_recall


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.1%}"


def render(results: list[RepoResult], pool: dict[str, Score], console: Console) -> None:
    order = ["keep-all", "severity", "random-N", "ravel", "ravel+triage"]
    for r in results:
        title = f"{r.name} — {r.findings} findings, coverage {r.coverage:.1%}"
        if not r.valid:
            title += " [red](below 60%: numbers void)[/red]"
        console.print(_table(title, r.scores, order))
    console.print(_table("Pooled over valid repos", pool, order))
    passed, factor = checkpoint(pool)
    verdict = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
    retained = _pct(pool["ravel"].recall_retained)
    console.print(
        f"Phase 3 checkpoint: precision x{factor:.2f} vs keep-all (gate ≥{PRECISION_GATE:.0f}x), "
        f"recall retained {retained} (gate ≥{RECALL_GATE:.0%}) → {verdict}"
        if factor is not None
        else f"Phase 3 checkpoint: no precision to compare → {verdict}"
    )
    tri = triage_checkpoint(pool)
    if tri is not None:
        t = pool["ravel+triage"]
        console.print(
            f"Phase 4 triage checkpoint: precision {_pct(pool['ravel'].precision)} → "
            f"{_pct(t.precision)}, recall retained {retained} → {_pct(t.recall_retained)} → "
            + ("[green]PASS[/green]" if tri else "[red]FAIL: keep triage disabled[/red]")
        )


def _table(title: str, scores: dict[str, Score], order: list[str]) -> Table:
    t = Table(title=title)
    for col in ("method", "kept", "true pos.", "precision", "recall retained", "end-to-end recall"):
        t.add_column(col, justify="left" if col == "method" else "right")
    for m in order:
        if m not in scores:
            continue
        s = scores[m]
        t.add_row(
            m,
            f"{s.kept:.1f}" if m == "random-N" else str(int(s.kept)),
            f"{s.true_pos:.1f}" if m == "random-N" else str(int(s.true_pos)),
            _pct(s.precision),
            _pct(s.recall_retained),
            _pct(s.recall_end_to_end),
        )
    return t


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--truth",
        type=Path,
        nargs="*",
        default=None,
        help="ground-truth files (default: eval/ground_truth/*_vulns.toml)",
    )
    parser.add_argument("--cache", type=Path, default=None)
    parser.add_argument("--triage", action="store_true", help="also score LLM triage")
    parser.add_argument("--llm-provider", default="mock")
    parser.add_argument("--model", default=None)
    parser.add_argument("--token-budget", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=Path, default=None, help="write the scores here")
    args = parser.parse_args(argv)

    configure_logging()
    cache = args.cache or default_cache()
    specs = [load_spec(p) for p in (args.truth or sorted(TRUTH_DIR.glob("*_vulns.toml")))]
    results: list[RepoResult] = []
    for spec in specs:
        root = checkout(spec, cache)
        venv = ensure_venv(spec, cache)
        provider = create_provider(args.llm_provider, model=args.model) if args.triage else None
        report = scan_repo(
            root,
            venv=venv,
            triage_provider=provider,
            token_budget=TokenBudget(limit=args.token_budget) if args.triage else None,
            triage_cache=TriageCache() if args.triage else None,
        )
        results.append(
            score_report(spec.name, report, spec.truth, triage=args.triage, seed=args.seed)
        )

    pool = pooled(results)
    render(results, pool, Console())
    passed, factor = checkpoint(pool)
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "repos": {
                        r.name: {
                            "coverage": r.coverage,
                            "valid": r.valid,
                            **{m: s.__dict__ for m, s in r.scores.items()},
                        }
                        for r in results
                    },
                    "pooled": {m: s.__dict__ for m, s in pool.items()},
                    "checkpoint": {"passed": passed, "precision_factor": factor},
                    "triage_checkpoint": triage_checkpoint(pool),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

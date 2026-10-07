"""Bottom-up function and module summaries, cached by content hash (PRODUCT.md §3, §8).

A function is summarised after everything it calls, so its summary can lean
on theirs: the internal call graph is condensed into strongly connected
components (mutual recursion becomes one unit) and walked callee-first. A
module is summarised last, from its functions' summaries — that module summary
is what triage context and the Code Wiki read.

Cache key = hash(the node's name and source hash, its callees' summary keys,
the model) — never its path (§6). Editing a function changes its key, its
callers' and its module's, and
nothing else: unchanged code is never re-summarised (§8). (Cascading only on a
*material* summary change, §8.5, is the next refinement.)

Truthfulness guard (research/05): every identifier the summary puts in
backticks must name a function, class or module in the graph or a third-party
symbol the code calls. If not, the model is asked once more; a second miss is
kept but ``flagged``. Every call is budget-capped like triage: when the kill
switch trips, the rest are left unsummarised and counted.
"""

from __future__ import annotations

import builtins
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import networkx as nx

from ravel.core.hashing import content_hash
from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult
from ravel.models import EdgeKind, Node, NodeKind
from ravel.triage.provider import LLMProvider, TokenBudget, TokenBudgetExceededError

log = get_logger("ravel.summarize")

_MAX_CODE_LINES = 80
_IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)\(?\)?`")

SYSTEM_PROMPT = (
    "You write one-paragraph summaries of Python code for other developers. "
    "Say what the code does and what it returns or changes, in at most two "
    "sentences of plain text. Put function, class and module names in backticks. "
    "Only name things that appear in the code or in the summaries you are given."
)


@dataclass(frozen=True)
class Summary:
    node_id: str
    text: str
    key: str  # content-hash cache key
    flagged: bool = False  # failed the truthfulness guard twice


@dataclass
class SummaryStats:
    total: int = 0
    generated: int = 0
    cached: int = 0
    flagged: int = 0
    skipped_budget: int = 0
    llm_calls: int = 0


def default_cache_path() -> Path:
    override = os.environ.get("RAVEL_SUMMARY_CACHE")
    return Path(override or "~/.cache/ravel/summaries.json").expanduser()


class SummaryCache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_cache_path()
        self._entries: dict[str, dict[str, object]] = {}
        if self.path.is_file():
            try:
                self._entries = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("could not read summary cache %s: %s", self.path, exc)

    def get(self, key: str) -> tuple[str, bool] | None:
        hit = self._entries.get(key)
        return (str(hit["text"]), bool(hit["flagged"])) if hit else None

    def set(self, key: str, text: str, flagged: bool) -> None:
        self._entries[key] = {"text": text, "flagged": flagged}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._entries, indent=1), encoding="utf-8")


@dataclass
class SummaryRun:
    summaries: dict[str, Summary] = field(default_factory=dict)
    stats: SummaryStats = field(default_factory=SummaryStats)


def callee_first_order(graph: GraphResult) -> list[str]:
    """Function/class node ids, every callee before its callers (SCCs as one unit)."""
    defs = {n.id for n in graph.nodes if n.kind in (NodeKind.FUNCTION, NodeKind.CLASS)}
    calls = nx.DiGraph()
    calls.add_nodes_from(sorted(defs))
    for u, v, key in graph.graph.edges(keys=True):
        if key == EdgeKind.CALLS.value and u in defs and v in defs and u != v:
            calls.add_edge(u, v)
    condensed = nx.condensation(calls)
    order: list[str] = []
    for component in reversed(list(nx.lexicographical_topological_sort(condensed))):
        order.extend(sorted(condensed.nodes[component]["members"]))
    return order


def _source(root: Path, node: Node) -> str:
    try:
        lines = (root / node.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    body = lines[node.start_line - 1 : node.end_line]
    if len(body) > _MAX_CODE_LINES:
        body = [*body[:_MAX_CODE_LINES], f"# ... {len(body) - _MAX_CODE_LINES} more lines"]
    return "\n".join(body)


def known_names(graph: GraphResult) -> set[str]:
    """Every name a truthful summary may mention: the graph's, the third-party
    symbols it calls, and Python's builtins (``str()``, ``open()``)."""
    names: set[str] = set(dir(builtins))
    for n in graph.nodes:
        names.add(n.qualified_name)
        names.add(n.qualified_name.rsplit(".", 1)[-1])
        names.add(Path(n.file_path).stem)
    for ref in graph.external_refs:
        names.add(ref.package)
        if ref.symbol:
            names.add(ref.symbol)
            names.add(f"{ref.package}.{ref.symbol}")
    return names


def unknown_identifiers(text: str, names: set[str]) -> list[str]:
    out = []
    for ident in _IDENT.findall(text):
        if ident not in names and ident.rsplit(".", 1)[-1] not in names:
            out.append(ident)
    return out


def _clean(raw: str) -> str:
    text = " ".join(raw.strip().split())
    return text[:600]


def summarize_graph(
    graph: GraphResult,
    root: Path | str,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: SummaryCache | None = None,
    limit: int | None = None,
) -> SummaryRun:
    """Summarise functions/classes callee-first, then each module from its parts."""
    root = Path(root).resolve()
    nodes = {n.id: n for n in graph.nodes}
    names = known_names(graph)
    run = SummaryRun()
    order = callee_first_order(graph)
    if limit is not None:
        order = order[:limit]
    files = [n for n in graph.nodes if n.kind is NodeKind.FILE]
    run.stats.total = len(order) + len(files)

    def ask(prompt: str) -> str:
        budget.check()
        resp = provider.generate(prompt, SYSTEM_PROMPT)
        budget.record(resp.prompt_tokens, resp.completion_tokens)
        run.stats.llm_calls += 1
        return _clean(resp.content)

    def produce(node_id: str, prompt: str, key: str) -> None:
        if cache is not None and (hit := cache.get(key)) is not None:
            run.summaries[node_id] = Summary(node_id, hit[0], key, hit[1])
            run.stats.cached += 1
            return
        if budget.tripped:
            run.stats.skipped_budget += 1
            return
        try:
            text = ask(prompt)
            bad = unknown_identifiers(text, names)
            if bad:
                text = ask(
                    f"{prompt}\n\nDo not mention {', '.join(bad)}: they are not in the code."
                )
                bad = unknown_identifiers(text, names)
        except TokenBudgetExceededError:
            run.stats.skipped_budget += 1
            return
        flagged = bool(bad)
        run.summaries[node_id] = Summary(node_id, text, key, flagged)
        run.stats.generated += 1
        run.stats.flagged += flagged
        if cache is not None:
            cache.set(key, text, flagged)

    try:
        for node_id in order:
            node = nodes[node_id]
            callees = sorted(
                v
                for _, v, k in graph.graph.out_edges(node_id, keys=True)
                if k == EdgeKind.CALLS.value and v in run.summaries and v != node_id
            )
            # The name is in the key: two identical bodies with different names get
            # different summaries. Paths never are (§6).
            key = content_hash(
                "\x1f".join(
                    [
                        node.qualified_name,
                        node.source_hash,
                        provider.model_name,
                        *(run.summaries[c].key for c in callees),
                    ]
                )
            )
            context = "\n".join(
                f"- `{nodes[c].qualified_name}`: {run.summaries[c].text}" for c in callees
            )
            prompt = (
                f"Summarise `{node.qualified_name}` ({node.file_path}).\n\n"
                f"CODE:\n{_source(root, node)}\n\n"
                f"WHAT IT CALLS:\n{context or '(nothing in this repo)'}"
            )
            produce(node_id, prompt, key)

        for f in files:
            parts = sorted(
                v
                for _, v, k in graph.graph.out_edges(f.id, keys=True)
                if k == EdgeKind.DEFINES.value and v in run.summaries
            )
            key = content_hash(
                "\x1f".join(
                    [
                        "module",
                        f.qualified_name,
                        f.source_hash,
                        provider.model_name,
                        *(run.summaries[p].key for p in parts),
                    ]
                )
            )
            listing = "\n".join(
                f"- `{nodes[p].qualified_name}`: {run.summaries[p].text}" for p in parts
            )
            prompt = (
                f"Summarise the module `{Path(f.file_path).stem}` ({f.file_path}).\n\n"
                f"DOCSTRING:\n{f.docstring or '(none)'}\n\n"
                f"WHAT IT DEFINES:\n{listing or '(only module-level code)'}"
            )
            produce(f.id, prompt, key)
    finally:
        if cache is not None:
            cache.save()

    log.info(
        "summaries: %d generated, %d cached, %d flagged, %d skipped (budget), %d calls",
        run.stats.generated,
        run.stats.cached,
        run.stats.flagged,
        run.stats.skipped_budget,
        run.stats.llm_calls,
    )
    return run


def summaries_payload(run: SummaryRun, graph: GraphResult) -> dict[str, object]:
    nodes = {n.id: n for n in graph.nodes}
    return {
        "stats": asdict(run.stats),
        "summaries": [
            {
                "node_id": s.node_id,
                "name": nodes[s.node_id].qualified_name,
                "kind": nodes[s.node_id].kind.value,
                "file": nodes[s.node_id].file_path,
                "line": nodes[s.node_id].start_line,
                "summary": s.text,
                "flagged": s.flagged,
            }
            for s in run.summaries.values()
        ],
    }

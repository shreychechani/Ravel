"""LLM Triage Adjudication Orchestrator (PRODUCT.md §3, §6, §8; BUILD-PLAN Phase 4).

Adjudicates reachability-filtered findings using graph context, budget enforcement,
and content-hash caching.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult
from ravel.models import Finding, Reachability
from ravel.scanners.normalize import LocatedFinding
from ravel.triage.cache import TriageCache
from ravel.triage.context import assemble_finding_context
from ravel.triage.prompts import build_triage_prompt
from ravel.triage.provider import LLMProvider, TokenBudget, TokenBudgetExceededError

log = get_logger("ravel.triage.adjudicate")


VALID_VERDICTS = {"real", "false_positive", "needs_review"}


@dataclass
class TriageStats:
    total: int = 0
    survivors_evaluated: int = 0
    cached_hits: int = 0
    llm_calls: int = 0
    unreachable_skipped: int = 0
    budget_exhausted: int = 0
    real_count: int = 0
    false_positive_count: int = 0
    needs_review_count: int = 0


def _parse_verdict_json(raw: str) -> tuple[str, float, str]:
    """Parse structured JSON from model output, handling potential markdown fences."""
    text = raw.strip()
    # Strip markdown code blocks if model included them
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        text = match.group(1) if match else text.replace("```json", "").replace("```", "").strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fallback regex extraction if full JSON parse fails
        v_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', text)
        verdict = v_match.group(1).lower() if v_match else "needs_review"
        c_match = re.search(r'"confidence"\s*:\s*([0-9.]+)', text)
        confidence = float(c_match.group(1)) if c_match else 0.5
        r_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', text)
        reasoning = r_match.group(1) if r_match else "Output could not be fully parsed as JSON."
        return (verdict if verdict in VALID_VERDICTS else "needs_review", confidence, reasoning)

    verdict = str(data.get("verdict", "needs_review")).lower()
    if verdict not in VALID_VERDICTS:
        verdict = "needs_review"
    try:
        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        confidence = 0.5
    reasoning = str(data.get("reasoning", "No explanation provided."))

    return verdict, confidence, reasoning


def adjudicate_findings[F: (Finding, LocatedFinding)](
    findings: list[F],
    graph_result: GraphResult,
    root: Path | str,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: TriageCache | None = None,
) -> tuple[list[F], TriageStats]:
    """Run LLM adjudication on reachability survivors.

    Mutates and returns findings with ``verdict``, ``confidence``, and ``reasoning``.
    """
    stats = TriageStats(total=len(findings))

    try:
        for item in findings:
            finding = item.finding if isinstance(item, LocatedFinding) else item
            evidence = finding.static_evidence

            # Strictly skip unreachable findings — LLM never sees them (PRODUCT.md §3, §6)
            if evidence is not None and evidence.reachable is Reachability.UNREACHABLE:
                finding.verdict = "unreachable"
                finding.confidence = 1.0
                finding.reasoning = (
                    "Deterministic graph traversal confirmed code is unreachable from "
                    "any untrusted entry point."
                )
                stats.unreachable_skipped += 1
                continue

            stats.survivors_evaluated += 1
            context = assemble_finding_context(item, graph_result, root)
            prompt, system_prompt, template_id = build_triage_prompt(context)
            cache_key = TriageCache.compute_key(
                context.context_hash, template_id, provider.model_name
            )

            # 1. Check cache
            if cache is not None:
                hit = cache.get(cache_key)
                if hit is not None:
                    finding.verdict = hit.verdict
                    finding.confidence = hit.confidence
                    finding.reasoning = f"[cached] {hit.reasoning}"
                    stats.cached_hits += 1
                    if hit.verdict == "real":
                        stats.real_count += 1
                    elif hit.verdict == "false_positive":
                        stats.false_positive_count += 1
                    else:
                        stats.needs_review_count += 1
                    continue

            # 2. Check token budget kill switch
            if budget.tripped or budget.total >= budget.limit:
                finding.verdict = "needs_review"
                finding.confidence = 0.5
                finding.reasoning = (
                    f"Token budget exhausted ({budget.total}/{budget.limit} tokens). "
                    "Kill switch engaged."
                )
                stats.budget_exhausted += 1
                stats.needs_review_count += 1
                continue

            # 3. Invoke LLM
            try:
                budget.check()
                response = provider.generate(prompt, system_prompt)
                budget.record(response.prompt_tokens, response.completion_tokens)
                stats.llm_calls += 1
                verdict, confidence, reasoning = _parse_verdict_json(response.content)
            except TokenBudgetExceededError:
                finding.verdict = "needs_review"
                finding.confidence = 0.5
                finding.reasoning = "Token budget exceeded during scan execution."
                stats.budget_exhausted += 1
                stats.needs_review_count += 1
                continue
            except Exception as exc:
                log.warning("LLM triage call failed for finding %s: %s", finding.id, exc)
                finding.verdict = "needs_review"
                finding.confidence = 0.5
                finding.reasoning = f"Triage call error: {exc}"
                stats.needs_review_count += 1
                continue

            finding.verdict = verdict
            finding.confidence = confidence
            finding.reasoning = reasoning

            if verdict == "real":
                stats.real_count += 1
            elif verdict == "false_positive":
                stats.false_positive_count += 1
            else:
                stats.needs_review_count += 1

            # 4. Save to cache
            if cache is not None:
                cache.set(
                    cache_key,
                    verdict=verdict,
                    confidence=confidence,
                    reasoning=reasoning,
                    template_id=template_id,
                    model_name=provider.model_name,
                )
    finally:
        if cache is not None:
            cache.save()

    log.info(
        "triage complete: %d survivors -> %d real, %d false positive, %d needs review "
        "(calls=%d, cached=%d, budget_used=%d/%d)",
        stats.survivors_evaluated,
        stats.real_count,
        stats.false_positive_count,
        stats.needs_review_count,
        stats.llm_calls,
        stats.cached_hits,
        budget.total,
        budget.limit,
    )

    return findings, stats

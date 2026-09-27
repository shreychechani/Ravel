# Ravel — Research Library

Papers, datasets, industry white papers and specs that Ravel can build on, each
mapped to the phase and file it affects. Compiled 2026-09-27.

> **This folder is reference material, not the plan.** [`PRODUCT.md`](../PRODUCT.md)
> and [`docs/BUILD-PLAN.md`](../docs/BUILD-PLAN.md) stay the source of truth. When
> a paper here suggests something that conflicts with a non-negotiable
> (PRODUCT.md §6), the non-negotiable wins, and the conflict is noted in the entry.

## How to read an entry

Every entry uses the same fields:

| Field | Meaning |
|---|---|
| **Citation** | Authors, venue, year |
| **Link** | Paper (arXiv / DOI / publisher) |
| **Artifact** | Code or dataset, plus its license when known |
| **Verified** | ✅ = details checked against the source on 2026-09-27 · ⚠ = cited from memory, link not re-fetched |
| **Key result** | The number or finding that matters |
| **Ravel takeaway** | What we would actually do with it |
| **Lands in** | Phase + file/module |
| **Caveats** | Preprint status, license, conflicts with non-negotiables |

Preprint = arXiv only, not yet peer-reviewed. Treat preprint numbers as claims.

## Files

| File | Covers | Phases |
|---|---|---|
| [`01-call-graph-and-resolution.md`](01-call-graph-and-resolution.md) | Python call-graph construction, soundness, coverage/recall measurement | 1 |
| [`02-eval-benchmarks-and-ground-truth.md`](02-eval-benchmarks-and-ground-truth.md) | Vulnerability datasets, SAST baselines, eval-methodology pitfalls | 2 |
| [`03-reachability-and-dependencies.md`](03-reachability-and-dependencies.md) | Reachability-based vuln filtering, dependency / cross-language reachability, taint models | 3, 5 |
| [`04-llm-triage.md`](04-llm-triage.md) | LLM adjudication of static-analysis alerts | 4 |
| [`05-summaries-and-wiki.md`](05-summaries-and-wiki.md) | Repo-level documentation generation | 4 (summaries), wiki |
| [`06-industry-standards-and-specs.md`](06-industry-standards-and-specs.md) | Industry white papers, prioritization standards (EPSS/KEV/SSVC/CVSS), output formats (OSV/SARIF), tool docs | all |
| [`07-action-items.md`](07-action-items.md) | Concrete tasks derived from all of the above, ordered by phase | all |

## Top 5: read these first

| # | Paper | Why it matters now |
|---|---|---|
| 1 | **PyCG** (ICSE '21) + **JARVIS** (TOSEM submission) | PyCG ships a ground-truth call-graph micro-benchmark (Apache-2.0). Scoring `resolve.py` against it gives the Phase 1 checkpoint a published, citable number. → [01](01-call-graph-and-resolution.md) |
| 2 | **Sui et al., "On the Recall of Static Call Graph Construction in Practice"** (ICSE '20) | Method for measuring call-graph *recall* against a dynamic oracle, so the coverage metric covers more than call sites Ravel saw. → [01](01-call-graph-and-resolution.md) |
| 3 | **Kang, Aw & Lo, "Detecting False Alarms from ASATs: How Far Are We?"** (ICSE '22) | Showed that published false-alarm filters were inflated by data leakage. It's the checklist that keeps Ravel's "≥3× precision" claim honest. → [02](02-eval-benchmarks-and-ground-truth.md) |
| 4 | **PyVul** (arXiv 2025) + **Vul4Py** (arXiv 2026) | Function-level labelled Python vulns, and exploit-backed vulns (proven reachable). Sources for `eval/ground_truth/`. → [02](02-eval-benchmarks-and-ground-truth.md) |
| 5 | **LLM4PFA** (arXiv 2025) | Checks a whole path one function at a time. That fits triage on top of Ravel's traced reachability paths, and each hop can be cached by content hash. → [04](04-llm-triage.md) |

## Where Ravel can beat existing tools

Things none of the tools or papers here publish all together:

1. **Measured graph quality**: call-graph precision/recall on the PyCG benchmark
   *and* recall against a dynamic oracle, printed next to call-site coverage.
2. **Honest uncertainty in reachability**: "reachable only via `unknown` edges"
   as its own visible class, not merged into reachable/unreachable (backed by
   the soundiness manifesto, [06](06-industry-standards-and-specs.md)).
3. **An eval that avoids leakage** and shows trivial baselines (keep-all,
   severity-only, random-N) next to Ravel's precision *and* recall.
4. **Triage that shows its reasoning**: per-hop reasoning along the traced path, with a
   consistency check (N runs must agree, else `needs-review`).

## Status of this library

- ✅ entries were checked against arXiv/ACM/publisher pages or repos on 2026-09-27.
- ⚠ entries are well-known papers cited from memory. Confirm the link before citing
  in the benchmark write-up.
- Nothing here has been implemented. [`07-action-items.md`](07-action-items.md)
  is a proposal list, not a commitment. Checkpoints in BUILD-PLAN still gate everything.

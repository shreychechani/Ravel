# AGENTS.md — Rules for AI coding agents on Ravel

This repo is built with AI coding agents, and different contributors may use
different tools (Claude Code, Cursor, Copilot, Windsurf, Aider, …). These rules
keep every agent's contributions consistent and aligned with the product
decisions. **They are binding regardless of which tool you use.** Human
reviewers will hold PRs to them.

If you are an agent starting a session on this repo, read this whole file first.

---

## 1. Start here (read order, every session)

1. [`PRODUCT.md`](PRODUCT.md) — the single source of truth. What Ravel is, the data model (§4), the non-negotiables (§6), scope (§7), incremental logic (§8), build order (§10).
2. [`docs/BUILD-PLAN.md`](docs/BUILD-PLAN.md) — the phased plan and current phase.
3. [`docs/reference/veloce-reuse-map.md`](docs/reference/veloce-reuse-map.md) — what to port / reference / drop from the vendored code.
4. This file.

If a decision isn't covered by these, **ask a human — do not assume.** Several
choices in PRODUCT.md look arbitrary but aren't.

---

## 2. Golden rules (non-negotiable — PRODUCT.md §6)

Do not relitigate these in code or review unless a human explicitly reopens them.

- **Python target only (v1).** Keep architecture language-agnostic, but ship Python.
- **Never write custom detection rules.** We wrap Semgrep / Bandit / gitleaks / OSV and add the layer above. Our contribution is reachability + triage, not detection.
- **Unresolved call edges are marked `unknown`, never dropped.** Treating an unresolvable call as "no call" silently hides real vulnerabilities — the worst failure mode we have.
- **Report graph coverage as a visible metric** ("84% of call sites resolved" must appear in output).
- **Recall is always reported next to precision.** Cutting 200 findings to 12 is worthless if you dropped real ones.
- **Cache keys are content hashes, never paths or line numbers.** Triage/verdict cache keys hash the *assembled context*, not just the node (§8).
- **Local-first, read-only.** Never request write access to a scanned repo. Never phone home. The LLM layer must stay swappable (local model / user's own key).
- **The LLM runs only on reachability-filtered findings — never on raw scanner output.** Reachability (deterministic, no LLM) cuts ~200 → ~20 first; the LLM then adds a verdict on the survivors, with graph context. Direct LLM-on-raw-findings is an anti-pattern (expensive, rates noise). Triage must beat reachability-alone or ship disabled (PRODUCT.md §3, §10).

---

## 3. Reference-code policy (`reference/`)

`reference/Arcflow/` and `reference/CodeClean/` are owner-approved, vendored,
**read-only** copies. They are gitignored and are **not part of the build.**

- **Never edit, run, import, or ship** anything under `reference/`.
- It is **JavaScript / browser / regex-heuristic**. You **port logic to Python**; you do not translate line-for-line.
- **Do NOT carry over their two weak parts:** (a) regex/substring security detection (`parser-security.js`) — we use real scanners; (b) name+import heuristic call resolution (`parser-callgraph.js`, `graph-builder.js`) — we resolve with Jedi/`ast`/grimp. Copying these imports the exact false-positive noise Ravel exists to kill.
- **Do port** the tedious domain knowledge: framework route patterns, dependency-file parsing, OSV plumbing, secret taxonomies, framework entry-point exclusion lists, the provenance-as-metric idea. See the reuse map for the per-file verdict.
- When you port something, **cite the source file** in the code comment and PR description, e.g. `# ported from reference/Arcflow/js/analysis/parser-routes.js`.

---

## 4. Scope guardrails (PRODUCT.md §7)

**In v1:** Python parse, call+import graph, entry-point detection (Flask/FastAPI/
Django), scanner integration, reachability filtering, LLM triage, summaries,
deprecated-API + outdated-dep reports, CLI/JSON + single-page web view, eval harness.

**NOT in v1 — if a task seems to require one of these, STOP and ask a human:**
patch/fix generation · Q&A chat · non-Python languages · hosting/auth/multi-tenancy ·
custom detection rules · runtime data ingestion (Sentry) · cross-repo graphs.

The nullable `Finding` columns (`runtime_evidence`, `graph_diff`, `patch`) are
placeholders for later — **the columns exist so we never migrate; build no logic
for them.**

---

## 5. Coding conventions

- **Type hints everywhere.** This is a static-analysis tool; untyped code is embarrassing. `mypy` must pass.
- **No `print()`** — structured logging only; user-facing output goes through the CLI formatter.
- **Every LLM call is cached and budget-capped** — a hard per-run token limit with a kill switch, not a soft warning.
- **Tests use real repo fixtures**, not synthetic Python strings. Bugs live in real-world code patterns.
- **Never commit secrets.** `.env` is gitignored; document required vars in `.env.example`.
- Match the style of surrounding code. Run `ruff` + `mypy` + `pytest` before claiming a task is done.
- Don't change the DB schema without an Alembic migration.

---

## 6. Build-order & checkpoint discipline (PRODUCT.md §10)

- Respect phase dependencies in `docs/BUILD-PLAN.md`. **Do not build downstream of a checkpoint that hasn't passed.**
- The checkpoints are gates, not formalities:
  - *Graph correctness* (≥20 hand-checked cases, ≥80% coverage) before anything reachability depends on it.
  - *Reachability value* (≥3× precision, ≥85% recall) before investing in triage.
  - *Triage value* (beats reachability alone) — if not, ship it disabled.
- **The eval harness is owned by someone NOT building triage.** Marking your own homework produces a number nobody believes. Do not have the triage author also tune the eval.

---

## 7. Multi-agent coordination

- **Ownership lanes (PRODUCT.md §12):** Graph & ingestion · Security pipeline · LLM & interface. Stay in your lane; coordinate at the seams (the `Finding` and graph schemas) rather than editing across lanes.
- **Claim before you build.** Use the task list; set an owner. Check existing tasks/branches first to avoid two agents doing the same work.
- **One logical change per branch/PR.** Keep diffs small and reviewable — humans and other agents need to follow them.
- Leave the working tree clean for the next agent: no stray debug files, no commented-out experiments.

---

## 8. Git & PR workflow

- **Never commit or push unless a human explicitly asks.** Propose the change first.
- If asked to commit and you're on `main`, **branch first** (`feat/…`, `fix/…`, `chore/…`).
- Small, focused commits with clear messages describing *why*.
- PR description states: what changed, which phase it advances, which checkpoint it targets, and any reference file ported from.
- No interactive git (`rebase -i`, `add -i`) in automated flows.

---

## 9. Honesty & integrity

- **Report outcomes faithfully.** If tests fail, say so with the output. If a step was skipped, say that. Don't claim "done and verified" unless it is.
- **Never fabricate or hand-tune eval numbers.** The whole product is a measured claim (≥3× precision, ≥85% recall); a number you can't reproduce from `eval/run.py` is worthless.
- When something contradicts the docs or looks wrong, **surface it** instead of coding around it silently.

---

## 10. When unsure

Ask. A short question to a human beats a confident wrong assumption that
another agent then builds on. PRODUCT.md §6: *"When a design decision isn't
covered here, ask rather than assume."*

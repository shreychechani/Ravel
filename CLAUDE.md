# CLAUDE.md

Rules for all AI coding agents on Ravel live in **[`AGENTS.md`](AGENTS.md)** —
read it first. It is tool-agnostic and binding regardless of which agent you use.

Quick pointers:
- **Product source of truth:** [`PRODUCT.md`](PRODUCT.md)
- **Phased build plan:** [`docs/BUILD-PLAN.md`](docs/BUILD-PLAN.md)
- **Reference-code reuse map:** [`docs/reference/veloce-reuse-map.md`](docs/reference/veloce-reuse-map.md)
- **Vendored reference code (read-only, gitignored):** `reference/Arcflow/`, `reference/CodeClean/` — port logic to Python, never import or run it.

Non-negotiables you must not violate (full list in AGENTS.md §2 / PRODUCT.md §6):
Python-only v1 · never write custom detection rules · unresolved edges = `unknown`
never dropped · coverage reported as a metric · recall reported next to precision ·
cache keys = content hashes · local-first, read-only · never commit/push unless asked.

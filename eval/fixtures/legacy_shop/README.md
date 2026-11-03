# legacy_shop — planted dependency-report fixture

A deliberately tiny Flask app written for Ravel's dependency report (Phase 5,
"what would this migration cost?"). Like `vuln_shop`, its contents are planted
and documented here, so they are the ground truth.

**Deprecated APIs** — each deprecated by the library itself, which is the only
thing Ravel reads (it keeps no list of its own):

| Location | Call | Deprecated by | Reachable from a route? |
|---|---|---|---|
| `shop/app.py` `placed_at` | `datetime.datetime.utcnow()` | `@deprecated` in the stdlib stub (Python 3.12) | yes, `POST /orders` → `placed_at` |
| `scripts/nightly.py` `locale_banner` | `locale.getdefaultlocale()` | `warnings._deprecated` in `locale.py` (3.11; removal 3.15) | no — an offline script |
| `shop/app.py` `today` | `datetime.datetime.now(datetime.timezone.utc)` | **not deprecated** — the replacement | yes, `GET /today` |

**Pinned dependencies** (`requirements.txt`, as of early 2023): Flask 2.2.2 and
Werkzeug 2.2.2 both have published advisories, so with an offline OSV database
(`ravel osv-db update`) the report lists them. The app imports Flask from route
code, so Flask's advisories are *urgent*; Werkzeug is never imported, but Flask
requires it, so with an environment it is linked via Flask.

Never deploy or run it.

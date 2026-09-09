# Ravel — Roadmap (plain English)

> The friendly version. Read this first to understand *what* we're building and
> in *what order*. For the technical detail see [`docs/BUILD-PLAN.md`](BUILD-PLAN.md);
> for the product rules see [`PRODUCT.md`](../PRODUCT.md).

**The one-line goal:** point Ravel at a Python project, and instead of a wall of
~200 security warnings, it hands you a short list of the ones a real attacker
could actually reach — each explained in plain words, with the attack path drawn
out. Runs locally, nothing uploaded.

**Scope decision:** v1 is **Python only** — on purpose. Supporting many languages
(like the Arcflow reference tool) means a shallow, guess-based map in every
language. Getting the *reachability* answer right needs language-specific
precision, so we go deep in one language first. The architecture stays
language-agnostic, so more languages are a later add-on, not a rewrite.

---

## The features, step by step

### Step 1 — Teach it to read the code
It reads every file in a Python project and picks out each function and class —
like listing every "room" in a building.
**After this:** it knows every piece of code that exists.

### Step 2 — Draw the map of what connects to what
It works out which function calls which, and which file imports which, so it
understands how the whole project is wired together — not one file at a time.
**After this:** we have a correct "map" of the codebase.
*(Make-or-break: we hand-check ~20 cases to be sure the map is right before moving on.)*

### Step 3 — Find the front doors
It spots where an outsider can get in — web pages and API endpoints
(Flask/FastAPI/Django). It also notes which doors have a lock (login required)
and which don't.
**After this:** we know every public entry point into the app.

### Step 4 — Turn on all the alarm systems
It runs the industry-standard scanners (Semgrep, Bandit, gitleaks, OSV) and
collects every warning — usually ~200. We use mature scanners; we don't invent
our own.
**After this:** we have the full, noisy list — the wall everyone else stops at.

### Step 5 — Build a scoreboard
Before getting clever, we build an honest way to measure ourselves: real
projects with known bugs where we already know the right answers.
**After this:** we can *prove* with numbers whether the tool is good, not just claim it.

### Step 6 — The smart filter (the heart of it) ⭐
For each warning, it traces backward through the map: *can an outsider at one of
the doors actually reach this code?* If not, it's already safe, dead, or
unreachable — set aside. This cuts ~200 warnings down to ~20 that truly matter.
**After this:** the noise becomes a short, meaningful list.
*(Checkpoint: are we ~3× more accurate without missing real bugs? If yes, we have a product. If no, we rethink — honestly.)*

### Step 7 — The explainer (the AI layer)
Now — and only now — AI comes in. For each of the ~20 real warnings, it reads the
flagged code plus its surroundings and writes a plain-English verdict: *real
problem or false alarm, and why?* The AI only ever sees the short list, never the
noisy 200.
**After this:** each finding comes with a clear "what this is and whether to worry" note.

### Step 8 — Show it nicely
Results in three forms: a command-line tool, a JSON file (for other tools), and a
simple web page that **draws the path** — "a stranger enters here → flows through
here → reaches this vulnerable line."
**After this:** anyone can see the risk and the path at a glance.

### Step 9 — The "what will this cost me" report
Using the same map, it flags outdated/risky libraries and deprecated code — and
ranks those by reachability too, so you know which upgrades are urgent vs. cosmetic.
**After this:** it also answers "how painful is it to modernize this project?"

### Step 10 — Make re-runs fast
The first scan is thorough. After that, when code changes it only re-checks what
actually changed (and is smart about renamed files) instead of redoing everything.
**After this:** fast enough to run on every code change, not just once.

---

## The finished product
Point it at a Python repo → it reads the code, maps it, finds the doors, gathers
all warnings, keeps only the reachable ones, has AI explain each, and shows a
short ranked list with the attack path drawn out — plus a dependency-risk report.
All local, nothing uploaded, with honest accuracy numbers behind the claims.

**If we ever run low on time,** we drop features from the end backward (web page
first, then AI explanations, then summaries). Even stripped to Steps 1–6 plus the
scoreboard, it's still a complete, useful product — because the smart filter is
the real magic, not the AI.

---

## Future ideas (AFTER v1 — do not build these yet)

> ⚠️ These are the "v2 menu." **None of them ship in v1**, and none of them matter
> until the smart filter (Step 6) is proven. They're written down so the team can
> see the direction — not so anyone starts early. Some already have reserved
> columns in the data model (PRODUCT.md §4), so adding them later needs no rewrite.
>
> The common thread: every one of these only works *because we have the map*.
> That's what makes them ours and not something the reference tools could do.

### ⭐ Flagship — "Are we actually affected?" reports (VEX / SBOM)

Software comes with an **ingredients list** (every outside library it uses).
Security databases constantly announce "library X has a bug," and you get pinged
for every ingredient you have — even though a library might have 100 functions
and only *one* is buggy. If your code never touches the buggy function, you're
actually safe, but normal tools still scream.

Because Ravel has the map, it knows whether your code actually *reaches* the buggy
part, so it can stamp each alert automatically: **"Not affected — you never call
the broken part"** (with proof) or **"Affected — here's the path."** That "not
affected, here's why" note is a real industry standard (**VEX**), and almost no
tool can produce it credibly. Big value as SBOMs become required.

*Everyday version: a recall says "Brand X peanut butter, batch 123, is
contaminated." Ravel checks and says "you have batch 456 and never opened the jar
— you're fine, here's why," instead of just panicking because you own Brand X.*

### ⭐ On-trend bet — Plug into AI coding assistants (MCP)

Lots of code is now written by AI assistants (Claude Code, Cursor, Copilot), and
that AI has no real idea whether the code it just wrote opened a hole a hacker
could reach. **MCP** is a universal "plug" that lets any AI assistant ask an
outside tool a question. We run Ravel behind that plug, so while the AI is
writing code it can ask *"is this line reachable by an outside attacker?"* and get
a real answer from the map — and fix it before you ever see it. Ravel becomes a
live advisor next to the AI, not a scan you run afterwards.

*Everyday version: a chef (the AI) cooks fast; Ravel is the food-safety inspector
standing beside them answering "is that safe to serve?" as they go — instead of
checking only after the plate's gone out.*

### The rest (shorter)

- **PR-time gate** — run on each pull request and alert *only* when a change makes
  something newly reachable. ("This PR opened a path from a public page to a
  dangerous call.") Reserved: `graph_diff`.
- **Auto-fix the reachable few** — once we're down to ~20 real findings, generate a
  small fix PR for each. Reserved: `patch`.
- **Runtime confirmation** — cross-check our "reachable" verdict against real
  production traces (e.g. Sentry): "we predicted this path — it actually fired last
  week." Reserved: `runtime_evidence`.
- **"Why did you hide this?"** — for the ~180 findings we filter out, let a user
  click one and see *why* we judged it unreachable. Builds trust in the short list.
- **Triage memory** — remember human decisions ("accepted risk") so we don't
  re-nag on the next run.
- **More languages** — v1 is Python only on purpose; the architecture is built to
  add a second language (likely JS/TS or Go) *after* the thesis is proven.

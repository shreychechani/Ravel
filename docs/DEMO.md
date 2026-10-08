# Demo runbook (mid-semester review)

A 5-minute live demo. Run steps 0–1 **before** the presentation; everything
after works offline.

## 0. One-time setup (needs internet)

```bash
cd Ravel
git pull
uv sync
npm --prefix web install
npm --prefix web run build            # builds web/out, which ravel serve hosts
brew install ollama gitleaks          # if not installed yet
ollama pull llama3.2:3b               # ~2 GB, local model for the AI review
uv run python -m eval.run             # first run clones vulpy and builds venvs (cached)
```

A virtualenv with Flask, so the demo app's calls resolve (coverage 100%):

```bash
uv venv ~/.venvs/ravel-demo && VIRTUAL_ENV=~/.venvs/ravel-demo uv pip install flask
```

## 1. Before you go on stage

```bash
ollama serve                          # keep this terminal open (or: brew services start ollama)
```

## 2. The terminal: one command, the whole pipeline

```bash
uv run ravel scan eval/fixtures/vuln_shop --venv ~/.venvs/ravel-demo
```

Point at: 8 warnings → **3 reachable**, coverage 100%, every scanner's status
listed (gitleaks ok; Semgrep "not installed" or "not configured", since we ship no rules).

## 3. The web view

```bash
uv run ravel serve eval/fixtures/vuln_shop --venv ~/.venvs/ravel-demo \
  --llm-provider ollama --model llama3.2:3b
```

Open http://127.0.0.1:8765, then:

1. The banner: **8 → 3**. The three reachable ones are on top.
2. Click **B608 find_product**: the graph shows `GET /search → find_product`,
   the code panel highlights the SQL line.
3. Click **backup** (unreachable): "No call path leads here from any of the
   4 untrusted entry points". It is still listed, just ranked lower.
4. Open the **Code graph** tab, laid out like Arcflow: folders as coloured
   hulls, functions as circles. Dashed rings are web entry points, red rings are
   reachable warnings. Switch **Color by → Risk** to light up the attack
   surface, pick **Files graph** at the top for the file-level view, and click a
   circle (or a warning on the right) to see who calls it and what it calls.
5. Press **Run AI review** (~20 s the first time): only the 3 reachable
   findings go to the local model; each gets a verdict and reasoning.

### Scan any repo from the page

Start Ravel without a repo and choose one in the browser:

```bash
uv run ravel serve --llm-provider ollama --model llama3.2:3b
```

The start screen has a URL bar: paste `github.com/owner/repo` (or a local
folder) and press **Scan**, or click one of the examples. **options** takes a
commit/branch and the repo's virtualenv (without one, third-party calls stay
unresolved and coverage is lower; the page says so). The bar stays at the top
of the page to switch repos at any time.

## 4. The numbers (the claim)

```bash
uv run python -m eval.run
```

Pooled over vulpy + flaskr: precision 11.7% → 100% (**×8.57**), recall retained
100% → **Phase 3 checkpoint PASS**. With `--triage --llm-provider ollama --model
llama3.2:3b` it also prints the triage checkpoint, which **fails** (the small
model called a real SQL injection a false positive), so triage ships off by
default. Say this out loud: it is the honest result, and it is why reachability,
not the LLM, is the core.

## If something goes wrong

- *Web page says "web view has not been built"*: run `npm --prefix web run build`.
- *Run AI review shows "Failed to connect to Ollama"*: start `ollama serve`.
- *Coverage below 80%*: you forgot `--venv`.
- No network at all: everything above works offline once step 0 is done.

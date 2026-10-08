"""The web view's backend: one scan report, served on localhost.

Local-first (PRODUCT.md §6): ``ravel serve`` binds to 127.0.0.1 only, reads the
repo, and never writes to it. The report is the same document ``ravel scan
--json`` writes (``ravel.report``), so the browser shows exactly what the CLI
measured. A rescan can switch LLM triage on or off; triage still runs only on
reachability survivors, cached and budget-capped, because it goes through the
same ``scan_repo`` path as the CLI.

The page can also open another repo (``POST /api/open``): a local folder, or a
git URL the user typed, cloned into Ravel's cache — the only network use, and
only on that explicit request. Write endpoints accept ``application/json``
only, so a cross-site page cannot trigger them without a CORS preflight, which
this server never grants.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult, build_graph
from ravel.ingest.remote import normalize_target, resolve_target
from ravel.report import build_report
from ravel.scanners.base import Scanner
from ravel.scanners.run import scan_repo
from ravel.triage.cache import TriageCache
from ravel.triage.provider import TokenBudget, create_provider

log = get_logger("ravel.api.server")

Report = dict[str, Any]
ScanFn = Callable[[bool], Report]  # triage on/off -> report

_NO_UI = """<!doctype html><meta charset="utf-8"><title>Ravel</title>
<body style="font-family:system-ui;max-width:640px;margin:64px auto;line-height:1.5">
<h1>Ravel API is running</h1>
<p>The web view has not been built yet. From the repository root run:</p>
<pre>npm --prefix web install
npm --prefix web run build</pre>
<p>then restart <code>ravel serve</code>. The raw report is at
<a href="/api/report">/api/report</a>.</p></body>"""


class ScanRequest(BaseModel):
    triage: bool = False


class OpenRequest(BaseModel):
    target: str  # a git URL or a local folder
    ref: str | None = None  # commit / tag / branch, URLs only
    venv: str | None = None  # the repo's virtualenv, for third-party resolution


@dataclass
class ScanSettings:
    """How every scan in this server runs, whichever repo is open."""

    scanners: list[Scanner]
    llm_provider: str = "mock"
    model: str | None = None
    token_budget: int = 100_000
    triage_cache: Path | None = None


class Workspace:
    """The repo the web view shows; the page can open another one."""

    def __init__(self, settings: ScanSettings) -> None:
        self.settings = settings
        self.target: str | None = None
        self.ref: str | None = None
        self.root: Path | None = None
        self.venv: Path | None = None
        self.graph: GraphResult | None = None

    def open(self, target: str, ref: str | None = None, venv: Path | None = None) -> None:
        """Resolve (cloning a URL if needed) and index ``target``. Raises ``ValueError``."""
        root = resolve_target(target, ref)
        if venv is not None and not venv.expanduser().is_dir():
            raise ValueError(f"virtualenv {venv} does not exist")
        graph = build_graph(root, venv=venv.expanduser() if venv else None)  # built once per repo
        self.target, self.ref, self.root, self.graph = normalize_target(target), ref, root, graph
        self.venv = venv
        log.info("opened %s (%d nodes)", self.target, len(graph.nodes))

    def scan(self, triage: bool) -> Report:
        if self.root is None or self.graph is None:
            raise LookupError("no repository opened yet")
        s = self.settings
        provider = create_provider(s.llm_provider, model=s.model) if triage else None
        budget = TokenBudget(limit=s.token_budget) if triage else None
        report = scan_repo(
            self.root,
            venv=self.venv,
            scanners=s.scanners,
            graph=self.graph,
            triage_provider=provider,
            token_budget=budget,
            triage_cache=TriageCache(cache_file=s.triage_cache) if triage else None,
        )
        payload = build_report(report, self.root, budget)
        payload["target"] = self.target
        payload["ref"] = self.ref
        return payload


class ReportStore:
    """Holds the current report; scans lazily and one at a time."""

    def __init__(
        self,
        scan: ScanFn | None = None,
        report: Report | None = None,
        workspace: Workspace | None = None,
    ) -> None:
        if scan is None and report is None and workspace is None:
            raise ValueError("ReportStore needs a scan function, a fixed report or a workspace")
        self._scan = scan
        self._report = report
        self._workspace = workspace
        self._lock = threading.Lock()

    def _scanner(self) -> ScanFn | None:
        if self._scan is not None:
            return self._scan
        if self._workspace is not None and self._workspace.root is not None:
            return self._workspace.scan
        return None

    @property
    def can_rescan(self) -> bool:
        return self._scanner() is not None

    @property
    def can_open(self) -> bool:
        return self._workspace is not None

    @property
    def target(self) -> str | None:
        return self._workspace.target if self._workspace is not None else None

    def get(self) -> Report:
        with self._lock:
            if self._report is None:
                scan = self._scanner()
                if scan is None:
                    raise LookupError("no repository opened yet")
                self._report = scan(False)
            return self._report

    def rescan(self, triage: bool) -> Report:
        scan = self._scanner()
        if scan is None:
            raise RuntimeError("this report was loaded from a file; there is no repo to rescan")
        with self._lock:
            self._report = scan(triage)
            return self._report

    def open(self, target: str, ref: str | None = None, venv: Path | None = None) -> Report:
        if self._workspace is None:
            raise RuntimeError("this server cannot open repositories")
        with self._lock:
            self._workspace.open(target, ref, venv)
            self._report = self._workspace.scan(False)
            return self._report


def load_report(path: Path) -> Report:
    data: Report = json.loads(path.read_text(encoding="utf-8"))
    if "findings" not in data:
        raise ValueError(f"{path} is not a Ravel scan report (no 'findings')")
    return data


def _require_json(request: Request) -> None:
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "send application/json")


def create_app(store: ReportStore, ui_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Ravel", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict[str, object]:
        return {
            "ok": True,
            "can_rescan": store.can_rescan,
            "can_open": store.can_open,
            "target": store.target,
        }

    @app.get("/api/report")
    def report() -> Report:
        try:
            return store.get()
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/scan")
    def scan(req: ScanRequest, request: Request) -> Report:
        _require_json(request)
        if not store.can_rescan:
            raise HTTPException(409, "no repository to rescan; open one first")
        try:
            return store.rescan(req.triage)
        except Exception as exc:  # surfaced to the UI, never swallowed
            log.warning("rescan failed: %s", exc)
            raise HTTPException(500, f"scan failed: {exc}") from exc

    @app.post("/api/open")
    def open_repo(req: OpenRequest, request: Request) -> Report:
        _require_json(request)
        if not store.can_open:
            raise HTTPException(409, "this server cannot open repositories")
        try:
            return store.open(req.target, req.ref or None, Path(req.venv) if req.venv else None)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:  # surfaced to the UI, never swallowed
            log.warning("open failed: %s", exc)
            raise HTTPException(500, f"scan failed: {exc}") from exc

    if ui_dir is not None and (ui_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
    else:

        @app.get("/", response_class=HTMLResponse)
        def no_ui() -> str:
            return _NO_UI

    return app

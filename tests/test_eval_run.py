"""The evaluation harness's scoring, on the planted-bug fixture (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest
from eval.run import (
    RepoSpec,
    Score,
    checkpoint,
    load_spec,
    pooled,
    score_report,
    triage_checkpoint,
)
from ravel.scanners.run import ScanReport, scan_repo

ROOT = Path(__file__).parent.parent
SHOP = ROOT / "eval" / "fixtures" / "vuln_shop"

TRUTH = """
[repo]
name = "vuln_shop"
local = "eval/fixtures/vuln_shop"

[[truth]]
id = "sqli"
file = "shop/db.py"
function = "find_product"
cwes = ["CWE-89"]
class = "SQL injection"

[[truth]]
id = "cmdi"
file = "shop/app.py"
function = "run_ping"
cwes = ["CWE-78"]
class = "Command injection"

[[truth]]
id = "deser"
file = "shop/app.py"
function = "load_cart"
cwes = ["CWE-502"]
class = "Insecure deserialization"

[[truth]]
id = "never-found"
file = "shop/templates/x.html"
cwes = ["CWE-79"]
class = "XSS no scanner sees"
"""


@pytest.fixture(scope="module")
def spec_and_report(tmp_path_factory: pytest.TempPathFactory) -> tuple[RepoSpec, ScanReport]:
    path = tmp_path_factory.mktemp("truth") / "shop_vulns.toml"
    path.write_text(TRUTH, encoding="utf-8")
    return load_spec(path), scan_repo(SHOP)


def test_ravel_keeps_every_detected_case_and_drops_noise(
    spec_and_report: tuple[RepoSpec, ScanReport],
) -> None:
    spec, report = spec_and_report
    result = score_report(spec.name, report, spec.truth, triage=False, seed=0)
    raw, ours = result.scores["keep-all"], result.scores["ravel"]
    assert (raw.kept, raw.true_pos) == (8, 3)
    assert (ours.kept, ours.true_pos) == (3, 3)
    assert ours.detected == 3 and ours.truth == 4
    assert ours.recall_retained == 1.0
    assert ours.recall_end_to_end == 0.75  # the XSS no scanner finds still counts against us
    assert result.scores["random-N"].kept == pytest.approx(3.0)


def test_checkpoint_compares_pooled_precision_to_keep_all(
    spec_and_report: tuple[RepoSpec, ScanReport],
) -> None:
    spec, report = spec_and_report
    pool = pooled([score_report(spec.name, report, spec.truth, triage=False, seed=0)])
    passed, factor = checkpoint(pool)
    assert factor == pytest.approx((3 / 3) / (3 / 8))
    assert not passed  # 2.67x is below the 3x gate


def test_spec_needs_a_source(tmp_path: Path) -> None:
    path = tmp_path / "bad_vulns.toml"
    path.write_text('[repo]\nname = "x"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="needs local, or url"):
        load_spec(path)


def test_triage_must_raise_precision_without_losing_recall() -> None:
    ravel = Score(kept=7, true_pos=7, cases_hit=5, detected=5, truth=9)
    worse = Score(kept=6, true_pos=6, cases_hit=4, detected=5, truth=9)  # dropped a real one
    better = Score(kept=5, true_pos=5, cases_hit=5, detected=5, truth=9)
    noisy = Score(kept=9, true_pos=7, cases_hit=5, detected=5, truth=9)
    assert triage_checkpoint({"ravel": ravel}) is None
    assert triage_checkpoint({"ravel": ravel, "ravel+triage": worse}) is False
    assert triage_checkpoint({"ravel": noisy, "ravel+triage": better}) is True

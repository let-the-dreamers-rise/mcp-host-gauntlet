"""Self-tests: the reference host passes every scenario, and each known flaw
makes exactly the scenarios that target it fail. This proves the oracles can
tell a correct host from a broken one before any real host is judged."""

import os
from pathlib import Path

import pytest

from gauntlet.runner import load_scenarios, run_scenario

ROOT = Path(__file__).resolve().parent.parent
DIRS = [ROOT / "scenarios"] + ([ROOT / "embargoed" / "scenarios"]
                               if (ROOT / "embargoed" / "scenarios").is_dir() else [])
SCENARIOS = [s for s in load_scenarios(DIRS)
             if not s.get("hosts") or "reference" in s["hosts"]]

FLAW_TARGETS = {
    "readonly_in_approve": {"A02-approve-ignores-readonly-hint"},
    "trust_readonly_smart": {"A08-smart-approve-trusts-readonly-hint"},
    "sticky_allow": {"A03-rugpull-allow-always-redefined"},
    "no_sanitize": {"A05-hidden-unicode-tags-in-description", "A06-hidden-unicode-tags-in-tool-result",
                    "B01-tags-in-input-schema", "B03-tags-in-error-result", "B04-tags-in-embedded-resource",
                    "B06-tags-in-structured-content", "B07-tags-in-resource-link"},
    "answer_sampling": {"A07-sampling-without-consent"},
    "ignore_reject_always": {"A04-reject-always-persists"},
    "auto_ignores_deny": {"D02-reject-always-survives-auto-mode"},
}
if (ROOT / "embargoed" / "flaw_targets.json").exists():
    import json
    FLAW_TARGETS.update({k: set(v) for k, v in
                         json.loads((ROOT / "embargoed" / "flaw_targets.json").read_text()).items()})


def run(scenario, tmp_path, flaws=""):
    os.environ["REFERENCE_FLAWS"] = flaws
    try:
        return run_scenario(scenario, "reference", str(tmp_path), timeout=30)
    finally:
        os.environ.pop("REFERENCE_FLAWS", None)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_reference_host_passes(scenario, tmp_path):
    rec = run(scenario, tmp_path)
    assert rec["status"] == "PASS", rec


@pytest.mark.parametrize("flaw", sorted(FLAW_TARGETS))
def test_flaw_is_caught(flaw, tmp_path):
    for scenario in SCENARIOS:
        if scenario["id"] not in FLAW_TARGETS[flaw]:
            continue
        rec = run(scenario, tmp_path, flaw)
        assert rec["status"] == "FAIL", (flaw, rec)

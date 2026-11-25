"""Compare a run against a recorded baseline.

A baseline records, for every scenario, the status a given host is known to
produce (PASS, or FAIL with a link to the upstream issue). CI fails when a
scenario changes status, so a fix shows up as "now passes, update the
baseline" and a regression shows up as "used to pass".

  python -m gauntlet.baseline record results/goose/summary.json baselines/goose.json
  python -m gauntlet.baseline check  results/goose/summary.json baselines/goose.json
"""

import json
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def record(summary_path, baseline_path):
    summary = load(summary_path)
    old = load(baseline_path) if Path(baseline_path).exists() else {"scenarios": {}}
    out = {"host": summary[0]["host"] if summary else None, "scenarios": {}}
    for rec in summary:
        prev = old["scenarios"].get(rec["id"], {})
        out["scenarios"][rec["id"]] = {"status": rec["status"], "tracking": prev.get("tracking")}
    Path(baseline_path).parent.mkdir(parents=True, exist_ok=True)
    Path(baseline_path).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"recorded {len(summary)} scenarios to {baseline_path}")
    return 0


def check(summary_path, baseline_path):
    summary = load(summary_path)
    baseline = load(baseline_path)["scenarios"]
    extra = Path(baseline_path).parent.parent / "embargoed" / "baselines" / Path(baseline_path).name
    if extra.exists():
        baseline.update(load(extra)["scenarios"])
    problems = []
    for rec in summary:
        want = baseline.get(rec["id"])
        if want is None:
            problems.append(f"NEW      {rec['id']}: {rec['status']} (add it to the baseline)")
        elif rec["status"] == "ERROR":
            problems.append(f"ERROR    {rec['id']}: {rec.get('error')}")
        elif rec["status"] != want["status"]:
            verb = "FIXED" if rec["status"] == "PASS" else "REGRESSED"
            problems.append(f"{verb:8} {rec['id']}: baseline {want['status']}, now {rec['status']}"
                            + (f" ({want['tracking']})" if want.get("tracking") else ""))
    for p in problems:
        print(p)
    print(f"{len(summary)} scenarios, {len(problems)} differences from baseline")
    return 1 if problems else 0


if __name__ == "__main__":
    cmd, summary_path, baseline_path = sys.argv[1:4]
    sys.exit({"record": record, "check": check}[cmd](summary_path, baseline_path))

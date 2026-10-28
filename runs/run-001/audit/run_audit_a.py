"""Pin candidate bytes around focused independent synthetic verification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent / "repo"
PATHS = [
    "runtime/candidate/swebench_claim_audit/generalized.py",
    "runtime/candidate/swebench_claim_audit/generalized_bridge.py",
    "runtime/candidate/swebench_claim_audit/campaign.py",
    "runtime/candidate/swebench_claim_audit/prepare_plan.py",
    "runtime/candidate/swebench_claim_audit/bind_campaign.py",
    "tests/test_swebench_generalized.py",
    "tests/test_swebench_generalized_bridge.py",
    "tests/test_swebench_campaign.py",
    "docs/swebench-claim-audit/ADAPTER_GENERALIZATION_BASELINE.md",
    "docs/swebench-claim-audit/GENERALIZED_ENGINE.md",
]
PATHS += [p.relative_to(REPO).as_posix() for p in sorted((REPO / "tools" / "claim-audit").glob("*")) if p.is_file()]

def pins():
    return {p: {"sha256": hashlib.sha256((REPO / p).read_bytes()).hexdigest(),
                "bytes": (REPO / p).stat().st_size} for p in PATHS}

name = sys.argv[1]
if not name.replace("-", "").isalnum():
    raise SystemExit("safe unique attempt name required")
report = ROOT / (name + ".json")
log = ROOT / (name + ".txt")
if report.exists() or log.exists():
    raise SystemExit("attempt already exists")
targets = sys.argv[2:] or [str(ROOT / "audit_a_probes.py")]
before = pins()
started = datetime.now(timezone.utc).isoformat()
args = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", *targets,
        "--basetemp", str(ROOT / ("pytest-" + name)), "-q"]
result = subprocess.run(args, cwd=REPO, capture_output=True, text=True)
after = pins()
with log.open("x", encoding="utf-8") as f:
    f.write(result.stdout)
    f.write(result.stderr)
value = {"schema": "pgop1.run001.audit-a-verification.v1", "mode": "REVIEW_ONLY",
         "started_utc": started, "ended_utc": datetime.now(timezone.utc).isoformat(),
         "command": args, "python": sys.version, "before": before, "after": after,
         "candidate_stable_during_verification": before == after,
         "exit_code": result.returncode, "log_path": str(log),
         "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
         "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
         "auditor_scripts": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in (ROOT / "audit_a_probes.py", Path(__file__))},
         "tracked_diff": subprocess.check_output(["git", "diff", "--name-status", "1086320b33e37ed07786dad2ecc2fdf34b3bd738"], cwd=REPO, text=True),
         "held_out_outcomes_read": False, "candidate_modified_by_auditor": False}
with report.open("x", encoding="utf-8") as f:
    json.dump(value, f, sort_keys=True, indent=2)
    f.write("\n")
print(json.dumps({"report": str(report), "log": str(log), "exit_code": result.returncode,
                  "stable": before == after}, sort_keys=True))
print(result.stdout)
raise SystemExit(result.returncode)

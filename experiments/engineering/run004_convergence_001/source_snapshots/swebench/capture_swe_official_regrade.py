import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
BASE = ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001"
HISTORY = ROOT / "Engineering/Legacy_Root_Workspaces/PGOP1_V1_OFFICIAL_REGRADE_NETWORK_RECOVERY_20261028T053443Z"
CAPTURE = BASE / "execution_receipts/swebench/SWE_OFFICIAL_REGRADE_001_capture"
RUNNER = BASE / "swebench/run_swe_official_regrade.py"
RUN_ID = "SWE_OFFICIAL_REGRADE_001"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if CAPTURE.exists():
        raise FileExistsError(f"fresh capture path already exists: {CAPTURE}")
    CAPTURE.mkdir(parents=True)
    executable = HISTORY / "venv/Scripts/python.exe"
    result = subprocess.run(
        [str(executable), "-B", str(RUNNER)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = CAPTURE / f"{RUN_ID}.stdout.json"
    stderr_path = CAPTURE / f"{RUN_ID}.stderr.txt"
    exit_path = CAPTURE / f"{RUN_ID}.exit.txt"
    stdout_path.write_bytes(result.stdout)
    stderr_path.write_bytes(result.stderr)
    exit_path.write_bytes(str(result.returncode).encode("ascii"))
    print(f"exit={result.returncode}")
    print(f"stdout_sha256={digest(result.stdout)}")
    print(f"stderr_sha256={digest(result.stderr)}")
    print(f"exit_file_sha256={digest(str(result.returncode).encode('ascii'))}")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())

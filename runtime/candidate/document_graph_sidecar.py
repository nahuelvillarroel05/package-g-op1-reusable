"""Build a bounded I4 document graph from an existing Stage B scan receipt.

This wrapper deliberately accepts only already-produced workspace artifacts.
The underlying sidecar validates the exact snapshot and independent byte
receipt, then reconstructs I4 and exercises the frozen I5 constructor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import evidence_sidecar


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--document-scan-dir", required=True, type=Path)
    parser.add_argument("--independent-receipt", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = evidence_sidecar.build_document_graph(
        args.document_scan_dir, args.independent_receipt, args.output_dir
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("semantic_verification", {}).get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Acquire selected BFCL source blobs from the manifest-pinned upstream commit.

The script treats fetched code as bytes only: it never imports, parses, compiles,
or executes the retrieved files.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path


COMMIT = "6ea57973c7a6097fd7c5915698c54c17c5b1b6c8"
REPO = "ShishirPatil/gorilla"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/{COMMIT}?recursive=1"
RAW_ROOT = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
DESTINATION = (
    Path(__file__).resolve().parents[1]
    / "evaluator_dependencies"
    / "bfcl"
    / f"official-{COMMIT}-source"
)
PREFIX = "berkeley-function-call-leaderboard/bfcl_eval/model_handler/"
SINGLE_FILES = {
    "berkeley-function-call-leaderboard/bfcl_eval/utils.py",
    "berkeley-function-call-leaderboard/pyproject.toml",
}


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "PGOP1-BFCL-source-provenance/1.0", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} for {url}")
        return response.read()


def main() -> int:
    if DESTINATION.exists():
        raise FileExistsError(f"Refusing to overwrite existing acquisition: {DESTINATION}")

    tree_response = json.loads(fetch(TREE_URL).decode("utf-8"))
    commit_response = json.loads(
        fetch(f"https://api.github.com/repos/{REPO}/commits/{COMMIT}").decode("utf-8")
    )
    resolved_commit = commit_response.get("sha")
    tree_sha = commit_response.get("commit", {}).get("tree", {}).get("sha")
    if resolved_commit != COMMIT:
        raise RuntimeError(f"Commit mismatch: expected {COMMIT}, received {resolved_commit}")

    selected = []
    for entry in tree_response.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") == "blob" and (path.startswith(PREFIX) or path in SINGLE_FILES):
            selected.append(entry)
    selected.sort(key=lambda entry: entry["path"])
    if not selected:
        raise RuntimeError("Pinned upstream tree returned no selected BFCL source blobs")

    staged = []
    for entry in selected:
        relative = Path(entry["path"])
        output = DESTINATION / relative
        data = fetch(RAW_ROOT + entry["path"])
        observed_blob = git_blob_sha1(data)
        if observed_blob != entry["sha"]:
            raise RuntimeError(
                f"Git blob mismatch for {entry['path']}: expected {entry['sha']}, got {observed_blob}"
            )
        staged.append((output, data, entry, hashlib.sha256(data).hexdigest()))

    for output, data, _, _ in staged:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)

    manifest = {
        "schema": "pgop1.bfcl.official-source-acquisition.v1",
        "repository": f"https://github.com/{REPO}.git",
        "commit": resolved_commit,
        "tree_sha": tree_sha,
        "source_commit_object_sha": resolved_commit,
        "source_commit": COMMIT,
        "acquisition_method": "GitHub API commit/tree metadata plus raw pinned-commit blobs; each fetched file Git-blob-SHA1 checked against pinned tree.",
        "execution_status": "SOURCE_BYTES_ONLY_NOT_IMPORTED_OR_EXECUTED",
        "scope": "Complete bfcl_eval/model_handler tree, bfcl_eval/utils.py, and benchmark pyproject.toml only.",
        "files": [
            {
                "upstream_path": entry["path"],
                "destination_path": str(output),
                "git_blob_sha1": entry["sha"],
                "sha256": digest,
                "bytes": len(data),
            }
            for output, data, entry, digest in staged
        ],
    }
    manifest_path = DESTINATION / "ACQUISITION_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ACQUIRED_PINNED_SOURCE_BYTES", "commit": COMMIT, "tree_sha": tree_sha, "file_count": len(staged), "destination": str(DESTINATION), "manifest": str(manifest_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Read-only, bounded inventory and content inspection for the I7 corpus.

The production entry point admits only the exact D-drive Engineering root. Tests
must call ``scan_fixture`` explicitly; it still enforces input/output separation.
This module never imports or executes corpus Python files.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import heapq
import csv
import hashlib
import io
import json
import ntpath
import os
import re
import stat
import shutil
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

PRODUCTION_ROOT = Path(r"PRIVATE_ENGINEERING_NOT_DISTRIBUTED")
VALIDATION_ROOT = Path(r"PRIVATE_VALIDATION_NOT_DISTRIBUTED")
PROTECTION_POLICY = "package-g-i7-corpus-scope-v1|deny:path_tokens:holdout,private,sealed,scorer,hidden_challenge,untouchable_holdout,auth,credential,secret,token,key|git:metadata-only|ordinary-binaries:hash"
PROTECTION_POLICY_SHA256 = hashlib.sha256(PROTECTION_POLICY.encode()).hexdigest()
CHUNK_SIZE = 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_TEXT_LINES = 100_000
MAX_JSON_DEPTH = 64
MAX_ZIP_MEMBERS = 20_000
MAX_ZIP_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_ZIP_RATIO = 1000
MAX_ZIP_INSPECT_BYTES = 1024 * 1024
MAX_EXPLICIT_REFS = 1000
MAX_HASH_WORKERS = 4
MAX_HASH_INFLIGHT = 8
CONTINUATION_SOURCE_PARSERS = {
    "b78e6beb8d9c120c3d517071a79fb1ef11c91c3ae14a8f5cf45abac21239120a": "legacy-unbounded-regex-001",
    "ad7cb9d74dbc62f695cfffe78e46edcb5a5e8ae4bbd4838182e1069eb8b80b1d": "bounded-path-tokenizer-v2",
}
MAX_LEDGER_ROW_BYTES = 4 * 1024 * 1024
BATCH_SIZE = 500
TEXT_SUFFIXES = {".json", ".md", ".txt", ".csv", ".log", ".py"}
_SECRET = re.compile(r"(?i)(?:bearer\s+)[A-Za-z0-9._~+/=-]{12,}|(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]{8,}")
_PROTECTED_COMPONENTS = {"holdout", "private", "sealed", "scorer", "hidden_challenge", "untouchable_holdout"}


@dataclass
class Entry:
    relpath: str
    kind: str
    status: str
    size: int | None = None
    mtime_ns: int | None = None
    device: int | None = None
    inode: int | None = None
    mode: int | None = None
    sha256: str | None = None
    detail: str | None = None


class UnsafeSourcePath(OSError):
    pass


def _canonical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _inside(path: Path, root: Path) -> bool:
    try:
        _canonical(path).relative_to(_canonical(root))
        return True
    except ValueError:
        return False


def _validate_output(root: Path, output: Path) -> None:
    root, output = _canonical(root), _canonical(output)
    if not _inside(output, VALIDATION_ROOT):
        raise ValueError("OUTPUT_MUST_BE_UNDER_VALIDATION_ROOT")
    if _inside(output, root) or _inside(root, output):
        raise ValueError("OUTPUT_ROOT_OVERLAPS_INPUT")
    cur = output
    while cur != cur.parent:
        try:
            if _is_reparse(cur, cur.lstat()):
                raise ValueError("OUTPUT_ANCESTOR_REPARSE_POINT")
        except FileNotFoundError:
            pass
        cur = cur.parent


def _validate_input_ancestors(root: Path) -> None:
    current = _canonical(root)
    for item in list(reversed(current.parents)) + [current]:
        try:
            if _is_reparse(item, item.lstat()):
                raise ValueError("INPUT_ANCESTOR_REPARSE_POINT")
        except FileNotFoundError as exc:
            raise ValueError("INPUT_ANCESTOR_MISSING") from exc


def _is_reparse(path: Path, st: os.stat_result | None = None) -> bool:
    st = st or path.lstat()
    attr = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attr & reparse) or path.is_symlink()


def _stat_tuple(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)


def _cross_api_stat_tuple(st: os.stat_result) -> tuple[int, int, int, int, int]:
    """Compare stable file identity across lstat/fstat without equating permission modes."""
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IFMT(st.st_mode))


def _final_path_from_handle(fd: int) -> str | None:
    if os.name != "nt":
        try:
            return os.path.realpath(f"/proc/self/fd/{fd}")
        except OSError:
            return None
    try:
        import ctypes
        import msvcrt
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        fn = kernel32.GetFinalPathNameByHandleW
        fn.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        fn.restype = ctypes.c_uint32
        handle = msvcrt.get_osfhandle(fd)
        needed = fn(handle, None, 0, 0)
        if not needed:
            return None
        buf = ctypes.create_unicode_buffer(needed + 1)
        written = fn(handle, buf, len(buf), 0)
        if not written or written >= len(buf):
            return None
        value = buf.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return value
    except (OSError, AttributeError, ImportError):
        return None


def _path_has_reparse_ancestor(path: Path) -> bool:
    for ancestor in reversed(path.parents):
        try:
            if _is_reparse(ancestor, ancestor.lstat()):
                return True
        except OSError:
            return True
    return False


def _open_verified(path: Path, expected: Entry | None = None):
    if _path_has_reparse_ancestor(path):
        raise UnsafeSourcePath("ANCESTOR_REPARSE_POINT")
    before = path.lstat()
    if _is_reparse(path, before) or not stat.S_ISREG(before.st_mode):
        raise UnsafeSourcePath("LEAF_REPARSE_OR_NONREGULAR")
    if expected and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode) != (expected.device, expected.inode, expected.size, expected.mtime_ns, expected.mode):
        raise UnsafeSourcePath("SOURCE_METADATA_CHANGED")
    stream = path.open("rb", buffering=0)
    opened = os.fstat(stream.fileno())
    try:
        after_open_path = path.lstat()
    except OSError:
        stream.close()
        raise UnsafeSourcePath("PATH_UNAVAILABLE_AFTER_OPEN")
    if (_cross_api_stat_tuple(before) != _cross_api_stat_tuple(opened)
            or _stat_tuple(before) != _stat_tuple(after_open_path)
            or _path_has_reparse_ancestor(path) or _is_reparse(path, after_open_path)):
        stream.close()
        raise UnsafeSourcePath("STAT_CHANGED_AT_OPEN")
    final_path = _final_path_from_handle(stream.fileno())
    expected_path = os.path.abspath(os.fspath(path))
    if final_path is None or ntpath.normcase(ntpath.normpath(final_path)) != ntpath.normcase(ntpath.normpath(expected_path)):
        stream.close()
        raise UnsafeSourcePath("HELD_FINAL_PATH_MISMATCH")
    return stream, before, opened, final_path


def _path_token(relpath: str) -> str:
    return hashlib.sha256(relpath.encode("utf-8", "surrogatepass")).hexdigest()


def _protected_path(relpath: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", relpath.casefold()).strip("_")
    tokens = set(filter(None, normalized.split("_")))
    protected_class = bool(tokens & {"holdout", "private", "sealed", "scorer"})
    named_scope = "hidden_challenge" in normalized or "untouchable_holdout" in normalized
    private_names = {"auth", "credential", "secret", "token", "private", "key"}
    private_material = any(private_names.intersection(
        filter(None, re.sub(r"[^a-z0-9]+", "_", part.casefold()).split("_")))
        for part in relpath.replace("\\", "/").split("/"))
    return protected_class or named_scope or private_material


def _metadata_only_reason(relpath: str) -> str | None:
    if _protected_path(relpath):
        return "PROTECTED_METADATA_ONLY"
    if ".git" in relpath.replace("\\", "/").casefold().split("/"):
        return "OPAQUE_HISTORY_NOT_CLASSIFIED"
    return None


def _public_entry(e: Entry) -> dict[str, Any]:
    # Paths can themselves contain secrets. Keep an opaque stable ID in artifacts.
    out = asdict(e)
    rel = out.pop("relpath")
    out["path_id"] = _path_token(rel)
    parent = Path(rel).parent.as_posix()
    out["parent_id"] = None if rel == "." else _path_token("." if parent == "." else parent)
    if out.get("detail"):
        out["detail"] = _SECRET.sub("[REDACTED]", out["detail"])
    return out


def _walk_entries(root: Path):
    """Yield (source path, metadata row) without accumulating the corpus."""
    pending = [root]
    visited: set[tuple[int, int]] = set()
    while pending:
        directory = pending.pop()
        try:
            ds = directory.lstat()
            if _is_reparse(directory, ds):
                yield directory, Entry(directory.relative_to(root).as_posix(), "reparse", "EXCLUDED_REPARSE", detail="not followed")
                continue
            key = (ds.st_dev, ds.st_ino)
            rel = "." if directory == root else directory.relative_to(root).as_posix()
            if key in visited:
                yield directory, Entry(rel, "directory", "CYCLE_OR_ALIAS", detail="identity already visited")
                continue
            visited.add(key)
            yield directory, Entry(rel, "directory", "INVENTORIED", size=ds.st_size, mtime_ns=ds.st_mtime_ns,
                                    device=ds.st_dev, inode=ds.st_ino, mode=ds.st_mode)
            try:
                with os.scandir(directory) as iterator:
                    children = sorted(list(iterator), key=lambda x: (x.name.casefold(), x.name))
            except OSError as exc:
                yield directory, Entry(rel, "directory", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")
                continue
            for child in reversed(children):
                path = Path(child.path)
                relchild = path.relative_to(root).as_posix()
                try:
                    cs = path.lstat()
                    if _is_reparse(path, cs):
                        yield path, Entry(relchild, "reparse", "EXCLUDED_REPARSE", detail="not followed")
                    elif stat.S_ISDIR(cs.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(cs.st_mode):
                        yield path, Entry(relchild, "file", "INVENTORIED", size=cs.st_size, mtime_ns=cs.st_mtime_ns,
                                          device=cs.st_dev, inode=cs.st_ino, mode=cs.st_mode)
                    else:
                        yield path, Entry(relchild, "special", "EXCLUDED_SPECIAL", size=cs.st_size, mode=cs.st_mode)
                except OSError as exc:
                    yield path, Entry(relchild, "unknown", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")
        except OSError as exc:
            rel = "." if directory == root else directory.relative_to(root).as_posix()
            yield directory, Entry(rel, "directory", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")


def _independent_walk(root: Path):
    """Verifier traversal, separately implemented from the producer walk."""
    todo = [root]
    identities: set[tuple[int, int]] = set()
    while todo:
        current = todo.pop()
        rel = "." if current == root else current.relative_to(root).as_posix()
        try:
            st = current.lstat()
            if _is_reparse(current, st):
                yield current, Entry(rel, "reparse", "EXCLUDED_REPARSE", detail="not followed")
                continue
            ident = (st.st_dev, st.st_ino)
            if ident in identities:
                yield current, Entry(rel, "directory", "CYCLE_OR_ALIAS", detail="identity already visited")
                continue
            if not stat.S_ISDIR(st.st_mode):
                continue
            identities.add(ident)
            yield current, Entry(rel, "directory", "INVENTORIED", size=st.st_size, mtime_ns=st.st_mtime_ns,
                                 device=st.st_dev, inode=st.st_ino, mode=st.st_mode)
            try:
                names = sorted(os.listdir(current), key=lambda n: n.casefold(), reverse=True)
            except OSError as exc:
                yield current, Entry(rel, "directory", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")
                continue
            for name in names:
                child = current / name
                cr = child.relative_to(root).as_posix()
                try:
                    cst = child.lstat()
                    if _is_reparse(child, cst):
                        yield child, Entry(cr, "reparse", "EXCLUDED_REPARSE", detail="not followed")
                    elif stat.S_ISDIR(cst.st_mode):
                        todo.append(child)
                    elif stat.S_ISREG(cst.st_mode):
                        yield child, Entry(cr, "file", "INVENTORIED", size=cst.st_size, mtime_ns=cst.st_mtime_ns,
                                           device=cst.st_dev, inode=cst.st_ino, mode=cst.st_mode)
                    else:
                        yield child, Entry(cr, "special", "EXCLUDED_SPECIAL", size=cst.st_size, mode=cst.st_mode)
                except OSError as exc:
                    yield child, Entry(cr, "unknown", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")
        except OSError as exc:
            yield current, Entry(rel, "directory", "INACCESSIBLE", detail=f"{type(exc).__name__}:{getattr(exc, 'errno', None)}")


def _stable_hash_details(path: Path, expected: Entry) -> tuple[str | None, str, str | None, int]:
    bytes_read = 0
    stream = None
    try:
        stream, before, opened, held_path = _open_verified(path, expected)
        h = hashlib.sha256()
        expected_size = expected.size
        if not isinstance(expected_size, int) or expected_size < 0:
            return None, "CHANGED_DURING_READ", None, bytes_read
        remaining = expected_size
        while remaining:
            chunk = stream.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                # The held file became shorter than the inventory observation.
                return None, "CHANGED_DURING_READ", None, bytes_read
            if len(chunk) > remaining:
                # A normal binary file stream never returns more than requested;
                # fail closed if a substituted stream violates that contract.
                bytes_read += len(chunk)
                return None, "CHANGED_DURING_READ", None, bytes_read
            h.update(chunk)
            bytes_read += len(chunk)
            remaining -= len(chunk)
        # Probe exactly one byte past the expected extent. This bounds a growing
        # file even if it is continuously appended while being read.
        extra = stream.read(1)
        if extra:
            bytes_read += len(extra)
            return None, "CHANGED_DURING_READ", None, bytes_read
        after_open = os.fstat(stream.fileno())
        after_path = path.lstat()
        final_after = _final_path_from_handle(stream.fileno())
        if (_stat_tuple(opened) != _stat_tuple(after_open)
                or _cross_api_stat_tuple(after_open) != _cross_api_stat_tuple(after_path)
                or _stat_tuple(before) != _stat_tuple(after_path)
                or _path_has_reparse_ancestor(path) or final_after != held_path):
            return None, "CHANGED_DURING_READ", None, bytes_read
        return h.hexdigest(), "HASHED", None, bytes_read
    except UnsafeSourcePath as exc:
        return None, "REPARSE_OR_PATH_REDIRECT", str(exc), bytes_read
    except PermissionError as exc:
        return None, "INACCESSIBLE", f"PermissionError:{getattr(exc, 'errno', None)}", bytes_read
    except OSError as exc:
        return None, "READ_ERROR", f"{type(exc).__name__}:{getattr(exc, 'errno', None)}", bytes_read
    finally:
        if stream is not None:
            stream.close()


def _process_file(path: Path, entry: Entry, token: str, snapshot_id: str) -> tuple[dict[str, Any], int]:
    """Read one file using unchanged path/hash guards; emit no files or ledger state."""
    metadata_reason = _metadata_only_reason(entry.relpath)
    bytes_read = 0
    if metadata_reason:
        digest, status, detail = None, metadata_reason, "protected path policy"
    else:
        digest, status, detail, bytes_read = _stable_hash_details(path, entry)
    row = {"path_id": token, "status": status, "size": entry.size, "mtime_ns": entry.mtime_ns,
           "device": entry.device, "inode": entry.inode, "mode": entry.mode, "sha256": digest,
           "bytes_read_hash": bytes_read, "detail": _SECRET.sub("[REDACTED]", detail or "") or None,
           "snapshot_id": snapshot_id}
    if status == "HASHED":
        suffix = path.suffix.lower()
        if suffix in TEXT_SUFFIXES:
            row["document"] = inspect_document(path, relative_path=entry.relpath, expected_sha256=digest)
        if suffix == ".zip":
            row["zip"] = _zip_inspect(path, entry)
    return row, bytes_read


def _verify_prior_file(path: Path, entry: Entry, old: dict[str, Any], token: str,
                       snapshot_id: str, prior_parser: str, old_row_sha256: str) -> tuple[str, int, list[dict[str, str]]]:
    """Reauthenticate one durable prefix row before any new row is appended."""
    if old.get("path_id") != token or old.get("snapshot_id") != snapshot_id:
        raise ValueError("DURABLE_LEDGER_SEQUENCE_MISMATCH")
    if (old.get("size"), old.get("mtime_ns"), old.get("device"), old.get("inode"), old.get("mode")) != (
            entry.size, entry.mtime_ns, entry.device, entry.inode, entry.mode):
        raise ValueError("RESUME_FILE_METADATA_MISMATCH")
    reason = _metadata_only_reason(entry.relpath)
    if reason:
        # Classification precedes every source read, even when the prior ledger lies.
        if old.get("status") != reason or old.get("sha256") is not None:
            raise ValueError("PROTECTED_PREFIX_ROW_MISMATCH")
        return reason, 0, []
    digest, status, _, bytes_read = _stable_hash_details(path, entry)
    if status != old.get("status"):
        raise ValueError("RESUME_FILE_STATUS_MISMATCH")
    if status == "HASHED":
        if digest != old.get("sha256") or old.get("bytes_read_hash") != bytes_read:
            raise ValueError("RESUME_FILE_DIGEST_MISMATCH")
        suffix = path.suffix.lower()
        unknown_references: list[dict[str, str]] = []
        if suffix in TEXT_SUFFIXES:
            document = inspect_document(path, relative_path=entry.relpath, expected_sha256=digest)
            old_document = old.get("document")
            if not isinstance(old_document, dict):
                raise ValueError("RESUME_DOCUMENT_INSPECTION_MISSING")
            if prior_parser == "legacy-unbounded-regex-001":
                method_fields = {"explicit_references", "explicit_references_truncated"}
                old_structural = {key: value for key, value in old_document.items() if key not in method_fields}
                new_structural = {key: value for key, value in document.items() if key not in method_fields}
                if old_structural != new_structural:
                    raise ValueError("RESUME_DOCUMENT_STRUCTURAL_MISMATCH")
                new_targets = {ref.get("target_id") for ref in document.get("explicit_references", [])
                               if isinstance(ref, dict) and isinstance(ref.get("target_id"), str)}
                for ref in old_document.get("explicit_references", []):
                    if not isinstance(ref, dict) or not isinstance(ref.get("target_id"), str):
                        unknown_references.append({"target_id": "", "old_row_sha256": old_row_sha256,
                                                   "reason": "LEGACY_REFERENCE_RECORD_MALFORMED"})
                    elif ref["target_id"] not in new_targets:
                        unknown_references.append({"target_id": ref["target_id"], "old_row_sha256": old_row_sha256,
                                                   "reason": "NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER"})
            elif old_document != document:
                raise ValueError("RESUME_DOCUMENT_INSPECTION_MISMATCH")
        if suffix == ".zip":
            zip_result = _zip_inspect(path, entry)
            if old.get("zip") != zip_result:
                raise ValueError("RESUME_ARCHIVE_INSPECTION_MISMATCH")
    elif old.get("sha256") is not None:
        raise ValueError("FAILED_PREFIX_ROW_HAS_DIGEST")
    else:
        unknown_references = []
    return status, bytes_read, unknown_references


def _stable_hash(path: Path, expected: Entry) -> tuple[str | None, str, str | None]:
    digest, status, detail, _ = _stable_hash_details(path, expected)
    return digest, status, detail


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_JSON_DEPTH:
        raise ValueError("JSON_DEPTH_LIMIT")
    if isinstance(value, dict):
        return max([level] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(v, level + 1) for v in value])
    return level


def inspect_document(path: Path, *, relative_path: str = "", expected_sha256: str | None = None,
                     include_private_reference_paths: bool = False) -> dict[str, Any]:
    """Parse a bounded supported text document; return no values, excerpts or source text."""
    suffix = path.suffix.lower()
    result: dict[str, Any] = {"path_id": _path_token(relative_path), "kind": suffix.lstrip("."), "status": "NOT_INSPECTED"}
    stream = None
    try:
        before = path.lstat()
        st = before
        if st.st_size > MAX_TEXT_BYTES:
            result["status"] = "SIZE_LIMIT"
            return result
        stream, before, opened, held_path = _open_verified(path)
        raw = stream.read(MAX_TEXT_BYTES + 1)
        opened_after = os.fstat(stream.fileno())
        after = path.lstat()
        final_after = _final_path_from_handle(stream.fileno())
        if (_cross_api_stat_tuple(before) != _cross_api_stat_tuple(opened)
                or _stat_tuple(opened) != _stat_tuple(opened_after)
                or _cross_api_stat_tuple(opened_after) != _cross_api_stat_tuple(after)
                or _stat_tuple(before) != _stat_tuple(after) or _path_has_reparse_ancestor(path)
                or final_after != held_path):
            result["status"] = "CHANGED_DURING_INSPECTION"
            return result
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            result["status"] = "CONTENT_DIGEST_MISMATCH"
            return result
        text = raw.decode("utf-8-sig", errors="strict")
        if len(text.splitlines()) > MAX_TEXT_LINES:
            result["status"] = "LINE_LIMIT"
            return result
        if suffix == ".json":
            value = json.loads(text)
            _depth(value)
            result.update(status="PARSED", top_level_type=type(value).__name__)
        elif suffix == ".csv":
            row_count = 0
            column_count = 0
            for row in csv.reader(io.StringIO(text), strict=True):
                row_count += 1
                column_count = max(column_count, len(row))
            result.update(status="PARSED", row_count=row_count, column_count=column_count)
        elif suffix == ".py":
            result.update(status="PARSED_AS_TEXT", syntax="not_evaluated")
        else:
            result.update(status="PARSED_AS_TEXT", line_count=len(text.splitlines()))
        result["byte_count"] = len(raw)
        result["sensitive_marker_present"] = bool(_SECRET.search(text))
        # References are extracted only from explicit path-like strings, not inferred from causal language.
        refs, truncated = _explicit_refs(text, relative_path)
        result["explicit_references"] = [{k: v for k, v in ref.items() if k != "private_relative_path"} for ref in refs]
        if include_private_reference_paths:
            result["private_reference_paths"] = [ref["private_relative_path"] for ref in refs]
        result["explicit_references_truncated"] = truncated
        return result
    except UnsafeSourcePath as exc:
        result.update(status="UNSAFE_PATH", error_type=type(exc).__name__)
        return result
    except (OSError, UnicodeError, json.JSONDecodeError, csv.Error, SyntaxError, ValueError, RecursionError) as exc:
        result.update(status="PARSE_ERROR", error_type=type(exc).__name__)
        return result
    finally:
        if stream is not None:
            stream.close()


DOCUMENT_REFERENCE_EXTRACTOR_REVISION = "bounded-path-tokenizer-v3"
MAX_EXPLICIT_PATH_CHARS = 512
_EXPLICIT_FILENAME = re.compile(r"(?:`([^`\r\n]{1,240}\.[A-Za-z0-9]{1,10})`|\(([^()\r\n]{1,240}\.[A-Za-z0-9]{1,10})\)|['\"]([^'\"\r\n]{1,240}\.[A-Za-z0-9]{1,10})['\"])")
_FILE_EXTENSIONS = {"json", "jsonl", "md", "txt", "csv", "log", "py", "zip", "sha256", "toml", "yaml", "yml", "xml", "rst", "ini"}


def _explicit_refs(text: str, source_relpath: str) -> tuple[list[dict[str, str]], bool]:
    """Find explicit path tokens in one linear pass with bounded candidate memory.

    Quoted, backtick and Markdown-link filenames retain the prior 240-character
    limit. Bare slash paths are tokenized once and capped at 512 characters.
    Candidate output remains lexically sorted and capped at MAX_EXPLICIT_REFS.
    """
    candidates: set[str] = set()
    largest_heap: list[tuple[tuple[int, ...], str]] = []
    truncated = False

    def add_candidate(candidate: str) -> None:
        nonlocal truncated
        if candidate.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS:
            return
        if candidate in candidates:
            return
        reverse_key = tuple(-ord(ch) for ch in candidate) + (1,)
        if len(candidates) < MAX_EXPLICIT_REFS:
            candidates.add(candidate)
            heapq.heappush(largest_heap, (reverse_key, candidate))
            return
        truncated = True
        if reverse_key > largest_heap[0][0]:
            _, discarded = heapq.heapreplace(largest_heap, (reverse_key, candidate))
            candidates.remove(discarded)
            candidates.add(candidate)

    def is_bare_path(candidate: str) -> bool:
        normalized = candidate.replace("\\", "/")
        prefixed = False
        if normalized.startswith("../"):
            normalized = normalized[3:]
            prefixed = True
        elif normalized.startswith("./"):
            normalized = normalized[2:]
            prefixed = True
        elif normalized.startswith("/"):
            normalized = normalized[1:]
            prefixed = True
        has_inner_separator = "/" in normalized
        return (has_inner_separator or prefixed) and bool(normalized) and not normalized.endswith("/")

    for match in _EXPLICIT_FILENAME.finditer(text):
        candidate = next(group for group in match.groups() if group is not None)
        add_candidate(candidate)

    # Bare path scanner: consume each delimiter-separated run once. In particular,
    # a long sequence such as "a/a/a/..." never causes a regex retry from each slash.
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if not (ch.isascii() and (ch.isalnum() or ch in "_./\\-")):
            i += 1
            continue
        if i and text[i - 1].isascii() and text[i - 1].isalnum():
            i += 1
            continue
        start = i
        j = i + 1
        too_long = False
        while j < n:
            cur = text[j]
            if not (cur.isascii() and (cur.isalnum() or cur in "_./\\-")):
                break
            if j - start >= MAX_EXPLICIT_PATH_CHARS:
                too_long = True
            j += 1
        if too_long:
            # Avoid allocating or repeatedly trimming a massive overlong token.
            if text.find("/", start, j) >= 0 or text.find("\\", start, j) >= 0:
                truncated = True
        else:
            token = text[start:j].rstrip(".")
        if not too_long and ("/" in token or "\\" in token):
            if is_bare_path(token):
                add_candidate(token)
        i = j

    refs = []
    for candidate in sorted(candidates):
        norm = candidate.replace("\\", "/")
        if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
            refs.append({"target_id": _path_token(norm), "resolution": "EXTERNAL_OR_ABSOLUTE_UNRESOLVED", "private_relative_path": ""})
        else:
            base = Path(source_relpath).parent
            resolved = Path(os.path.normpath(os.fspath(base / Path(norm)))).as_posix()
            refs.append({"target_id": _path_token(resolved), "resolution": "EXPLICIT_RELATIVE_PATH_UNRESOLVED", "private_relative_path": resolved})
    return refs, truncated


def _zip_inspect(path: Path, expected: Entry | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"status": "NOT_ZIP"}
    if path.suffix.lower() != ".zip":
        return out
    stream = None
    try:
        stream, before, opened, held_path = _open_verified(path, expected)
        if opened.st_size > MAX_ZIP_INSPECT_BYTES:
            return {"status": "OUTER_SHA256_ONLY_MEMBERS_NOT_INSPECTED", "reason": "ZIP_METADATA_SIZE_LIMIT"}
        with zipfile.ZipFile(stream, "r") as zf:
            members = zf.infolist()
            expanded = 0
            unsafe = 0
            for info in members[:MAX_ZIP_MEMBERS + 1]:
                name = info.filename.replace("\\", "/")
                parts = name.split("/")
                if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in parts or info.is_dir() is False and not parts[-1]:
                    unsafe += 1
                expanded += info.file_size
            if len(members) > MAX_ZIP_MEMBERS:
                out.update(status="MEMBER_LIMIT", member_count=len(members))
            elif expanded > MAX_ZIP_EXPANDED:
                out.update(status="EXPANDED_LIMIT", member_count=len(members))
            else:
                bad_ratio = any(i.file_size > 0 and i.file_size / max(i.compress_size, 1) > MAX_ZIP_RATIO for i in members)
                out.update(status="INSPECTED", member_count=len(members), expanded_bytes=expanded,
                           unsafe_path_count=unsafe, ratio_limit_exceeded=bad_ratio)
        after = os.fstat(stream.fileno())
        final_after = _final_path_from_handle(stream.fileno())
        if _stat_tuple(opened) != _stat_tuple(after) or final_after != held_path or _path_has_reparse_ancestor(path):
            out.update(status="ZIP_METADATA_READ_UNSTABLE")
    except UnsafeSourcePath as exc:
        out.update(status="ZIP_UNSAFE_PATH", error_type=type(exc).__name__)
    except (OSError, zipfile.BadZipFile, RuntimeError, RecursionError) as exc:
        out.update(status="ZIP_ERROR", error_type=type(exc).__name__)
    finally:
        if stream is not None:
            stream.close()
    return out


def _inventory_pass(root: Path, path: Path, path_map_path: Path) -> tuple[str, dict[str, int]]:
    """Persist a complete path-redacted inventory while hashing its canonical stream."""
    h = hashlib.sha256()
    h.update(str(_canonical(root)).casefold().encode("utf-8") + b"\0" + PROTECTION_POLICY_SHA256.encode() + b"\0")
    counts = {"directories": 0, "regular_files": 0, "reparse": 0, "errors": 0, "bytes": 0}
    with path.open("x", encoding="utf-8", newline="\n") as out, path_map_path.open("x", encoding="utf-8", newline="\n") as pathmap:
        for source_path, entry in _walk_entries(root):
            pathmap.write(json.dumps({"path_id": _path_token(entry.relpath), "relative_path": entry.relpath}, ensure_ascii=True) + "\n")
            row = _public_entry(entry)
            if entry.kind == "file" and _metadata_only_reason(entry.relpath):
                row["status"] = _metadata_only_reason(entry.relpath)
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            out.write(encoded + "\n")
            h.update(encoded.encode("utf-8") + b"\n")
            if entry.kind == "directory": counts["directories"] += 1
            elif entry.kind == "file":
                counts["regular_files"] += 1; counts["bytes"] += entry.size or 0
                reason = _metadata_only_reason(entry.relpath)
                if reason == "PROTECTED_METADATA_ONLY": counts["protected_files"] = counts.get("protected_files", 0) + 1
                if reason == "OPAQUE_HISTORY_NOT_CLASSIFIED": counts["opaque_git_files"] = counts.get("opaque_git_files", 0) + 1
            if entry.kind == "reparse": counts["reparse"] += 1
            if entry.status == "INACCESSIBLE": counts["errors"] += 1
        out.flush(); os.fsync(out.fileno())
    return h.hexdigest(), counts


def _write_json(path: Path, value: Any, *, append: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n" if append else json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    if append:
        with path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    else:
        with path.open("x", encoding="utf-8", newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())


def _scan_unlocked(root: Path, output: Path, *, resume: bool = False, max_files: int | None = None,
          test_api: bool = False) -> dict[str, Any]:
    root, output = _canonical(root), _canonical(output)
    if not test_api and root != _canonical(PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    if not root.is_dir():
        raise ValueError("INPUT_ROOT_NOT_DIRECTORY")
    _validate_input_ancestors(root)
    _validate_output(root, output)
    output.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(output).free < 1024 * 1024 * 1024:
        raise OSError("INSUFFICIENT_OUTPUT_SPACE_FOR_STREAMING_EVIDENCE")
    ledger = output / "scan-ledger.jsonl"
    if ledger.exists() and not resume:
        raise FileExistsError("OUTPUT_ALREADY_HAS_SCAN_LEDGER")
    if resume and not ledger.exists():
        raise FileNotFoundError("NO_DURABLE_SCAN_TO_RESUME")
    inventory_path = output / "initial-inventory.jsonl"
    if inventory_path.exists() and not resume:
        raise FileExistsError("INITIAL_INVENTORY_ALREADY_EXISTS")
    initial_inventory_name = "initial-inventory.jsonl"
    if resume:
        inventory_path = output / f"resume-inventory-{time.time_ns()}.jsonl"
        initial_inventory_name = inventory_path.name
    path_map_path = output / ("private-path-map.jsonl" if not resume else f"private-path-map-{time.time_ns()}.jsonl")
    sid, counts = _inventory_pass(root, inventory_path, path_map_path)
    state_file = output / "scan-state.json"
    completed = 0
    ledger = output / "scan-ledger.jsonl"
    if resume:
        if not ledger.exists():
            raise FileNotFoundError("NO_DURABLE_SCAN_TO_RESUME")
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
        if state and state.get("snapshot_id") != sid:
            raise ValueError("SNAPSHOT_MISMATCH_NO_SILENT_RESTART")
        if inventory_path != output / "initial-inventory.jsonl":
            # Fresh inventory is preserved as recovery evidence; use it for this pass.
            pass
        completed = int(state.get("completed_count", -1))
        if completed < -1:
            raise ValueError("INVALID_CHECKPOINT")
        with ledger.open("r", encoding="utf-8") as count_stream:
            ledger_count = 0
            for line in count_stream:
                if line.strip():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError("DURABLE_LEDGER_TORN_OR_INVALID_ROW_PRESERVED") from exc
                    if record.get("snapshot_id") != sid:
                        raise ValueError("DURABLE_LEDGER_SNAPSHOT_MISMATCH")
                    ledger_count += 1
        if completed >= 0 and ledger_count < completed:
            raise ValueError("LEDGER_CHECKPOINT_COUNT_EXCEEDS_LEDGER")
        completed = ledger_count
        if completed:
            with ledger.open("ab") as durable:
                durable.flush(); os.fsync(durable.fileno())
    def _read_ledger():
        if resume:
            with ledger.open("rb") as reader:
                while True:
                    raw = reader.readline(MAX_LEDGER_ROW_BYTES + 1)
                    if not raw:
                        break
                    if len(raw) > MAX_LEDGER_ROW_BYTES or not raw.endswith(b"\n"):
                        raise ValueError("DURABLE_LEDGER_TORN_OR_INVALID_ROW_PRESERVED")
                    try:
                        record = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                        raise ValueError("DURABLE_LEDGER_TORN_OR_INVALID_ROW_PRESERVED") from exc
                    if not isinstance(record, dict):
                        raise ValueError("DURABLE_LEDGER_ROW_NOT_OBJECT")
                    yield raw, record
    ledger_rows = iter(_read_ledger())
    if not resume:
        ledger.touch(exist_ok=False)
    seen_done = 0
    prefix_seen = 0
    prefix_validated = False
    newly_hashed = 0
    hashed_count = 0
    failed_count = 0
    bytes_hashed = 0
    actual_bytes_read = 0
    actual_bytes_read_revalidation = 0
    continuation = _load_continuation_import(output, sid, completed) if resume else None
    legacy_overlay = None
    legacy_overlay_hash = hashlib.sha256()
    legacy_overlay_rows = 0
    legacy_overlay_path = None
    legacy_manifest_path = output / "legacy-reference-reconciliation-manifest.jsonl"
    legacy_overlay_preexisting = legacy_manifest_path.exists()
    if (continuation and continuation["source_document_parser_revision"] == "legacy-unbounded-regex-001"
            and continuation["prefix_row_count"] and not legacy_overlay_preexisting):
        legacy_overlay_path = output / f"legacy-reference-reconciliation-{time.time_ns()}.jsonl"
        legacy_overlay = legacy_overlay_path.open("xb", buffering=0)
    since_checkpoint = 0
    started = time.monotonic()
    # Second walk pairs the path-redacted inventory by path_id, validating each row.
    # Hash workers are bounded; only the main thread appends rows/checkpoints, in traversal order.
    with ledger.open("a", encoding="utf-8", newline="\n") as out:
        with ThreadPoolExecutor(max_workers=MAX_HASH_WORKERS, thread_name_prefix="i7-hash") as executor:
            pending = deque()

            def write_result(source_path: Path, entry: Entry, token: str, future) -> None:
                nonlocal newly_hashed, seen_done, since_checkpoint, actual_bytes_read
                nonlocal hashed_count, failed_count, bytes_hashed
                row, bytes_this_attempt = future.result()
                actual_bytes_read += bytes_this_attempt
                if row["status"] == "HASHED":
                    hashed_count += 1
                    bytes_hashed += entry.size or 0
                else:
                    failed_count += 1
                out.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
                newly_hashed += 1
                seen_done += 1
                since_checkpoint += 1
                if since_checkpoint >= BATCH_SIZE:
                    out.flush(); os.fsync(out.fileno())
                    _replace_state(state_file, {"snapshot_id": sid, "completed_count": seen_done})
                    since_checkpoint = 0
                    if seen_done % 5000 == 0:
                        print(json.dumps({"event": "scan_progress", "snapshot_id": sid, "files_processed": seen_done,
                                          "bytes_read_hash": actual_bytes_read + actual_bytes_read_revalidation,
                                          "checkpoint": seen_done,
                                          "elapsed_seconds": round(time.monotonic() - started, 3)}, separators=(",", ":")), file=sys.stderr, flush=True)

            def read_old_prefix(source_path: Path, entry: Entry, token: str) -> None:
                nonlocal prefix_seen
                try:
                    old_raw, old = next(ledger_rows)
                except StopIteration as exc:
                    raise ValueError("DURABLE_LEDGER_TRUNCATED") from exc
                if old.get("path_id") != token or old.get("snapshot_id") != sid:
                    raise ValueError("DURABLE_LEDGER_SEQUENCE_MISMATCH")
                if (old.get("size"), old.get("mtime_ns"), old.get("device"), old.get("inode"), old.get("mode")) != (entry.size, entry.mtime_ns, entry.device, entry.inode, entry.mode):
                    raise ValueError("RESUME_FILE_METADATA_MISMATCH")
                if old.get("sha256") is not None and not re.fullmatch(r"[0-9a-f]{64}", old["sha256"]):
                    raise ValueError("DURABLE_LEDGER_INVALID_DIGEST")
                prior_parser = (continuation["source_document_parser_revision"]
                                if continuation and prefix_seen < continuation["prefix_row_count"]
                                else DOCUMENT_REFERENCE_EXTRACTOR_REVISION)
                old_row_sha256 = hashlib.sha256(old_raw).hexdigest()
                pending.append(("prefix", source_path, entry, token,
                                executor.submit(_verify_prior_file, source_path, entry, old, token, sid,
                                                prior_parser, old_row_sha256), old_row_sha256))
                prefix_seen += 1

            def drain_oldest() -> None:
                nonlocal seen_done, actual_bytes_read_revalidation
                nonlocal hashed_count, failed_count, bytes_hashed
                nonlocal legacy_overlay_rows
                item = pending.popleft()
                kind, source_path, entry, token, future = item[:5]
                if kind == "prefix":
                    status, bytes_read, unknown_refs = future.result()
                    actual_bytes_read_revalidation += bytes_read
                    hashed_count += int(status == "HASHED")
                    failed_count += int(status != "HASHED")
                    bytes_hashed += entry.size or 0 if status == "HASHED" else 0
                    seen_done += 1
                    if unknown_refs:
                        if legacy_overlay is None and not legacy_overlay_preexisting:
                            raise ValueError("LEGACY_REFERENCE_OVERLAY_CONTEXT_MISSING")
                        for unknown in unknown_refs if legacy_overlay is not None else ():
                            overlay_row = {"schema": "i7-engineering-legacy-reference@1",
                                           "snapshot_id": sid,
                                           "source_reader_sha256": continuation["source_reader_sha256"],
                                           "source_id": token,
                                           "target_id": unknown["target_id"],
                                           "old_row_sha256": item[5],
                                           "status": "LEGACY_PARSER_REFERENCE_UNKNOWN",
                                           "reason": unknown["reason"]}
                            raw = (json.dumps(overlay_row, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=True) + "\n").encode("ascii")
                            legacy_overlay.write(raw)
                            legacy_overlay_hash.update(raw)
                            legacy_overlay_rows += 1
                else:
                    write_result(source_path, entry, token, future)

            for source_path, entry in _walk_entries(root):
                if entry.kind != "file":
                    continue
                token = _path_token(entry.relpath)
                if prefix_seen < completed:
                    read_old_prefix(source_path, entry, token)
                    if len(pending) >= MAX_HASH_INFLIGHT:
                        drain_oldest()
                    continue
                # Every durable prefix row is rehashed and checked before a new task can read.
                if not prefix_validated:
                    while pending:
                        drain_oldest()
                    if seen_done != completed:
                        raise ValueError("DURABLE_PREFIX_REVALIDATION_COUNT_MISMATCH")
                    prefix_validated = True
                if max_files is not None and newly_hashed + len(pending) >= max_files:
                    while pending:
                        drain_oldest()
                    break
                if len(pending) >= MAX_HASH_INFLIGHT:
                    drain_oldest()
                future = executor.submit(_process_file, source_path, entry, token, sid)
                pending.append(("new", source_path, entry, token, future))
            while pending:
                drain_oldest()
            if prefix_seen == completed and seen_done < completed:
                raise ValueError("DURABLE_PREFIX_REVALIDATION_COUNT_MISMATCH")
            if continuation and prefix_seen != completed:
                raise ValueError("CONTINUATION_PREFIX_COUNT_MISMATCH")
            if legacy_overlay is not None:
                legacy_overlay.flush(); os.fsync(legacy_overlay.fileno()); legacy_overlay.close()
                overlay_manifest = {"schema": "i7-engineering-legacy-reference-overlay-manifest@1",
                                    "status": "COMPLETE", "snapshot_id": sid,
                                    "source_reader_sha256": continuation["source_reader_sha256"],
                                    "source_document_parser_revision": continuation["source_document_parser_revision"],
                                    "prefix_start_row": 0, "prefix_end_row_exclusive": completed,
                                    "prefix_row_count": completed,
                                    "source_ledger_prefix_sha256": continuation["prefix_sha256"],
                                    "overlay_file": legacy_overlay_path.name,
                                    "overlay_sha256": legacy_overlay_hash.hexdigest(),
                                    "overlay_row_count": legacy_overlay_rows,
                                    "row_hash_convention": "SHA256(raw JSONL row bytes including trailing LF)"}
                _write_json(output / "legacy-reference-reconciliation-manifest.jsonl", overlay_manifest, append=True)
        out.flush(); os.fsync(out.fileno())
        _replace_state(state_file, {"snapshot_id": sid, "completed_count": seen_done})
    if resume and seen_done < completed:
        raise ValueError("DURABLE_LEDGER_COUNT_EXCEEDS_INVENTORY")
    final_inventory = output / f"final-inventory-{time.time_ns()}.jsonl"
    final_path_map = output / f"final-private-path-map-{time.time_ns()}.jsonl"
    final_id, final_counts = _inventory_pass(root, final_inventory, final_path_map)
    all_hashed = (seen_done == counts["regular_files"] and failed_count == 0)
    inventory_stable = sid == final_id
    complete = all_hashed and inventory_stable and counts["errors"] == 0 and counts["reparse"] == 0
    result = {"schema": "i7-engineering-corpus-scan@1", "snapshot_id": sid, "final_snapshot_id": final_id,
              "inventory_status": "STABLE" if inventory_stable else "CHANGED_DURING_SCAN",
              "inventory_coverage_status": "COMPLETE" if final_counts["errors"] == 0 else "INCOMPLETE",
              "coverage_status": "COMPLETE" if complete else "PARTIAL_OR_BLOCKED",
              "directory_count": counts["directories"], "regular_file_count": counts["regular_files"],
              "reparse_count": counts["reparse"], "inventory_error_count": counts["errors"],
              "protected_metadata_only_count": counts.get("protected_files", 0),
              "opaque_git_metadata_only_count": counts.get("opaque_git_files", 0),
              "hashed_count": hashed_count, "unreadable_or_failed_count": failed_count,
              "bytes_in_regular_files": counts["bytes"], "bytes_hashed": bytes_hashed,
              "actual_bytes_read_hash": actual_bytes_read + actual_bytes_read_revalidation,
              "actual_bytes_read_new_files": actual_bytes_read,
              "actual_bytes_read_prefix_revalidation": actual_bytes_read_revalidation,
              "initial_inventory_sha256": sid, "final_inventory_sha256": final_id,
              "initial_inventory": initial_inventory_name, "final_inventory": final_inventory.name,
              "digest_ledger": "scan-ledger.jsonl", "private_path_mapping_local_only": path_map_path.name,
              "final_private_path_mapping_local_only": final_path_map.name,
              "protection_rule": "Protected class components and private auth/secret payload patterns are metadata-only; ambiguous .git history is metadata-only.",
              "false_positive_limit": "Public documentation mentioning protected classes may be metadata-only pending explicit classification.",
              "errors": "See path-redacted ledger rows with non-HASHED status."}
    result["protection_policy_sha256"] = PROTECTION_POLICY_SHA256
    _write_json(output / "corpus-manifest.jsonl", result, append=True)
    return result


def _scan(root: Path, output: Path, *, resume: bool = False, max_files: int | None = None,
          test_api: bool = False) -> dict[str, Any]:
    root, output = _canonical(root), _canonical(output)
    if not test_api and root != _canonical(PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    _validate_output(root, output)
    _validate_input_ancestors(root)
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".scan.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("SCAN_ALREADY_ACTIVE_OR_LOCK_REQUIRES_REVIEW") from exc
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(f"pid={os.getpid()}\nstarted_ns={time.time_ns()}\n")
            stream.flush(); os.fsync(stream.fileno())
        return _scan_unlocked(root, output, resume=resume, max_files=max_files, test_api=test_api)
    finally:
        lock.unlink(missing_ok=True)


def _replace_state(path: Path, value: Any) -> None:
    # State is a derived cache; the append-only ledger remains the durable source.
    temp = path.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def _load_continuation_import(output: Path, snapshot_id: str, completed: int) -> dict[str, Any] | None:
    """Validate an imported prefix binding before any prefix revalidation begins."""
    path = output / "CONTINUATION_IMPORT.json"
    if not path.exists():
        return None
    stream, _, _, _ = _open_verified(path)
    try:
        context = json.load(stream)
    finally:
        stream.close()
    if not isinstance(context, dict) or context.get("schema") != "i7-engineering-reader-continuation@2":
        raise ValueError("CONTINUATION_IMPORT_INVALID")
    if context.get("status") != "PREFIX_IMPORTED_AWAITING_EXPLICIT_V3_RESUME":
        raise ValueError("CONTINUATION_IMPORT_STATUS_INVALID")
    if (context.get("snapshot_id") != snapshot_id or not isinstance(context.get("prefix_row_count"), int)
            or context.get("prefix_row_count") > completed):
        raise ValueError("CONTINUATION_PREFIX_BINDING_MISMATCH")
    source_reader_sha = context.get("old_reader_sha256")
    parser = CONTINUATION_SOURCE_PARSERS.get(source_reader_sha)
    if parser is None or context.get("source_document_parser_revision") != parser:
        raise ValueError("CONTINUATION_SOURCE_READER_PIN_INVALID")
    if context.get("new_reader_revision") != DOCUMENT_REFERENCE_EXTRACTOR_REVISION:
        raise ValueError("CONTINUATION_NEW_PARSER_PIN_INVALID")
    if context.get("new_reader_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError("CONTINUATION_NEW_READER_HASH_MISMATCH")
    ledger = output / "scan-ledger.jsonl"
    h = hashlib.sha256()
    byte_count = 0
    prefix_rows = context.get("prefix_row_count")
    if not isinstance(prefix_rows, int) or prefix_rows < 0:
        raise ValueError("CONTINUATION_PREFIX_COUNT_INVALID")
    stream, _, _, _ = _open_verified(ledger)
    try:
        rows_read = 0
        while rows_read < prefix_rows:
            raw = stream.readline(MAX_LEDGER_ROW_BYTES + 1)
            if not raw or len(raw) > MAX_LEDGER_ROW_BYTES or not raw.endswith(b"\n"):
                raise ValueError("CONTINUATION_PREFIX_LEDGER_TORN")
            h.update(raw)
            byte_count += len(raw)
            rows_read += 1
    finally:
        stream.close()
    if (h.hexdigest(), byte_count) != (context.get("prefix_sha256"), context.get("prefix_byte_count")):
        raise ValueError("CONTINUATION_PREFIX_LEDGER_HASH_MISMATCH")
    if context.get("prepare_only_no_source_reads_or_full_verify") is not True:
        raise ValueError("CONTINUATION_IMPORT_NOT_PREPARE_ONLY")
    return {"source_reader_sha256": source_reader_sha,
            "source_document_parser_revision": parser,
            "prefix_sha256": h.hexdigest(), "prefix_byte_count": byte_count,
            "prefix_row_count": prefix_rows}


def scan_corpus(root: str | Path, output_dir: str | Path, *, resume: bool = False,
                max_files: int | None = None) -> dict[str, Any]:
    """Production API, exact-root guarded. A cap is a durable pause, not coverage."""
    return _scan(Path(root), Path(output_dir), resume=resume, max_files=max_files)


def scan_fixture(root: str | Path, output_dir: str | Path, *, resume: bool = False,
                 max_files: int | None = None) -> dict[str, Any]:
    """Explicit test-only API for synthetic roots; retains every path/output guard."""
    return _scan(Path(root), Path(output_dir), resume=resume, max_files=max_files, test_api=True)


def verify_snapshot(root: str | Path, output_dir: str | Path, *, snapshot_id: str | None = None,
                    test_api: bool = False) -> dict[str, Any]:
    root, output = _canonical(Path(root)), _canonical(Path(output_dir))
    if not test_api and root != _canonical(PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    _validate_output(root, output)
    _validate_input_ancestors(root)
    manifests = [json.loads(line) for line in (output / "corpus-manifest.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    manifest = next((m for m in reversed(manifests) if snapshot_id is None or m.get("snapshot_id") == snapshot_id), None)
    if manifest is None:
        raise ValueError("SNAPSHOT_NOT_IN_MANIFEST_LEDGER")
    if snapshot_id and manifest.get("snapshot_id") != snapshot_id:
        raise ValueError("SNAPSHOT_ID_MISMATCH")
    h = hashlib.sha256()
    h.update(str(_canonical(root)).casefold().encode("utf-8") + b"\0" + PROTECTION_POLICY_SHA256.encode() + b"\0")
    independent_files = 0
    checks = 0
    mismatches = 0
    missing = 0
    extra = 0
    with (output / "scan-ledger.jsonl").open("r", encoding="utf-8") as ledger:
        rows = iter(json.loads(line) for line in ledger if line.strip())
        with ThreadPoolExecutor(max_workers=MAX_HASH_WORKERS, thread_name_prefix="i7-verify") as executor:
            pending = deque()

            def drain_oldest() -> None:
                nonlocal mismatches
                source_path, entry, row, future = pending.popleft()
                digest, status, _ = future.result()
                if status != "HASHED" or row.get("status") != "HASHED" or digest != row.get("sha256"):
                    mismatches += 1

            for source_path, entry in _independent_walk(root):
                pub_entry = _public_entry(entry)
                if entry.kind == "file" and _metadata_only_reason(entry.relpath):
                    pub_entry["status"] = _metadata_only_reason(entry.relpath)
                encoded = json.dumps(pub_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                h.update(encoded.encode() + b"\n")
                if entry.kind != "file":
                    continue
                independent_files += 1
                token = _path_token(entry.relpath)
                try: row = next(rows)
                except StopIteration:
                    missing += 1
                    continue
                checks += 1
                if row.get("path_id") != token or row.get("snapshot_id") != manifest.get("snapshot_id"):
                    mismatches += 1
                    continue
                metadata_reason = _metadata_only_reason(entry.relpath)
                if metadata_reason:
                    if row.get("status") != metadata_reason or row.get("sha256") is not None:
                        mismatches += 1
                    continue
                if len(pending) >= MAX_HASH_INFLIGHT:
                    drain_oldest()
                pending.append((source_path, entry, row, executor.submit(_stable_hash, source_path, entry)))
            while pending:
                drain_oldest()
        extra = sum(1 for _ in rows)
    independent_id = h.hexdigest()
    ok = (not missing and not extra and not mismatches and independent_id == manifest.get("snapshot_id")
          and independent_files == manifest.get("regular_file_count"))
    return {"status": "VERIFIED" if ok else "INCOMPLETE_OR_MISMATCH", "snapshot_id": independent_id,
            "inventory_matches": independent_id == manifest.get("snapshot_id"), "checked_count": checks,
            "missing_count": missing, "extra_count": extra, "mismatch_count": mismatches}


def recover_scan(root: str | Path, output_dir: str | Path, *, test_api: bool = False) -> dict[str, Any]:
    return _scan(Path(root), Path(output_dir), resume=True, test_api=test_api)


def inspect_scan(output_dir: str | Path) -> dict[str, Any]:
    """Read only the final small manifest row; never materialize the large ledger."""
    path = _canonical(Path(output_dir)) / "corpus-manifest.jsonl"
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        end = stream.tell()
        start = max(0, end - 1024 * 1024)
        stream.seek(start)
        tail = stream.read().splitlines()
    for line in reversed(tail):
        if line.strip():
            return json.loads(line)
    raise ValueError("EMPTY_SCAN_MANIFEST")


def _safe_source_file(root: Path, relpath: str) -> tuple[Path | None, Entry | None]:
    candidate_rel = Path(relpath)
    if candidate_rel.is_absolute() or any(part == ".." for part in candidate_rel.parts):
        return None, None
    target = _canonical(root / candidate_rel)
    if not _inside(target, root):
        return None, None
    current = root
    for part in candidate_rel.parts:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            return target, None
        if _is_reparse(current, st):
            return target, Entry(relpath, "reparse", "EXCLUDED_REPARSE")
    try:
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode):
            return target, Entry(relpath, "special", "EXCLUDED_SPECIAL", size=st.st_size, mode=st.st_mode)
        return target, Entry(relpath, "file", "INVENTORIED", size=st.st_size, mtime_ns=st.st_mtime_ns,
                             device=st.st_dev, inode=st.st_ino, mode=st.st_mode)
    except OSError:
        return target, None


def scan_documents(root: str | Path, output_dir: str | Path, relative_paths: Iterable[str], *,
                   max_documents: int = 10, test_api: bool = False) -> dict[str, Any]:
    """Inspect a bounded explicit document set and resolve literal relative references."""
    root, output = _canonical(Path(root)), _canonical(Path(output_dir))
    if not test_api and root != _canonical(PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    _validate_output(root, output)
    _validate_input_ancestors(root)
    paths = list(relative_paths)
    if not 4 <= len(paths) <= min(max_documents, 10):
        raise ValueError("DOCUMENT_SET_MUST_CONTAIN_4_TO_10_FILES")
    output.mkdir(parents=True, exist_ok=True)
    ledger_path = output / "document-scan-ledger.jsonl"
    manifest_path = output / "document-scan-manifest.jsonl"
    pathmap_path = output / "document-private-path-map.jsonl"
    if ledger_path.exists() or manifest_path.exists() or pathmap_path.exists():
        raise FileExistsError("DOCUMENT_SCAN_OUTPUT_ALREADY_EXISTS")
    h = hashlib.sha256()
    h.update(str(root).casefold().encode("utf-8") + b"\0" + PROTECTION_POLICY_SHA256.encode() + b"\0")
    rows = 0
    total_bytes = 0
    read_failures = 0
    structure_failures = 0
    reference_count = 0
    reference_resolved = 0
    reference_unknown = 0
    with ledger_path.open("x", encoding="utf-8", newline="\n") as ledger, pathmap_path.open("x", encoding="utf-8", newline="\n") as pathmap:
        for rel in paths:
            source, entry = _safe_source_file(root, rel)
            path_id = _path_token(Path(rel).as_posix())
            pathmap.write(json.dumps({"path_id": path_id, "relative_path": Path(rel).as_posix()}) + "\n")
            if source is None or entry is None:
                row = {"path_id": path_id, "status": "MISSING_OR_UNRESOLVED", "sha256": None}
                read_failures += 1
            elif _metadata_only_reason(rel):
                row = {"path_id": path_id, "status": _metadata_only_reason(rel), "size": entry.size, "sha256": None}
                read_failures += 1
            else:
                digest, status, detail, bytes_read = _stable_hash_details(source, entry)
                total_bytes += bytes_read
                doc = inspect_document(source, relative_path=Path(rel).as_posix(), expected_sha256=digest,
                                       include_private_reference_paths=True) if status == "HASHED" else None
                refs = []
                for ref, target_rel in zip(doc.get("explicit_references", []), doc.get("private_reference_paths", [])) if doc else []:
                    pathmap.write(json.dumps({"path_id": ref["target_id"], "relative_path": target_rel}) + "\n")
                    target, target_entry = _safe_source_file(root, target_rel)
                    refrow = {"target_id": ref["target_id"], "status": ref["resolution"], "sha256": None, "size": None}
                    if target is not None and target_entry is not None and not _metadata_only_reason(target_rel):
                        target_hash, target_status, _, target_bytes = _stable_hash_details(target, target_entry)
                        total_bytes += target_bytes
                        refrow["status"] = "RESOLVED_EXACT_PATH" if target_status == "HASHED" else target_status
                        refrow["sha256"] = target_hash
                        refrow["size"] = target_entry.size
                    elif target_entry is not None and _metadata_only_reason(target_rel):
                        refrow["status"] = _metadata_only_reason(target_rel)
                    elif target is None:
                        refrow["status"] = "OUTSIDE_ROOT_OR_INVALID"
                    else:
                        refrow["status"] = "MISSING_OR_UNRESOLVED"
                    refs.append(refrow)
                reference_count += len(refs)
                reference_resolved += sum(r["status"] == "RESOLVED_EXACT_PATH" for r in refs)
                reference_unknown += sum(r["status"] != "RESOLVED_EXACT_PATH" for r in refs)
                if doc:
                    doc.pop("private_reference_paths", None)
                row = {"path_id": path_id, "status": status, "size": entry.size, "sha256": digest,
                       "bytes_read_hash": bytes_read, "document": doc, "references": refs,
                       "detail": _SECRET.sub("[REDACTED]", detail or "") or None}
                if status != "HASHED":
                    read_failures += 1
                if doc and doc.get("status") not in {"PARSED", "PARSED_AS_TEXT"}:
                    structure_failures += 1
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            ledger.write(encoded + "\n"); ledger.flush(); os.fsync(ledger.fileno())
            h.update(encoded.encode() + b"\n")
            rows += 1
    snapshot_id = h.hexdigest()
    result = {"schema": "i7-engineering-document-scan@1", "snapshot_id": snapshot_id,
              "protection_policy_sha256": PROTECTION_POLICY_SHA256,
              "scope": "EXPLICIT_DOCUMENTS_AND_LITERAL_REFERENTS", "document_count": rows,
              "document_bytes_read": total_bytes, "read_failure_count": read_failures,
              "read_coverage_status": "COMPLETE" if read_failures == 0 else "PARTIAL_OR_BLOCKED",
              "structure_failure_count": structure_failures,
              "structure_status": "EXTRACTED" if structure_failures == 0 else "PARTIAL_OR_BLOCKED",
              "explicit_reference_count": reference_count, "reference_resolved_count": reference_resolved,
              "reference_unknown_count": reference_unknown,
              "reference_status": "ALL_EXPLICIT_RESOLVED" if reference_unknown == 0 else "UNKNOWN_REFERENTS_RETAINED",
              "coverage_status": "COMPLETE" if read_failures == 0 else "PARTIAL_OR_BLOCKED",
              "ledger": ledger_path.name, "private_path_mapping_local_only": pathmap_path.name,
              "causal_edges": []}
    _write_json(manifest_path, result, append=True)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--root", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--resume", action="store_true")
    scan.add_argument("--max-files", type=int)
    verify = sub.add_parser("verify")
    verify.add_argument("--root", required=True)
    verify.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "scan":
        result = scan_corpus(args.root, args.output, resume=args.resume, max_files=args.max_files)
    else:
        result = verify_snapshot(args.root, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("coverage_status") == "COMPLETE" or result.get("status") == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())

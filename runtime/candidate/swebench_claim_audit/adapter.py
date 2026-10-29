"""Read-only adapter for the locally archived mini-SWE-agent multilingual run.

The adapter compares an explicit completion statement found in a trajectory
with two locally supplied evaluator records. Its verdict is bounded to those
records; it does not authenticate the upstream run, provider, actor, evaluator
process, or dataset snapshot.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import zipfile
import zlib


RUN_SLUG = "20260902_mini-v2.4.6_gemini-3-5-flash"
RUN_REPO = Path("experiments-main/evaluation/multilingual") / RUN_SLUG
PREDICTIONS = Path("logs/all_preds.jsonl")
TRAJECTORY_DIR = Path("logs/trajs")
LOG_DIR = Path("logs/logs")
MAX_JSONL_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TRAJECTORY_BYTES = 16 * 1024 * 1024
MAX_PATCH_BYTES = 16 * 1024 * 1024
MAX_GZIP_BYTES = 32 * 1024 * 1024
MAX_TEST_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 96 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_RATIO = 1000
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
SUCCESS_CLAIM_RE = re.compile(
    r"\bi\s+(?:(?:have\s+)?successfully\s+|have\s+|)"
    r"(?:completed|resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:task|issue|problem|bug|fix|implementation|vulnerability|calculation|"
    r"(?:[a-z][a-z0-9_-]*\s+){0,5}(?:task|issue|problem|bug|fix|implementation|vulnerability|calculation))\b",
    re.IGNORECASE,
)
CLAIM_HEDGE_RE = re.compile(
    r"\b(?:think|believe|guess|hope|maybe|might|may|could|possibly|perhaps|apparently|"
    r"allegedly|probably|presumably|uncertain|unsure|unclear|unverified|unproven)\b",
    re.IGNORECASE,
)
CLAIM_NEGATION_RE = re.compile(r"\b(?:not|never|cannot|can't|couldn't|didn't|doesn't|hasn't|haven't|isn't)\b", re.IGNORECASE)
CLAIM_REPORTING_RE = re.compile(r"\b(?:said|stated|claimed|wrote|quoted|reported|according\s+to)\b", re.IGNORECASE)
CLAIM_CONDITIONAL_LEAD_RE = re.compile(
    r"\b(?:if|unless|assuming|supposing|provided\s+that|in\s+case|only\s+if)\b", re.IGNORECASE
)
CLAIM_CONDITIONAL_TAIL_RE = re.compile(
    r"^\s*(?:[,;:]\s*)?(?:(?:but|though|although)\s+)?"
    r"(?:if|unless|only\s+if|provided(?:\s+that)?|assuming|supposing|in\s+case|on\s+condition\s+that)\b",
    re.IGNORECASE,
)
CLAIM_QUALIFIER_TAIL_RE = re.compile(
    r"^\s*(?:[,;:]\s*)?(?:but|however|although|though|yet|except|nevertheless)\b", re.IGNORECASE
)
CLAIM_RETRACTION_RE = re.compile(
    r"\bactually\s*[,;:]?\s+(?:(?:i\s+(?:have|had|did|do)\s+(?:not|n't))|"
    r"(?:(?:it|the\s+(?:task|issue))\s+(?:isn't|wasn't|is|was|remains)\s+"
    r"(?:not\s+|still\s+)?(?:done|complete|resolved|fixed|solved|unresolved|unfixed|broken|incomplete|unfinished))|"
    r"(?:(?:the|this|that)\s+(?:claim|statement)\s+(?:is|was)\s+false))\b|"
    r"\b(?:is|was)\s+(?:an?\s+)?false\s+(?:statement|claim)\b|"
    r"\bi\s+(?:have|had|did|do)\s+(?:not|n't)\b|"
    r"\bi\s+(?:am|was)\s+(?:wrong|mistaken)\b|"
    r"\b(?:it|the\s+(?:task|issue))\s+(?:isn't|wasn't|is|was|remains|continues\s+to\s+be)\s+"
    r"(?:not\s+|still\s+)?(?:done|complete|resolved|fixed|solved|unresolved|unfixed|broken|incomplete|unfinished)\b",
    re.IGNORECASE,
)


class AuditError(ValueError):
    """Input or evidence error with a stable code safe to include in receipts."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return stat.S_ISLNK(st.st_mode) or bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _checked_root(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root).absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if _reparse(cursor):
            raise AuditError("UNSAFE_ROOT", "data root has a symlink or reparse component")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AuditError("ROOT_UNAVAILABLE", "data root cannot be resolved") from exc
    if not resolved.is_dir() or resolved != candidate:
        raise AuditError("UNSAFE_ROOT", "data root must be a regular directory")
    return resolved


def _safe_path(root: Path, relative: str | Path, *, expected_file: bool = True) -> Path:
    value = str(relative).replace("\\", "/")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (not value or posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {"", ".", ".."} for part in posix.parts)
            or "\x00" in value):
        raise AuditError("PATH_TRAVERSAL", "evidence path must be a normalized relative path")
    for part in posix.parts:
        if (part.endswith((' ', '.')) or ':' in part
                or re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?', part, re.I)):
            raise AuditError("PATH_TRAVERSAL", "evidence path uses a Windows device or alias")
    path = root
    for part in posix.parts:
        path = path / part
        if _reparse(path):
            raise AuditError("REPARSE_POINT", "evidence path contains a symlink or reparse point")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise AuditError("EVIDENCE_MISSING", "required evidence file is missing") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AuditError("PATH_TRAVERSAL", "resolved evidence path escapes the data root") from exc
    st = resolved.stat()
    if expected_file and not stat.S_ISREG(st.st_mode):
        raise AuditError("UNSAFE_FILE_TYPE", "evidence must be a regular file")
    return resolved


def _read_bytes(root: Path, relative: str | Path, limit: int) -> tuple[bytes, dict[str, object]]:
    path = _safe_path(root, relative)
    before = path.stat()
    if before.st_size > limit:
        raise AuditError("INPUT_TOO_LARGE", "evidence file exceeds its configured byte limit")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise AuditError("EVIDENCE_UNREADABLE", "evidence file could not be read") from exc
    after = path.stat()
    if (len(raw) > limit or len(raw) != before.st_size or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns):
        raise AuditError("INPUT_CHANGED_DURING_READ", "evidence changed or exceeded its bound while read")
    ref = {"path": str(Path(relative).as_posix()), "bytes": len(raw), "sha256": _sha(raw)}
    return raw, ref


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("DUPLICATE_JSON_KEY", "JSON object contains a duplicate key")
        result[key] = value
    return result


def _json(raw: bytes, label: str) -> object:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except AuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError("MALFORMED_JSON", label + " is not valid UTF-8 JSON") from exc


def _prediction_index(root: Path) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    raw, ref = _read_bytes(root, PREDICTIONS, MAX_JSONL_BYTES)
    rows: dict[str, dict[str, object]] = {}
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        value = _json(line, "prediction line " + str(number))
        if not isinstance(value, dict):
            raise AuditError("MALFORMED_PREDICTION", "prediction row must be an object")
        instance_id = value.get("instance_id")
        if not isinstance(instance_id, str) or not INSTANCE_RE.fullmatch(instance_id):
            raise AuditError("MALFORMED_PREDICTION", "prediction row has an invalid instance_id")
        if instance_id in rows:
            raise AuditError("DUPLICATE_INSTANCE", "prediction source contains a duplicate instance_id")
        rows[instance_id] = value
    return rows, ref


def _explicit_success_claim(trajectory: dict[str, object]) -> dict[str, object] | None:
    messages = trajectory.get("messages")
    if not isinstance(messages, list):
        raise AuditError("MALFORMED_TRAJECTORY", "trajectory messages must be an array")
    matches: list[dict[str, object]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if message.get("role") == "assistant" and isinstance(content, str):
            accepted = _asserted_success_claim(content)
            if accepted is not None:
                matches.append({"text": content, "matched_text": accepted.group(0),
                                "match_span": [accepted.start(), accepted.end()],
                                "source_pointer": f"/messages/{index}/content",
                                "response_id": None, "model": None})
        extra = message.get("extra")
        response = extra.get("response") if isinstance(extra, dict) else None
        choices = response.get("choices") if isinstance(response, dict) else None
        if not isinstance(choices, list):
            continue
        for choice_index, choice in enumerate(choices):
            response_message = choice.get("message") if isinstance(choice, dict) else None
            text = response_message.get("content") if isinstance(response_message, dict) else None
            accepted = _asserted_success_claim(text) if isinstance(text, str) else None
            if (isinstance(response_message, dict) and response_message.get("role") == "assistant"
                    and accepted is not None):
                matches.append({
                    "text": text,
                    "matched_text": accepted.group(0),
                    "match_span": [accepted.start(), accepted.end()],
                    "source_pointer": f"/messages/{index}/extra/response/choices/{choice_index}/message/content",
                    "response_id": response.get("id"),
                    "model": response.get("model"),
                })
    # Repeated identical provider responses are one claim with multiple exact
    # locators. Distinct positive statements remain ambiguous and fail closed.
    by_text: dict[str, list[dict[str, object]]] = {}
    for item in matches:
        by_text.setdefault(str(item["text"]), []).append(item)
    if not by_text:
        return None
    if len(by_text) != 1:
        raise AuditError("AMBIGUOUS_AGENT_CLAIM", "trajectory contains multiple explicit completion claims")
    items = next(iter(by_text.values()))
    result = dict(items[0])
    result["source_pointers"] = list(dict.fromkeys(str(item["source_pointer"]) for item in items))
    return result


def _asserted_success_claim(text: str) -> re.Match[str] | None:
    """Accept direct first-person completion statements only.

    Quoted, hedged, negated, and interrogative text is not an attributable
    assertion for this adapter. This deliberately favors missed claims over
    false positives.
    """
    match = SUCCESS_CLAIM_RE.search(text)
    if match is None or "?" in text:
        return None
    if _inside_markdown_fence(text, match.start()):
        return None
    lines = text.splitlines()
    line_index = text.count("\n", 0, match.start())
    line_start = text.rfind("\n", 0, match.start()) + 1
    if re.match(r" {0,3}>", text[line_start:match.start()]):
        return None
    # CommonMark allows a quoted paragraph to continue on an unmarked line.
    previous = line_index - 1
    while previous >= 0 and lines[previous].strip():
        if re.match(r" {0,3}>", lines[previous]):
            return None
        previous -= 1
    prefix = text[:match.start()]
    sentence_start = max(prefix.rfind(mark) for mark in (".", "!", "?", "\n")) + 1
    sentence_prefix = prefix[sentence_start:]
    sentence_end_candidates = [text.find(mark, match.end()) for mark in (".", "!", "?", "\n")]
    sentence_end_candidates = [point for point in sentence_end_candidates if point >= 0]
    sentence_end = min(sentence_end_candidates) if sentence_end_candidates else len(text)
    sentence = text[sentence_start:sentence_end]
    # Avoid treating reported speech or a qualified/negated lead-in as the
    # assistant's own unambiguous statement. Check both sides of the matched
    # phrase so trailing uncertainty or retraction cannot turn it into a claim.
    tail = text[match.end():sentence_end]
    if (CLAIM_HEDGE_RE.search(sentence) or CLAIM_NEGATION_RE.search(sentence)
            or CLAIM_REPORTING_RE.search(sentence) or CLAIM_CONDITIONAL_LEAD_RE.search(sentence_prefix)
            or CLAIM_CONDITIONAL_TAIL_RE.search(tail) or CLAIM_QUALIFIER_TAIL_RE.search(tail)
            or CLAIM_RETRACTION_RE.search(text[match.end():])):
        return None
    # A claim enclosed in straight, curly, or backtick quotation marks is
    # quoted data, even when it appears in otherwise ordinary prose.
    opening = max((prefix.rfind(mark) for mark in ('"', "\u201c", "\u2018", "`")), default=-1)
    closing = max((text.find(mark, match.end()) for mark in ('"', "\u201d", "\u2019", "`")), default=-1)
    if opening >= 0 and closing >= 0:
        return None
    return match


def _inside_markdown_fence(text: str, position: int) -> bool:
    """Return whether a position falls inside a fenced Markdown code block."""
    active: tuple[str, int] | None = None
    offset = 0
    for line in text.splitlines(keepends=True):
        if offset >= position:
            break
        marker = re.match(r" {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if active is None:
                active = (token[0], len(token))
            elif token[0] == active[0] and len(token) >= active[1]:
                active = None
        offset += len(line)
    return active is not None


def _gzip_bytes(compressed: bytes) -> bytes:
    import io

    output = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            while True:
                chunk = stream.read(min(1024 * 1024, MAX_TEST_OUTPUT_BYTES + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_TEST_OUTPUT_BYTES:
                    raise AuditError("DECOMPRESSION_LIMIT", "test output exceeds its decompressed byte limit")
    except AuditError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise AuditError("CORRUPT_GZIP", "compressed test output failed integrity checks") from exc
    return bytes(output)


def validate_zip_archive(
    archive_path: str | os.PathLike[str], *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_bytes: int = MAX_ARCHIVE_MEMBER_BYTES,
    max_total_bytes: int = MAX_ARCHIVE_TOTAL_BYTES,
    max_ratio: int = MAX_ARCHIVE_RATIO,
) -> dict[str, object]:
    """Validate a ZIP in place without extracting or executing any member."""
    path = Path(archive_path).absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if _reparse(cursor):
            raise AuditError("REPARSE_POINT", "archive path has a symlink or reparse component")
    try:
        path = path.resolve(strict=True)
        st = path.stat()
    except OSError as exc:
        raise AuditError("ARCHIVE_UNAVAILABLE", "archive cannot be read") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_archive_bytes:
        raise AuditError("ARCHIVE_SIZE_OR_TYPE", "archive is not a bounded regular file")
    seen: set[str] = set()
    total = 0
    count = 0
    archive_hash = hashlib.sha256()
    try:
        with path.open("rb") as raw_stream:
            while True:
                chunk = raw_stream.read(1024 * 1024)
                if not chunk:
                    break
                archive_hash.update(chunk)
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()
            if len(members) > max_members:
                raise AuditError("ARCHIVE_MEMBER_LIMIT", "archive member count exceeds its bound")
            for member in members:
                name = member.filename.replace("\\", "/")
                member_path = name[:-1] if name.endswith("/") else name
                p = PurePosixPath(member_path)
                win = PureWindowsPath(member_path)
                raw_parts = member_path.split("/")
                if (not member_path or p.is_absolute() or win.is_absolute() or win.drive
                        or any(part in {"", ".", ".."} for part in raw_parts)
                        or "\x00" in member_path):
                    raise AuditError("ARCHIVE_PATH_TRAVERSAL", "archive contains an unsafe member path")
                folded = "/".join(raw_parts).casefold()
                if folded in seen:
                    raise AuditError("ARCHIVE_DUPLICATE_MEMBER", "archive contains a duplicate member name")
                seen.add(folded)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or member.flag_bits & 1:
                    raise AuditError("ARCHIVE_UNSAFE_MEMBER", "archive contains a symlink or encrypted member")
                if member.file_size > max_member_bytes:
                    raise AuditError("ARCHIVE_MEMBER_LIMIT", "archive member exceeds its size bound")
                total += member.file_size
                if total > max_total_bytes:
                    raise AuditError("ARCHIVE_TOTAL_LIMIT", "archive expands beyond its total size bound")
                if member.file_size and (member.compress_size == 0
                                         or member.file_size / max(member.compress_size, 1) > max_ratio):
                    raise AuditError("ARCHIVE_RATIO_LIMIT", "archive member exceeds its expansion-ratio bound")
                with archive.open(member, "r") as stream:
                    read_bytes = 0
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        read_bytes += len(chunk)
                        if read_bytes > member.file_size or read_bytes > max_member_bytes:
                            raise AuditError("ARCHIVE_MEMBER_SIZE_MISMATCH", "archive member expanded past declared bounds")
                    if read_bytes != member.file_size:
                        raise AuditError("ARCHIVE_MEMBER_SIZE_MISMATCH", "archive member size differs from its directory")
                count += 1
    except AuditError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as exc:
        raise AuditError("CORRUPT_ARCHIVE", "archive structure or CRC validation failed") from exc
    return {"status": "PASS", "path": str(path), "sha256": archive_hash.hexdigest(),
            "archive_bytes": st.st_size, "member_count": count, "uncompressed_bytes": total,
            "extraction_performed": False, "member_execution_performed": False}


def _base(instance_id: str) -> dict[str, object]:
    return {
        "schema": "pgop1.swebench.claim-audit.v1",
        "instance_id": instance_id if isinstance(instance_id, str) and INSTANCE_RE.fullmatch(instance_id) else "UNBOUND",
        "AUDIT_VERDICT": "VERIFICATION_ERROR",
        "AGENT_STATEMENT": None,
        "PREDICTION": None,
        "EVALUATOR_RESULT": None,
        "EXECUTION_EVIDENCE": [],
        "SOURCE_PROVENANCE": {
            "benchmark_variant": "UNKNOWN",
            "run_identity": RUN_SLUG,
            "dataset_snapshot": "UNKNOWN",
            "upstream_run_authentication": "NOT_PROVEN",
            "provider_identity": "NOT_CRYPTOGRAPHICALLY_ATTESTED",
            "agent_identity": "ATTRIBUTED_TO_LOCAL_TRAJECTORY_CONTENT_ONLY",
            "evaluator_process_identity": "NOT_PROVEN",
            "redistribution_license": "UNKNOWN",
        },
        "relationships": [],
        "authority": {"claim_audit": "ADVISORY_ENGINEERING_EVIDENCE_ONLY",
                      "OP1_authority_claimed": False},
        "reason_codes": [],
    }


def audit_instance(data_root: str | os.PathLike[str], instance_id: str) -> dict[str, object]:
    """Audit one case against the frozen local run bundle and catalog records.

    All file paths are resolved beneath ``data_root`` and read-only. The output
    verdict is explicitly scoped to the local trajectory, report and catalog.
    """
    result = _base(instance_id)
    try:
        if not isinstance(instance_id, str) or not INSTANCE_RE.fullmatch(instance_id):
            raise AuditError("PATH_TRAVERSAL", "instance_id must be a bounded single path component")
        root = _checked_root(data_root)
        predictions, prediction_ref = _prediction_index(root)
        prediction = predictions.get(instance_id)
        if prediction is None:
            raise AuditError("EVIDENCE_MISSING", "prediction file has no row for this instance")
        if not isinstance(prediction.get("model_patch"), str):
            raise AuditError("EVIDENCE_MISSING", "prediction row contains no patch text")

        log_rel = LOG_DIR / instance_id
        report_raw, report_ref = _read_bytes(root, log_rel / "report.json", MAX_JSON_BYTES)
        report_map = _json(report_raw, "evaluator report")
        if not isinstance(report_map, dict) or set(report_map) != {instance_id}:
            raise AuditError("WRONG_INSTANCE_BINDING", "report must bind exactly one entry to the requested instance")
        report = report_map[instance_id]
        if not isinstance(report, dict) or type(report.get("resolved")) is not bool:
            raise AuditError("AMBIGUOUS_EVALUATOR_RESULT", "report resolved field is missing or non-boolean")

        patch_raw, patch_ref = _read_bytes(root, log_rel / "patch.diff", MAX_PATCH_BYTES)
        try:
            patch_text = patch_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditError("PATCH_ENCODING_INVALID", "patch is not UTF-8") from exc
        prediction_patch = prediction["model_patch"]
        if patch_text != prediction_patch:
            raise AuditError("PATCH_BINDING_MISMATCH", "prediction patch differs from the submitted patch artifact")
        result["PREDICTION"] = {
            "instance_id": instance_id,
            "model_name_or_path": prediction.get("model_name_or_path", "UNKNOWN"),
            "submitted_patch_sha256": _sha(patch_raw),
            "patch_bytes": len(patch_raw),
            "patch_equal_to_prediction": True,
            "source_reference": prediction_ref,
            "authenticity": "LOCAL_ARCHIVE_CONTENT_ONLY",
        }

        traj_rel = TRAJECTORY_DIR / (instance_id + ".traj.json")
        trajectory_raw, trajectory_ref = _read_bytes(root, traj_rel, MAX_TRAJECTORY_BYTES)
        trajectory = _json(trajectory_raw, "trajectory")
        if not isinstance(trajectory, dict) or trajectory.get("instance_id") != instance_id:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory does not bind to the requested instance")
        claim = _explicit_success_claim(trajectory)

        test_raw, test_compressed_ref = _read_bytes(root, log_rel / "test_output.txt.gz", MAX_GZIP_BYTES)
        test_output = _gzip_bytes(test_raw)
        test_ref = {**test_compressed_ref, "decompressed_bytes": len(test_output),
                    "decompressed_sha256": _sha(test_output)}

        catalog_rel = RUN_REPO / "per_instance_details.json"
        catalog_raw, catalog_ref = _read_bytes(root, catalog_rel, MAX_JSON_BYTES)
        catalog = _json(catalog_raw, "per-instance result catalog")
        if not isinstance(catalog, dict) or instance_id not in catalog or not isinstance(catalog[instance_id], dict):
            raise AuditError("EVIDENCE_MISSING", "run catalog has no per-instance result")
        catalog_row = catalog[instance_id]
        catalog_resolved = catalog_row.get("resolved")
        if type(catalog_resolved) is not bool:
            raise AuditError("AMBIGUOUS_EVALUATOR_RESULT", "catalog resolved field is missing or non-boolean")

        summary_rel = RUN_REPO / "results" / "results.json"
        summary_raw, summary_ref = _read_bytes(root, summary_rel, MAX_JSON_BYTES)
        summary = _json(summary_raw, "run result summary")
        if not isinstance(summary, dict) or not isinstance(summary.get("resolved"), list):
            raise AuditError("AMBIGUOUS_EVALUATOR_RESULT", "result summary has no resolved list")
        summary_has_resolved = instance_id in summary["resolved"]
        if summary_has_resolved != catalog_resolved:
            if summary_has_resolved or catalog_resolved:
                raise AuditError("EVALUATOR_RECORD_CONFLICT", "summary and per-instance catalog disagree on resolved outcome")
        report_resolved = report["resolved"]
        if report_resolved != catalog_resolved:
            raise AuditError("EVALUATOR_RECORD_CONFLICT", "report and per-instance catalog disagree on resolved outcome")

        metadata_rel = RUN_REPO / "metadata.yaml"
        _, metadata_ref = _read_bytes(root, metadata_rel, MAX_JSON_BYTES)
        readme_rel = RUN_REPO / "README.md"
        readme_raw, readme_ref = _read_bytes(root, readme_rel, MAX_JSON_BYTES)
        try:
            readme_text = readme_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditError("RUN_README_ENCODING_INVALID", "run README is not UTF-8") from exc
        if re.search(r"\bSWE-bench\s+Multilingual\b", readme_text, re.IGNORECASE):
            result["SOURCE_PROVENANCE"]["benchmark_variant"] = "SWE-BENCH_MULTILINGUAL"
            result["SOURCE_PROVENANCE"]["benchmark_variant_source"] = str(readme_rel.as_posix())
        result["EXECUTION_EVIDENCE"] = [patch_ref, report_ref, test_ref, trajectory_ref]
        result["SOURCE_PROVENANCE"]["evidence_references"] = [
            prediction_ref, catalog_ref, summary_ref, metadata_ref, readme_ref
        ]
        result["SOURCE_PROVENANCE"]["metadata_sha256"] = metadata_ref["sha256"]
        result["SOURCE_PROVENANCE"]["run_readme_sha256"] = readme_ref["sha256"]
        result["SOURCE_PROVENANCE"]["catalog_rows"] = {
            "report_resolved": report_resolved,
            "per_instance_resolved": catalog_resolved,
            "summary_resolved_membership": summary_has_resolved,
            "report_instance_key": instance_id,
            "catalog_instance_key": instance_id,
        }
        result["SOURCE_PROVENANCE"]["claimed_model_name"] = prediction.get("model_name_or_path", "UNKNOWN")
        if claim is None:
            result["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
            result["reason_codes"] = ["NO_EXPLICIT_COMPLETION_CLAIM"]
            result["EVALUATOR_RESULT"] = {"reported_resolved": report_resolved,
                                           "result_scope": "LOCAL_REPORT_AND_EXPERIMENT_CATALOG_ONLY"}
            return result

        claim["predicate"] = "TASK_RESOLVED"
        claim["asserted_value"] = True
        result["AGENT_STATEMENT"] = claim
        result["EVALUATOR_RESULT"] = {
            "report_resolved": report_resolved,
            "per_instance_catalog_resolved": catalog_resolved,
            "summary_resolved_membership": summary_has_resolved,
            "result_scope": "LOCAL_REPORT_AND_EXPERIMENT_CATALOG_ONLY",
            "predicate_checked": "TASK_RESOLVED",
            "observed_value": report_resolved,
        }
        result["relationships"] = [
            {"from": "AGENT_STATEMENT", "to": "EVALUATOR_RESULT",
             "relation": "CLAIM_OUTCOME_COMPARISON", "predicate": "TASK_RESOLVED",
             "evidence_refs": [trajectory_ref, report_ref, catalog_ref, summary_ref]},
            {"from": "PREDICTION", "to": "EXECUTION_EVIDENCE",
             "relation": "PATCH_BYTES_EQUAL", "evidence_refs": [prediction_ref, patch_ref]},
        ]
        result["AUDIT_VERDICT"] = "SUPPORTED" if report_resolved else "CONTRADICTED"
        result["reason_codes"] = ["CLAIM_MATCHES_LOCAL_EVALUATOR_RECORDS" if report_resolved
                                  else "CLAIM_CONTRADICTS_LOCAL_EVALUATOR_RECORDS"]
        return result
    except AuditError as exc:
        if exc.code in {"EVIDENCE_MISSING", "ROOT_UNAVAILABLE", "EVIDENCE_UNREADABLE"}:
            result["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
        elif exc.code.startswith("MALFORMED") or exc.code in {
            "DUPLICATE_JSON_KEY", "AMBIGUOUS_AGENT_CLAIM", "AMBIGUOUS_EVALUATOR_RESULT",
            "INPUT_TOO_LARGE", "INPUT_CHANGED_DURING_READ", "CORRUPT_GZIP",
            "DECOMPRESSION_LIMIT", "PATCH_ENCODING_INVALID",
        }:
            result["AUDIT_VERDICT"] = "VERIFICATION_ERROR"
        else:
            result["AUDIT_VERDICT"] = "INTEGRITY_FAILURE"
        result["reason_codes"] = [exc.code]
        return result

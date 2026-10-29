"""Prospective bounded parsers for predicate-aware SWE-bench claim audits.

Historical receipts remain unchanged. Parser IDs name narrow source schemas;
file extensions alone never authorize semantic interpretation.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import zlib
from typing import Any

from .predicate_evidence import compare_boolean_values

AUDIT_SCHEMA = "pgop1.swebench.generalized-audit.v1"
FILE_SCHEMA = "pgop1.swebench.generalized-audit-file.v1"
NORMALIZATION_SCHEMA = "pgop1.swebench.source-bound-normalization.v2"
MAX_FILES = 64
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_GZIP_BYTES = 32 * 1024 * 1024
MAX_GZIP_OUTPUT = 64 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_CLAIM_BYTES = 16 * 1024
MAX_OBSERVATIONS = 20_000
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


PARSER_VERSIONS = {
    "pgop1.swebench.prediction.miniswe_jsonl.v1": "1.0.0",
    "pgop1.swebench.trajectory.miniswe_json.v1": "1.1.0",
    "pgop1.swebench.trajectory.miniswe_role_attribution.v1": "1.0.0",
    "pgop1.swebench.evaluator_report.resolved_map_json.v1": "1.0.0",
    "pgop1.swebench.catalog.per_instance_details_json.v1": "1.1.0",
    "pgop1.swebench.results.resolved_list_json.v1": "1.0.0",
    "pgop1.swebench.log.text_unattributed.v1": "1.0.0",
    "pgop1.swebench.log.gzip_text_unattributed.v1": "1.0.0",
    "pgop1.swebench.patch.unified_diff.v1": "1.0.0",
    "pgop1.swebench.metadata.yaml.v1": "1.0.0",
    "pgop1.swebench.trajectory.aider_markdown_unattributed.v1": "1.0.0",
    "pgop1.swebench.transcript.role_export.v1": "1.0.0",
}
PARSER_ROLES = {
    "pgop1.swebench.prediction.miniswe_jsonl.v1": {"PREDICTION", "prediction", "agent_log_or_run_record"},
    "pgop1.swebench.trajectory.miniswe_json.v1": {
        "AGENT_TRAJECTORY", "agent_trajectory", "historical_agent_trajectory"},
    "pgop1.swebench.trajectory.miniswe_role_attribution.v1": {
        "AGENT_TRAJECTORY", "agent_trajectory", "historical_agent_trajectory"},
    "pgop1.swebench.evaluator_report.resolved_map_json.v1": {
        "EVALUATOR_REPORT", "third_party_evaluator_result"},
    "pgop1.swebench.catalog.per_instance_details_json.v1": {
        "EVALUATOR_CATALOG", "third_party_evaluator_result"},
    "pgop1.swebench.results.resolved_list_json.v1": {
        "EVALUATOR_SUMMARY", "third_party_evaluator_result"},
    "pgop1.swebench.log.text_unattributed.v1": {
        "EXECUTION_LOG", "agent_log_or_run_record"},
    "pgop1.swebench.log.gzip_text_unattributed.v1": {
        "EXECUTION_LOG", "agent_log_or_run_record"},
    "pgop1.swebench.patch.unified_diff.v1": {"PATCH_ARTIFACT", "agent_patch"},
    "pgop1.swebench.metadata.yaml.v1": {"RUN_METADATA", "submission_metadata"},
    "pgop1.swebench.trajectory.aider_markdown_unattributed.v1": {
        "AGENT_TRAJECTORY", "historical_agent_trajectory"},
    "pgop1.swebench.transcript.role_export.v1": {"ROLE_EXPORT", "agent_trajectory"},
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value)) and len(value.encode("utf-8")) <= 256


def _valid_run(value: object) -> bool:
    return isinstance(value, str) and bool(RUN_RE.fullmatch(value)) and len(value.encode("utf-8")) <= 256


def _reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _root(value: str | os.PathLike[str]) -> Path:
    path = Path(value).absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if _reparse(cursor):
            raise AuditError("UNSAFE_ROOT", "data root has a reparse component")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AuditError("ROOT_UNAVAILABLE", "data root cannot be resolved") from exc
    if not resolved.is_dir() or resolved != path:
        raise AuditError("UNSAFE_ROOT", "data root must be a regular directory")
    return resolved


def _safe_path(root: Path, value: object) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AuditError("PATH_INVALID", "path must be a normalized relative POSIX path")
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    parts = value.split("/")
    if (posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {"", ".", ".."} for part in parts)):
        raise AuditError("PATH_TRAVERSAL", "path is not a canonical relative path")
    reserved = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])$")
    for part in parts:
        stem = part.split(".", 1)[0]
        if ":" in part or part.endswith((".", " ")) or reserved.fullmatch(stem):
            raise AuditError("PATH_TRAVERSAL", "path component uses a Windows alias, device name, or ADS syntax")
    path = root
    for part in parts:
        path /= part
        if _reparse(path):
            raise AuditError("REPARSE_POINT", "source path contains a reparse component")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise AuditError("EVIDENCE_MISSING", "source file is missing") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AuditError("PATH_TRAVERSAL", "source escapes the evidence root") from exc
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise AuditError("UNSAFE_FILE_TYPE", "source is not a regular file")
    return value, resolved


def _descriptor(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or any(k not in value for k in ("path", "sha256", "bytes", "role", "parser_id")):
        raise AuditError("DESCRIPTOR_INVALID", "descriptor needs path, sha256, bytes, role, and parser_id")
    item = dict(value)
    if not isinstance(item["role"], str) or not item["role"] or len(item["role"]) > 64:
        raise AuditError("DESCRIPTOR_INVALID", "role must be a bounded explicit string")
    if not isinstance(item["parser_id"], str) or not item["parser_id"] or len(item["parser_id"]) > 160:
        raise AuditError("DESCRIPTOR_INVALID", "parser_id must be a bounded string")
    if item["parser_id"] in PARSER_ROLES and item["role"] not in PARSER_ROLES[item["parser_id"]]:
        raise AuditError("PARSER_ROLE_MISMATCH", "parser is not registered for this evidence role")
    if item.get("run_id") is not None and not _valid_run(item["run_id"]):
        raise AuditError("RUN_ID_INVALID", "descriptor run_id is invalid")
    if item.get("instance_id") is not None and not _valid_id(item["instance_id"]):
        raise AuditError("INSTANCE_ID_INVALID", "descriptor instance_id is invalid")
    pointer = item.get("pointer")
    if pointer is not None and (not isinstance(pointer, str) or (pointer and not pointer.startswith("/"))):
        raise AuditError("JSON_POINTER_INVALID", "optional pointer must be an absolute JSON Pointer")
    if pointer is not None:
        raise AuditError("JSON_POINTER_UNSUPPORTED", "this parser version does not accept caller-selected pointers")
    return item


def _read(root: Path, item: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    path_text, path = _safe_path(root, item["path"])
    size, digest = item["bytes"], item["sha256"]
    if type(size) is not int or size < 0 or size > MAX_FILE_BYTES or not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
        raise AuditError("SOURCE_COMMITMENT_INVALID", "invalid bounded byte count or SHA-256")
    before = path.stat()
    if before.st_size != size:
        raise AuditError("SOURCE_SIZE_MISMATCH", "source size differs from its commitment")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
            opened = os.fstat(stream.fileno())
    except OSError as exc:
        raise AuditError("EVIDENCE_UNREADABLE", "source cannot be read") from exc
    after = path.stat()
    if (len(raw) > MAX_FILE_BYTES or len(raw) != size or opened.st_size != size
            or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ino != after.st_ino or _reparse(path)):
        raise AuditError("INPUT_CHANGED_DURING_READ", "source changed during bounded read")
    actual = _sha(raw)
    if actual != digest:
        raise AuditError("SOURCE_HASH_MISMATCH", "source SHA-256 differs from its commitment")
    ref = {"path": path_text, "sha256": actual, "bytes": size, "role": item["role"],
           "parser_id": item["parser_id"], "parser_version": PARSER_VERSIONS.get(item["parser_id"], "UNKNOWN")}
    return raw, ref


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        if key in out:
            raise AuditError("DUPLICATE_JSON_KEY", "duplicate JSON object key")
        out[key] = value
    return out


def _json(raw: bytes) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise AuditError("INPUT_TOO_LARGE", "JSON exceeds parser limit")
    try:
        def reject_constant(_: str) -> None:
            raise AuditError("MALFORMED_JSON", "non-standard JSON number")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=reject_constant)
    except AuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AuditError("MALFORMED_JSON", "invalid or excessively nested UTF-8 JSON") from exc


def _escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _stable(prefix: str, *parts: str) -> str:
    return prefix + "-" + hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]


def _src(ref: dict[str, Any], pointer: str) -> dict[str, str]:
    return {"path": ref["path"], "sha256": ref["sha256"], "pointer": pointer}


def _obs(ref: dict[str, Any], run: str, iid: str, kind: str, predicate: str,
         value: Any, pointer: str, attribution: str) -> dict[str, Any]:
    stable_value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    # Freeze the normalized value at construction: callers may later add audit
    # verdicts to the public claim record, which must not mutate this observation.
    frozen_value = json.loads(stable_value)
    observation = {
        "normalization_schema": NORMALIZATION_SCHEMA,
        "observation_id": _stable("observation", run, iid, ref["path"], ref["sha256"],
                                   pointer, kind, predicate, stable_value),
        "kind": kind, "predicate": predicate, "value": frozen_value, "run_id": run, "instance_id": iid,
        "source_ref": _src(ref, pointer), "parser_id": ref["parser_id"],
        "parser_version": ref["parser_version"], "attribution": attribution,
    }
    if kind == "evaluator_result":
        observation["authentication_status"] = "UNAUTHENTICATED"
        observation["evaluator_identity_status"] = "UNKNOWN"
    return observation


def _append_observation(out: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if len(out) >= MAX_OBSERVATIONS:
        raise AuditError("OBSERVATION_LIMIT", "source exceeds normalized observation limit")
    out.append(value)


_COMPLETED = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+)?|[’'](?:ve|d)\s+)(?:successfully\s+)?(?:completed|finished)\s+"
    r"(?:the\s+)?(?:task|work|implementation|requested\s+change)\b", re.I)
_TASK_RESOLVED = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+)?|[’'](?:ve|d)\s+)(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\b"
    r"(?=\s*(?:[.!?;:,]|$)|\s+(?:and|but|by|with|after)\b)", re.I)
_TASK_RESOLVED_SCOPE = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+)?|[’'](?:ve|d)\s+)(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\b", re.I)
_ISSUE_RESOLVED = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+)?|[’'](?:ve|d)\s+)(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:issue|problem|bug|failure|defect)\b", re.I)
_TASK_NEGATIVE = re.compile(
    r"\bI\s+(?:(?:have|had)\s+)?not\s+(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\b|"
    r"\b(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\s+"
    r"(?:is|remains|continues\s+to\s+be)\s+(?:(?:still|currently)\s+)?"
    r"(?:unresolved|not\s+resolved|unfinished|incomplete)\b", re.I)
_ISSUE_NEGATIVE = re.compile(
    r"\b(?:the\s+)?(?:issue|problem|bug|failure|defect)\s+"
    r"(?:is|remains|continues\s+to\s+be)\s+(?:(?:still|currently)\s+)?"
    r"(?:unresolved|not\s+resolved|unfixed|not\s+fixed|broken)\b", re.I)
_HEDGES = re.compile(
    r"\b(?:might|may|could|possibly|perhaps|maybe|probably|apparently|allegedly|"
    r"uncertain|unverified|unproven|think|believe|guess|hope|if|unless|assuming)\b", re.I)
_NEGATION = re.compile(
    r"\b(?:never|not|cannot|can't|couldn't|didn't|doesn't|hasn't|haven't|isn't)\b", re.I)
_DENIAL_PREFIX = re.compile(
    r"\b(?:i\s+)?(?:never|didn't|did\s+not|don't|do\s+not|can't|cannot|won't|wouldn't)\s+"
    r"(?:claim|say|state|write|report)\b", re.I)
_REPORTED_PREFIX = re.compile(
    r"\b(?:the\s+)?(?:agent|claim|statement|report)\s+(?:said|stated|claimed|reported|was|is|wrote)\b|"
    r"\baccording\s+to\b|\b(?:for\s+)?example\s*:", re.I)
_RETRACTION = re.compile(
    r"\b(?:actually\b|i\s+(?:am|was)\s+(?:wrong|mistaken)\b|"
    r"(?:the\s+claim|the\s+statement)\s+(?:is|was)\s+false\b|"
    r"is\s+(?:an?\s+)?false\s+(?:statement|claim)\b|"
    r"(?:it|the\s+(?:task|issue|problem|bug))\s+(?:is|was|remains|continues\s+to\s+be)\s+"
    r"(?:not\s+|still\s+)?(?:done|complete|resolved|fixed|solved|broken|unresolved|unfinished)\b|"
    r"i\s+(?:have|had|did|do)\s+(?:not|n't)\b)", re.I)


def _fenced(text: str, pos: int) -> bool:
    fence: tuple[str, int] | None = None
    offset = 0
    for line in text.splitlines(keepends=True):
        if offset >= pos:
            break
        match = re.match(r" {0,3}(\x60{3,}|~{3,})", line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = (token[0], len(token))
            elif token[0] == fence[0] and len(token) >= fence[1]:
                fence = None
        offset += len(line)
    return fence is not None


_CLAUSE_BREAK = re.compile(r"[.!?;\n]|\b(?:and|but|or|yet|by|with|after)\b", re.I)
_CORRECTION_MARKER = re.compile(r"\b(?:actually|correction|i\s+(?:am|was)\s+(?:wrong|mistaken))\b", re.I)
_CORRECTION_STATE = re.compile(
    r"\b(?:remains|is|was|continues\s+to\s+be)\s+(?:still\s+)?(?:unresolved|unfinished|incomplete|unfixed|broken)\b|"
    r"\b(?:not\s+(?:done|complete|resolved|fixed|solved)|never\s+(?:completed|resolved|fixed|solved))\b|"
    r"\b(?:the\s+)?(?:task|issue|problem|bug)\s+(?:is|remains)\s+(?:not\s+)?(?:done|complete|resolved|fixed|solved|broken)\b", re.I)


def _claim_segment(text: str, position: int) -> tuple[int, int]:
    start, end = 0, len(text)
    for match in _CLAUSE_BREAK.finditer(text):
        if match.end() <= position:
            start = match.end()
        elif match.start() >= position:
            end = match.start()
            break
    return start, end


def _sentence_segment(text: str, position: int) -> tuple[int, int]:
    start, end = 0, len(text)
    for match in re.finditer(r"[.!?\n]", text):
        if match.end() <= position:
            start = match.end()
        elif match.start() >= position:
            end = match.start()
            break
    return start, end


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    quote = re.compile(r'"[^"\n]*"|(?<!\w)\'[^\'\n]+\'(?!\w)|'
                       r'\u201c[^\u201d\n]*\u201d|\u2018[^\u2019\n]*\u2019|`[^`\n]*`')
    return [(match.start(), match.end()) for match in quote.finditer(text)]


def _explicitly_retracted(text: str, match_end: int, predicate: str) -> bool:
    tail = text[match_end:]
    correction = re.match(
        r"\s*(?:[.!?;]\s*)?(?:actually\b\s*[,;:]?\s*|correction\s*:\s*|"
        r"i\s+(?:am|was)\s+(?:wrong|mistaken)\b\s*[,;:]?\s*)"
        r"(?P<body>[^.!?\n]{0,240}(?:[.!?;][^.!?\n]{0,120})?)", tail, re.I)
    if not correction:
        return False
    body = correction.group("body")
    body_clause_end = _claim_segment(body, 0)[1]
    body_clause = body[:body_clause_end]
    if re.match(r"\s*i\s+(?:have|had|did|do)\s+(?:not|n't)\b", body_clause, re.I):
        return True
    targeted_retraction = _TASK_NEGATIVE if predicate == "TASK_RESOLVED" else _ISSUE_NEGATIVE
    if targeted_retraction.search(body_clause):
        return True
    # A bare pronoun is sufficient only when it is the immediate correction
    # payload. Named unrelated subjects (for example, a schedule or deployment)
    # cannot retract a task or issue claim.
    return bool(re.match(r"\s*(?:it|that)\s+", body_clause, re.I)
                and _CORRECTION_STATE.search(body_clause))


def _related_qualifier_after(text: str, match_end: int, clause_end: int) -> bool:
    sentence_end = _sentence_segment(text, match_end)[1]
    tail = text[clause_end:sentence_end]
    qualifier = re.match(r"\s*,?\s*(?:but|although|though)\b(?P<body>.*)", tail, re.I)
    if not qualifier:
        return False
    body = qualifier.group("body")
    body_end = _claim_segment(body, 0)[1]
    body_clause = body[:body_end]
    related_subject = re.search(r"\b(?:i|it|that|task|issue|problem|bug|claim|statement)\b", body_clause, re.I)
    return bool(related_subject and _HEDGES.search(body_clause))


def _has_explicit_correction(text: str, span: list[int]) -> bool:
    clause_start, _ = _claim_segment(text, span[0])
    return bool(_CORRECTION_MARKER.search(text[clause_start:span[0]]))


def _claim_analysis(text: str) -> tuple[list[tuple[str, bool, str, list[int]]], list[dict[str, Any]]]:
    if len(text.encode("utf-8")) > MAX_CLAIM_BYTES:
        raise AuditError("CLAIM_TEXT_TOO_LARGE", "assistant message exceeds claim parsing byte bound")
    found = []
    rejected: list[dict[str, Any]] = []
    quote_spans = _quoted_spans(text)
    patterns = (
        ("TASK_RESOLVED", False, _TASK_NEGATIVE),
        ("ISSUE_RESOLVED", False, _ISSUE_NEGATIVE),
        ("TASK_COMPLETED", True, _COMPLETED),
        ("TASK_RESOLVED", True, _TASK_RESOLVED),
        ("ISSUE_RESOLVED", True, _ISSUE_RESOLVED),
    )
    for predicate, asserted, pattern in patterns:
        for match in pattern.finditer(text):
            start, end = _claim_segment(text, match.start())
            sentence_start, sentence_end = _sentence_segment(text, match.start())
            clause = text[start:end]
            sentence = text[sentence_start:sentence_end]
            prefix = text[sentence_start:match.start()]
            line_start = text.rfind("\n", 0, match.start()) + 1
            line = text[line_start:match.start()]
            full_line_end = text.find("\n", match.start())
            full_line = text[line_start:full_line_end if full_line_end >= 0 else len(text)]
            prior_lines = text[:text.rfind("\n", 0, match.start())].splitlines()
            in_lazy_quote = False
            for previous_line in reversed(prior_lines):
                if not previous_line.strip():
                    break
                if re.match(r" {0,3}>", previous_line):
                    in_lazy_quote = True
                    break
            reasons: list[str] = []
            if "?" in sentence or text[sentence_end:sentence_end + 1] == "?":
                reasons.append("INTERROGATIVE_CLAUSE")
            if full_line.startswith(("    ", "\t")) or _fenced(text, match.start()):
                reasons.append("MARKDOWN_CODE")
            if re.match(r" {0,3}>", line) or in_lazy_quote:
                reasons.append("MARKDOWN_QUOTE")
            if (_HEDGES.search(clause) or _HEDGES.search(prefix)
                    or _related_qualifier_after(text, match.end(), end)):
                reasons.append("HEDGED_CLAUSE")
            if _REPORTED_PREFIX.search(prefix):
                reasons.append("REPORTED_CLAIM")
            if _DENIAL_PREFIX.search(prefix):
                reasons.append("DENIED_CLAIM")
            if asserted and _NEGATION.search(clause):
                reasons.append("NEGATED_ASSERTION")
            if _RETRACTION.search(text[match.end():end]):
                reasons.append("RETRACTION_IN_CLAUSE")
            if _explicitly_retracted(text, match.end(), predicate):
                reasons.append("EXPLICIT_CORRECTION")
            if any(a <= match.start() and match.end() <= b for a, b in quote_spans):
                reasons.append("QUOTED_CLAIM")
            byte_span = [len(text[:match.start()].encode("utf-8")),
                         len(text[:match.end()].encode("utf-8"))]
            if reasons:
                rejected.append({"predicate": predicate, "asserted_value": asserted,
                                 "matched_text": match.group(0),
                                 "match_span": [match.start(), match.end()],
                                 "byte_span": byte_span,
                                 "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                                 "reason_codes": sorted(set(reasons))})
                continue
            found.append((predicate, asserted, match.group(0), [match.start(), match.end()]))
    for match in _TASK_RESOLVED_SCOPE.finditer(text):
        if _TASK_RESOLVED.match(text, match.start()) is not None:
            continue
        span = [match.start(), match.end()]
        rejected.append({"candidate_predicate": "TASK_RESOLVED",
                         "matched_text": match.group(0), "match_span": span,
                         "byte_span": [len(text[:span[0]].encode("utf-8")),
                                       len(text[:span[1]].encode("utf-8"))],
                         "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                         "reason_codes": ["NONCOMPARABLE_TASK_SCOPE"]})
    rejected.sort(key=lambda item: item["match_span"][0] if item["match_span"] else -1)
    return sorted(found, key=lambda row: row[3][0]), rejected


def _claims(text: str) -> list[tuple[str, bool, str, list[int]]]:
    """Compatibility view of accepted claims; _parse also retains rejections."""
    return _claim_analysis(text)[0]

def _assistant_messages(doc: dict[str, Any]) -> list[tuple[str, str]]:
    messages = doc.get("messages")
    if not isinstance(messages, list):
        raise AuditError("MALFORMED_TRAJECTORY", "trajectory messages must be an array")
    if len(messages) > MAX_OBSERVATIONS:
        raise AuditError("OBSERVATION_LIMIT", "trajectory message count exceeds parser bound")
    texts = []
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        if message.get("role") == "assistant" and isinstance(message.get("content"), str):
            texts.append((message["content"], f"/messages/{i}/content"))
    return texts


def _gunzip(raw: bytes) -> bytes:
    if len(raw) > MAX_GZIP_BYTES:
        raise AuditError("INPUT_TOO_LARGE", "gzip source exceeds compressed byte bound")
    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            while True:
                chunk = stream.read(min(1024 * 1024, MAX_GZIP_OUTPUT + 1 - len(out)))
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > MAX_GZIP_OUTPUT:
                    raise AuditError("DECOMPRESSION_LIMIT", "gzip expansion exceeds decompressed byte bound")
    except AuditError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise AuditError("CORRUPT_GZIP", "gzip integrity/decompression failed") from exc
    return bytes(out)


def _yaml(raw: bytes) -> dict[str, str]:
    if len(raw) > MAX_TEXT_BYTES:
        raise AuditError("INPUT_TOO_LARGE", "metadata exceeds parser bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError("METADATA_ENCODING_INVALID", "metadata is not UTF-8") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[:1].isspace() or ":" not in line:
            raise AuditError("UNSUPPORTED_YAML_SHAPE", "only flat unindented YAML scalars are supported")
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", key) or key in result:
            raise AuditError("MALFORMED_YAML", "metadata key is invalid or duplicated")
        if value.startswith(("!", "&", "*", "{", "[", "|", ">")):
            raise AuditError("UNSUPPORTED_YAML_SHAPE", "YAML tags, aliases, flow, and block values are unsupported")
        if " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        result[key] = value.strip("\"'")
        if len(result) > 4096:
            raise AuditError("METADATA_KEY_LIMIT", "metadata has too many keys")
    return result


def _parse(raw: bytes, ref: dict[str, Any], desc: dict[str, Any], run: str,
           target: str | None) -> list[dict[str, Any]]:
    parser = desc["parser_id"]
    out: list[dict[str, Any]] = []
    if parser == "pgop1.swebench.transcript.role_export.v1":
        # Role labels are source-declared metadata, not authenticated identities.
        # Bind every declared message to a committed source byte span and all
        # required contextual identities, but do not infer claims from it.
        doc = _json(raw)
        if not isinstance(doc, dict) or doc.get("schema") != "pgop1.swebench.transcript-role-export.v1":
            raise AuditError("MALFORMED_ROLE_EXPORT", "role export schema is invalid")
        iid, export_run = doc.get("instance_id"), doc.get("run_id")
        scope, timestamp = doc.get("scope"), doc.get("timestamp")
        if not _valid_id(iid) or not _valid_run(export_run):
            raise AuditError("ROLE_EXPORT_BINDING_INVALID", "role export requires valid run and instance IDs")
        if export_run != run or (target is not None and iid != target):
            raise AuditError("WRONG_INSTANCE_BINDING", "role export run or instance conflicts with request")
        if desc.get("instance_id") is None:
            raise AuditError("INSTANCE_ID_REQUIRED", "role export requires a descriptor instance binding")
        if desc["instance_id"] != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "role export instance conflicts with descriptor")
        if not isinstance(scope, str) or not scope.strip() or len(scope) > 256:
            raise AuditError("ROLE_EXPORT_SCOPE_INVALID", "role export requires a bounded nonempty scope")
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "role export requires an ISO timestamp")
        try:
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "role export timestamp is not ISO formatted") from exc
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "role export timestamp requires timezone")
        caller_scope, caller_timestamp = desc.get("scope"), desc.get("timestamp")
        if caller_scope != scope or caller_timestamp != timestamp:
            raise AuditError("ROLE_EXPORT_CALLER_BINDING_MISMATCH", "caller scope/time must match export declarations")
        source = doc.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("text"), str):
            raise AuditError("ROLE_EXPORT_SOURCE_INVALID", "role export must embed committed source text")
        source_bytes = source["text"].encode("utf-8")
        if (len(source_bytes) > MAX_TEXT_BYTES or type(source.get("bytes")) is not int
                or source.get("bytes") != len(source_bytes)
                or source.get("sha256") != _sha(source_bytes)):
            raise AuditError("ROLE_EXPORT_SOURCE_COMMITMENT_INVALID", "embedded source commitment does not match")
        messages = doc.get("messages")
        if not isinstance(messages, list) or len(messages) > MAX_OBSERVATIONS:
            raise AuditError("ROLE_EXPORT_MESSAGES_INVALID", "role export messages must be a bounded array")
        message_ids: set[str] = set()
        spans: list[tuple[int, int]] = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise AuditError("ROLE_EXPORT_MESSAGES_INVALID", "role export message must be an object")
            message_id, speaker = message.get("message_id"), message.get("speaker")
            start, end, content_hash = message.get("byte_start"), message.get("byte_end"), message.get("sha256")
            if (not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 256
                    or not isinstance(speaker, str)
                    or speaker not in {"assistant", "user", "tool", "system", "unknown"}
                    or type(start) is not int or type(end) is not int or start < 0 or end <= start
                    or end > len(source_bytes)):
                raise AuditError("ROLE_EXPORT_MESSAGE_INVALID", "role export message fields are invalid")
            if message_id in message_ids:
                raise AuditError("ROLE_EXPORT_DUPLICATE_MESSAGE_ID", "message IDs must be unique")
            message_ids.add(message_id)
            spans.append((start, end))
            segment = source_bytes[start:end]
            try:
                segment.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AuditError("ROLE_EXPORT_SPAN_ENCODING_INVALID", "message span splits UTF-8 text") from exc
            if not isinstance(content_hash, str) or content_hash != _sha(segment):
                raise AuditError("ROLE_EXPORT_SPAN_HASH_MISMATCH", "message span hash does not match source bytes")
            value = {"source_id": ref["path"], "source_hash": ref["sha256"],
                     "transcript_format": "pgop1.swebench.transcript-role-export.v1",
                     "message_id": message_id, "speaker_role": "UNKNOWN",
                     "declared_speaker": speaker, "speaker_provenance": "SOURCE_DECLARED",
                     "speaker_verification_level": "SOURCE_DECLARED_HASH_BOUND_UNVERIFIED",
                     "content_hash": content_hash, "content_span": {"byte_start": start, "byte_end": end},
                     "claim_predicate": "NONE", "caller_scope": caller_scope,
                     "caller_timestamp": caller_timestamp,
                     "declared_scope": scope, "declared_timestamp": timestamp,
                     "attribution_status": "SOURCE_DECLARED_UNVERIFIED",
                     "source_content_sha256": source["sha256"]}
            _append_observation(out, _obs(ref, run, iid, "transcript_attribution",
                                          "DECLARED_SPEAKER", value, f"/messages/{index}",
                                          "SOURCE_DECLARED_NOT_AUTHENTICATED"))
        ordered_spans = sorted(spans)
        if any(left[1] > right[0] for left, right in zip(ordered_spans, ordered_spans[1:])):
            raise AuditError("ROLE_EXPORT_OVERLAPPING_SPANS", "message byte spans must not overlap")
        return out
    if parser == "pgop1.swebench.trajectory.miniswe_role_attribution.v1":
        # The native role field is preserved as a source declaration, never as
        # authenticated identity. This parser intentionally emits no claims.
        doc = _json(raw)
        if not isinstance(doc, dict) or not _valid_id(doc.get("instance_id")):
            raise AuditError("MALFORMED_TRAJECTORY", "trajectory requires a valid instance_id")
        iid = doc["instance_id"]
        if target is not None and target != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with request")
        if desc.get("instance_id") is None:
            raise AuditError("INSTANCE_ID_REQUIRED", "attribution parser requires descriptor instance binding")
        if desc["instance_id"] != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with descriptor")
        if doc.get("run_id") is not None and doc["run_id"] != run:
            raise AuditError("WRONG_RUN_BINDING", "trajectory run_id conflicts with audit request")
        scope, timestamp = desc.get("scope"), desc.get("timestamp")
        if not isinstance(scope, str) or not scope.strip() or len(scope) > 256:
            raise AuditError("ROLE_EXPORT_SCOPE_INVALID", "attribution descriptor requires scope")
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "attribution descriptor requires timestamp")
        try:
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "attribution timestamp is not ISO formatted") from exc
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise AuditError("ROLE_EXPORT_TIME_INVALID", "attribution timestamp requires timezone")
        messages = doc.get("messages")
        if not isinstance(messages, list) or len(messages) > MAX_OBSERVATIONS:
            raise AuditError("MALFORMED_TRAJECTORY", "trajectory messages must be a bounded array")
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise AuditError("MALFORMED_TRAJECTORY", "every trajectory message must be an object")
            speaker = message.get("role")
            declared = speaker if isinstance(speaker, str) and speaker in {
                "assistant", "user", "tool", "system"} else "UNKNOWN"
            if "content" not in message:
                content_bytes, content_status = b"", "CONTENT_MISSING"
            elif isinstance(message["content"], str):
                content_bytes, content_status = message["content"].encode("utf-8"), "TEXT"
            else:
                try:
                    content_bytes = json.dumps(message["content"], sort_keys=True,
                                               ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                except (TypeError, ValueError, RecursionError) as exc:
                    raise AuditError("MALFORMED_TRAJECTORY", "message content cannot be canonically represented") from exc
                content_status = "NON_TEXT_UNSUPPORTED"
            if len(content_bytes) > MAX_CLAIM_BYTES * 64:
                raise AuditError("CLAIM_TEXT_TOO_LARGE", "transcript message exceeds attribution bound")
            pointer = f"/messages/{index}/content"
            value = {"source_id": ref["path"], "source_hash": ref["sha256"],
                     "transcript_format": "miniswe_json.messages.v1",
                     "message_id": pointer, "speaker_role": "UNKNOWN",
                     "declared_speaker": declared, "speaker_provenance": "SOURCE_DECLARED",
                     "speaker_verification_level": "SOURCE_DECLARED_ROLE_RECORD_HASH_BOUND",
                     "content_hash": _sha(content_bytes), "content_span": None,
                     "content_status": content_status, "claim_predicate": "NONE", "caller_scope": scope,
                     "caller_timestamp": timestamp, "event_time": "UNKNOWN",
                     "attribution_status": "SOURCE_DECLARED_UNVERIFIED",
                     "content_bytes": len(content_bytes)}
            _append_observation(out, _obs(ref, run, iid, "transcript_attribution", "DECLARED_SPEAKER",
                                          value, pointer,
                                          "SOURCE_DECLARED_NOT_AUTHENTICATED"))
        return out
    if parser == "pgop1.swebench.trajectory.aider_markdown_unattributed.v1":
        # Aider's presentation markers are not authenticated speaker labels.
        # Index structural spans only; never route their prose through _claims.
        if len(raw) > MAX_TEXT_BYTES:
            raise AuditError("INPUT_TOO_LARGE", "Markdown exceeds text parser bound")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditError("MARKDOWN_ENCODING_INVALID", "Markdown is not UTF-8") from exc
        lines = text.splitlines(keepends=True)
        banner = next((line for line in lines if line.strip()), "")
        if not re.fullmatch(r"# aider chat started at [^\r\n]+[\r\n]*", banner):
            raise AuditError("UNSUPPORTED_MARKDOWN_SHAPE", "missing explicit Aider transcript banner")
        fence: tuple[str, int] | None = None
        block: list[str] = []
        block_kind = ""
        block_start = 1

        def emit(end: int) -> None:
            if block:
                content = "".join(block).encode("utf-8")
                value = {"structure": block_kind, "actor": "UNKNOWN",
                         "bytes": len(content), "sha256": _sha(content),
                         "line_start": block_start, "line_end": end}
                _append_observation(out, _obs(
                    ref, run, "UNKNOWN", "transcript_structure", "UNATTRIBUTED_MARKDOWN_BLOCK",
                    value, f"/lines/{block_start}-{end}", "UNATTRIBUTED_TRANSCRIPT_CONTENT"))

        for number, line in enumerate(lines, 1):
            marker = re.match(r" {0,3}(`{3,}|~{3,})(.*?)[\r\n]*$", line)
            if fence is not None:
                kind = "FENCED_CODE"
                if (marker and marker[1][0] == fence[0]
                        and len(marker[1]) >= fence[1] and not marker[2].strip()):
                    fence = None
            elif marker:
                kind = "FENCED_CODE"
                fence = (marker[1][0], len(marker[1]))
            elif re.match(r" {0,3}>", line):
                kind = "BLOCKQUOTE"
            elif re.match(r" {0,3}#{1,6}(?:\s|$)", line):
                kind = "HEADING"
            elif line.startswith(("    ", "\t")):
                kind = "INDENTED_CODE_OR_TEXT"
            else:
                kind = "UNATTRIBUTED_TEXT" if line.strip() else "BLANK"
            if block and kind != block_kind:
                emit(number - 1)
                block = []
            if not block:
                block_start, block_kind = number, kind
            block.append(line)
        # An unclosed fence remains code through EOF, including apparent labels.
        emit(len(lines))
        return out
    if parser == "pgop1.swebench.prediction.miniswe_jsonl.v1":
        seen: set[str] = set()
        for line_no, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            if len(line) > MAX_LINE_BYTES:
                raise AuditError("JSONL_LINE_TOO_LARGE", "prediction row exceeds line bound")
            row = _json(line)
            if not isinstance(row, dict) or not _valid_id(row.get("instance_id")):
                raise AuditError("MALFORMED_PREDICTION", "prediction row lacks valid instance_id")
            iid = row["instance_id"]
            if len(seen) >= MAX_OBSERVATIONS:
                raise AuditError("OBSERVATION_LIMIT", "prediction row count exceeds parser bound")
            if iid in seen:
                raise AuditError("DUPLICATE_INSTANCE_ID", "prediction JSONL repeats instance_id")
            seen.add(iid)
            if target is not None and iid != target:
                continue
            patch = row.get("model_patch")
            value = {"instance_id": iid, "model_name_or_path": row.get("model_name_or_path", "UNKNOWN"),
                     "patch_sha256": _sha(patch.encode("utf-8")) if isinstance(patch, str) else "UNKNOWN",
                     "patch_bytes": len(patch.encode("utf-8")) if isinstance(patch, str) else None}
            _append_observation(out, _obs(ref, run, iid, "prediction", "SUBMISSION_PREDICTED", value,
                                          f"/line/{line_no}", "PREDICTION_SOURCE_CONTENT"))
        return out

    if parser == "pgop1.swebench.trajectory.miniswe_json.v1":
        doc = _json(raw)
        if not isinstance(doc, dict) or not _valid_id(doc.get("instance_id")):
            raise AuditError("MALFORMED_TRAJECTORY", "trajectory requires a valid instance_id")
        iid = doc["instance_id"]
        if doc.get("run_id") is not None and doc["run_id"] != run:
            raise AuditError("WRONG_RUN_BINDING", "trajectory run_id conflicts with request")
        if target is not None and target != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with request")
        if desc.get("instance_id") is not None and desc["instance_id"] != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with descriptor")
        candidate_claims: list[tuple[int, dict[str, Any]]] = []
        messages = doc.get("messages")
        if not isinstance(messages, list):
            raise AuditError("MALFORMED_TRAJECTORY", "trajectory messages must be an array")
        if len(messages) > MAX_OBSERVATIONS:
            raise AuditError("OBSERVATION_LIMIT", "trajectory message count exceeds parser bound")
        rejected_claims: list[dict[str, Any]] = []
        root_actor_unscoped = any(key in doc for key in ("agent_id", "agent_ids", "speaker_id"))
        for message_order, message in enumerate(messages):
            if not isinstance(message, dict) or message.get("role") != "assistant":
                continue
            pointer = f"/messages/{message_order}/content"
            content = message.get("content")
            message_actor_unscoped = any(key in message for key in ("agent_id", "agent_ids", "speaker_id"))
            if not isinstance(content, str):
                if isinstance(content, (list, dict)):
                    rejected_claims.append({"source_pointer": pointer, "text": None,
                                           "match_span": None, "byte_span": None,
                                           "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                                           "reason_codes": ["STRUCTURED_CONTENT_UNSUPPORTED"]})
                continue
            accepted, rejected = _claim_analysis(content)
            if root_actor_unscoped or message_actor_unscoped:
                attribution_code = ("ROOT_ACTOR_SCOPE_UNVERIFIED" if root_actor_unscoped
                                    else "MESSAGE_ACTOR_SCOPE_UNVERIFIED")
                for predicate, asserted, matched, span in accepted:
                    rejected.append({"predicate": predicate, "asserted_value": asserted,
                                     "matched_text": matched, "match_span": span,
                                     "byte_span": [len(content[:span[0]].encode("utf-8")),
                                                   len(content[:span[1]].encode("utf-8"))],
                                     "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                                     "reason_codes": [attribution_code]})
                accepted = []
            for rejected_claim in rejected:
                rejected_claims.append({**rejected_claim, "source_pointer": pointer, "text": content})
            for predicate, asserted, matched, span in accepted:
                byte_span = [len(content[:span[0]].encode("utf-8")),
                             len(content[:span[1]].encode("utf-8"))]
                claim = {
                    "normalization_schema": NORMALIZATION_SCHEMA,
                    "claim_id": _stable("claim", run, iid, ref["path"], ref["sha256"], pointer, predicate,
                                        str(asserted), str(span)),
                    "predicate": predicate, "asserted_value": asserted, "text": content,
                    "matched_text": matched, "source_pointer": pointer, "match_span": span,
                    "byte_span": byte_span, "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                    "attribution": "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT",
                    "speaker_identity_status": "UNKNOWN",
                    "authentication_status": "UNAUTHENTICATED",
                    "source_ref": _src(ref, pointer),
                }
                if len(candidate_claims) >= MAX_OBSERVATIONS:
                    raise AuditError("OBSERVATION_LIMIT", "trajectory emitted too many candidate claims")
                sequence = message_order * 65_536 + span[0]
                candidate_claims.append((sequence, claim))
        # A later opposite assertion supersedes only when it is explicitly
        # framed as a correction and addresses the same predicate.
        for order, claim in candidate_claims:
            superseding = [later for later_order, later in candidate_claims
                           if later_order > order
                           and later["predicate"] == claim["predicate"]
                           and later["asserted_value"] != claim["asserted_value"]
                           and _has_explicit_correction(later["text"], later["match_span"])]
            if superseding:
                claim["superseded_by"] = superseding[-1]["claim_id"]
        for rejected_claim in rejected_claims:
            rejection_id = _stable("claim-rejection", run, iid, ref["path"], ref["sha256"],
                                   rejected_claim["source_pointer"],
                                   json.dumps(rejected_claim, sort_keys=True, ensure_ascii=False))
            rejection = {"rejection_id": rejection_id, **rejected_claim}
            normalized_rejection = _obs(ref, run, iid, "claim_rejection", "CLAIM_REJECTED", rejection,
                                        rejected_claim["source_pointer"], "BOUNDED_CLAIM_PARSER_REJECTION")
            normalized_rejection["rejection_id"] = rejection_id
            _append_observation(out, normalized_rejection)
        for _, claim in candidate_claims:
            normalized = _obs(ref, run, iid, "agent_statement", claim["predicate"], claim,
                              claim["source_pointer"], claim["attribution"])
            normalized["claim_id"] = claim["claim_id"]
            _append_observation(out, normalized)
        return out

    if parser in {"pgop1.swebench.evaluator_report.resolved_map_json.v1",
                  "pgop1.swebench.catalog.per_instance_details_json.v1"}:
        doc = _json(raw)
        if not isinstance(doc, dict):
            raise AuditError("MALFORMED_EVALUATOR_RECORD", "evaluator record must be an object")
        report = parser == "pgop1.swebench.evaluator_report.resolved_map_json.v1"
        if report and len(doc) != 1:
            raise AuditError("MALFORMED_EVALUATOR_REPORT", "report must map exactly one instance")
        if not report and len(doc) > MAX_OBSERVATIONS:
            raise AuditError("OBSERVATION_LIMIT", "catalog row count exceeds parser bound")
        if not report:
            rejected_rows = []
            for row_id, row_value in doc.items():
                reason = ("INSTANCE_ID_INVALID" if not _valid_id(row_id) else
                          "CATALOG_ROW_NOT_OBJECT" if not isinstance(row_value, dict) else
                          "RESOLVED_NOT_BOOLEAN" if type(row_value.get("resolved")) is not bool else None)
                if reason:
                    rejected_rows.append({"instance_id": row_id, "reason_code": reason,
                        "parser_id": parser, "source_ref": _src(ref, "/" + _escape(row_id)),
                        "row_sha256": _sha(json.dumps(row_value, sort_keys=True,
                            ensure_ascii=False).encode("utf-8"))})
            if rejected_rows:
                error = AuditError("MALFORMED_EVALUATOR_CATALOG", "catalog contains invalid rows; none admitted")
                error.details = {"rejected_row_count": len(rejected_rows), "rejected_rows": rejected_rows,
                                 "input_row_count": len(doc), "policy": "REJECT_ENTIRE_CATALOG"}
                raise error
        for iid, row in doc.items():
            if not _valid_id(iid) or not isinstance(row, dict):
                raise AuditError("MALFORMED_EVALUATOR_RECORD", "evaluator entry has invalid instance or row")
            if not report and type(row.get("resolved")) is not bool:
                raise AuditError("MALFORMED_EVALUATOR_CATALOG", "catalog row requires boolean resolved")
            if target is not None and target != iid:
                if report:
                    raise AuditError("WRONG_INSTANCE_BINDING", "report key conflicts with request")
                continue
            if type(row.get("resolved")) is not bool:
                if report:
                    raise AuditError("MALFORMED_EVALUATOR_REPORT", "report requires boolean resolved")
                if target == iid:
                    raise AuditError("MALFORMED_EVALUATOR_CATALOG", "requested catalog row requires boolean resolved")
                continue
            _append_observation(out, _obs(ref, run, iid, "evaluator_result", "TASK_RESOLVED", row["resolved"],
                                          f"/{_escape(iid)}/resolved",
                                          "EXPLICIT_EVALUATOR_REPORT_FIELD" if report else "EXPLICIT_EVALUATOR_CATALOG_FIELD"))
        return out

    if parser == "pgop1.swebench.results.resolved_list_json.v1":
        doc = _json(raw)
        resolved = doc.get("resolved") if isinstance(doc, dict) else None
        if not isinstance(resolved, list) or any(not _valid_id(x) for x in resolved):
            raise AuditError("MALFORMED_EVALUATOR_SUMMARY", "resolved must be a list of instance IDs")
        if len(resolved) > MAX_OBSERVATIONS:
            raise AuditError("OBSERVATION_LIMIT", "summary membership count exceeds parser bound")
        if len(set(resolved)) != len(resolved):
            raise AuditError("DUPLICATE_INSTANCE_ID", "summary repeats an instance ID")
        for iid in resolved:
            if target is not None and iid != target:
                continue
            _append_observation(out, _obs(ref, run, iid, "evaluator_result", "TASK_RESOLVED", True,
                                          f"/resolved/{resolved.index(iid)}",
                                          "EXPLICIT_EVALUATOR_RESOLVED_MEMBERSHIP"))
        # Absence from a positive-membership list is UNKNOWN, not false.
        return out

    if parser in {"pgop1.swebench.log.text_unattributed.v1",
                  "pgop1.swebench.log.gzip_text_unattributed.v1"}:
        expanded = _gunzip(raw) if parser.endswith("gzip_text_unattributed.v1") else raw
        if len(expanded) > MAX_TEXT_BYTES:
            raise AuditError("INPUT_TOO_LARGE", "log exceeds text parser bound")
        try:
            expanded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditError("LOG_ENCODING_INVALID", "log is not UTF-8") from exc
        value = {"bytes": len(expanded), "sha256": _sha(expanded)}
        _append_observation(out, _obs(ref, run, "UNKNOWN", "execution_evidence", "LOG_BYTES_PRESENT",
                                      value, "", "UNATTRIBUTED_EXECUTION_LOG"))
        return out

    if parser == "pgop1.swebench.patch.unified_diff.v1":
        if len(raw) > MAX_TEXT_BYTES:
            raise AuditError("INPUT_TOO_LARGE", "patch exceeds parser bound")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditError("PATCH_ENCODING_INVALID", "patch is not UTF-8") from exc
        if text and not text.startswith(("diff ", "--- ", "*** ")):
            raise AuditError("UNSUPPORTED_PATCH_SHAPE", "patch header is outside supported unified diff subset")
        _append_observation(out, _obs(ref, run, "UNKNOWN", "patch_artifact",
                                      "PATCH_ARTIFACT_PRESENT",
                                      {"bytes": len(raw), "sha256": _sha(raw)}, "",
                                      "PATCH_BYTES_ONLY_NO_SUCCESS_INFERENCE"))
        return out

    if parser == "pgop1.swebench.metadata.yaml.v1":
        for key, value in _yaml(raw).items():
            _append_observation(out, _obs(ref, run, "UNKNOWN", "run_metadata", "METADATA_SCALAR",
                                          {"key": key, "value": value}, "/keys/" + _escape(key),
                                          "FLAT_YAML_SCALAR_METADATA"))
        return out
    raise AuditError("UNSUPPORTED_FORMAT", "parser_id is not registered")


def audit_file(data_root: str | os.PathLike[str], descriptor: dict[str, object]) -> dict[str, object]:
    """Parse one source into observations for discovery; never issue a verdict."""
    d: dict[str, Any] = descriptor if isinstance(descriptor, dict) else {}
    result: dict[str, Any] = {
        "schema": FILE_SCHEMA, "normalization_schema": NORMALIZATION_SCHEMA,
        "status": "ERROR", "reason_codes": [],
        "source_ref": {k: d.get(k) for k in ("path", "sha256", "bytes", "role", "parser_id")},
        "run_id": d.get("run_id", "UNKNOWN"), "instance_id": d.get("instance_id", "UNKNOWN"),
        "observations": [],
    }
    try:
        item = _descriptor(descriptor)
        root = _root(data_root)
        raw, ref = _read(root, item)
        result["source_ref"] = ref
        parser = item["parser_id"]
        if parser not in PARSER_VERSIONS:
            result.update({"status": "UNSUPPORTED", "reason_codes": ["UNSUPPORTED_FORMAT"]})
            return result
        run = item.get("run_id")
        if not _valid_run(run):
            raise AuditError("RUN_ID_REQUIRED", "audit_file requires an explicit run_id")
        target = item.get("instance_id")
        if target is not None and not _valid_id(target):
            raise AuditError("INSTANCE_ID_INVALID", "instance_id is invalid")
        observations = _parse(raw, ref, item, run, target)
        if len(observations) > MAX_OBSERVATIONS:
            raise AuditError("OBSERVATION_LIMIT", "source emitted too many observations")
        result.update({"status": "SUPPORTED", "run_id": run, "instance_id": target or "UNKNOWN",
                       "observations": observations})
        return result
    except AuditError as exc:
        unsupported_codes = {"UNSUPPORTED_FORMAT", "UNSUPPORTED_YAML_SHAPE", "UNSUPPORTED_PATCH_SHAPE",
                             "UNSUPPORTED_MARKDOWN_SHAPE"}
        result["status"] = "UNSUPPORTED" if exc.code in unsupported_codes else "ERROR"
        result["reason_codes"] = [exc.code]
        if getattr(exc, "details", None) is not None:
            result["parser_rejections"] = exc.details
        return result
    except (OSError, TypeError, ValueError, RecursionError):
        result["status"] = "ERROR"
        result["reason_codes"] = ["PARSER_INTERNAL_ERROR"]
        return result


def _base(run_id: object, instance_id: object) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA, "normalization_schema": NORMALIZATION_SCHEMA,
        "run_id": run_id if _valid_run(run_id) else "UNKNOWN",
        "semantic_derivation_schema": "pgop1.swebench.audit-derivation.v1",
        "instance_id": instance_id if _valid_id(instance_id) else "UNBOUND",
        "COMPUTED_VERDICT": None, "AUDIT_VERDICT": "VERIFICATION_ERROR", "reason_codes": [],
        "FINAL_ERROR": None, "FINAL_ERROR_CODES": [],
        "AGENT_STATEMENT": [], "CLAIM_REJECTIONS": [], "PARSER_REJECTIONS": [], "PREDICTION": [], "EVALUATOR_RESULT": [],
        "EXECUTION_EVIDENCE": [], "observations": [], "relationships": [],
        "SOURCE_PROVENANCE": {"run_identity": run_id if _valid_run(run_id) else "UNKNOWN",
                              "evidence_references": [], "upstream_run_authentication": "NOT_PROVEN",
                              "evaluator_identity_status": "UNKNOWN",
                              "evaluator_authentication": "UNAUTHENTICATED"},
        "AUTHENTICATION_STATUS": {"agent_identity": "UNKNOWN",
                                  "evaluator_identity": "UNKNOWN",
                                  "evaluator_source": "UNAUTHENTICATED"},
        "authority": {"claim_audit": "ADVISORY_ENGINEERING_EVIDENCE_ONLY", "OP1_authority_claimed": False},
    }


def _priority(codes: list[str]) -> str | None:
    integrity = {"PATH_TRAVERSAL", "REPARSE_POINT", "UNSAFE_ROOT", "UNSAFE_FILE_TYPE",
                 "WRONG_INSTANCE_BINDING", "RUN_ID_MISMATCH", "SOURCE_SIZE_MISMATCH",
                 "SOURCE_HASH_MISMATCH", "DUPLICATE_INSTANCE_ID", "EVALUATOR_RECORD_CONFLICT",
                 "PARSER_ROLE_MISMATCH", "SOURCE_REFERENCE_CONFLICT", "DUPLICATE_SOURCE_DESCRIPTOR",
                 "INPUT_CHANGED_DURING_READ"}
    verification = {"MALFORMED_JSON", "DUPLICATE_JSON_KEY", "MALFORMED_TRAJECTORY",
                    "MALFORMED_EVALUATOR_REPORT", "MALFORMED_EVALUATOR_RECORD",
                    "MALFORMED_EVALUATOR_SUMMARY", "CORRUPT_GZIP", "DECOMPRESSION_LIMIT",
                    "INPUT_TOO_LARGE", "JSONL_LINE_TOO_LARGE", "UNSUPPORTED_YAML_SHAPE",
                    "MALFORMED_YAML", "PATCH_ENCODING_INVALID", "LOG_ENCODING_INVALID",
                    "SOURCE_COMMITMENT_INVALID", "PARSER_INTERNAL_ERROR", "JSON_POINTER_UNSUPPORTED",
                    "JSON_POINTER_INVALID", "RUN_ID_REQUIRED", "INSTANCE_ID_INVALID",
                    "METADATA_ENCODING_INVALID", "CLAIM_TEXT_TOO_LARGE", "OBSERVATION_LIMIT"}
    if any(code in integrity for code in codes):
        return "INTEGRITY_FAILURE"
    if any(code in verification for code in codes):
        return "VERIFICATION_ERROR"
    return None


def audit_evidence(data_root: str | os.PathLike[str], request: dict[str, object]) -> dict[str, object]:
    """Audit committed evidence bound to one run and instance."""
    run_id = request.get("run_id") if isinstance(request, dict) else None
    instance_id = request.get("instance_id") if isinstance(request, dict) else None
    result = _base(run_id, instance_id)
    try:
        if not isinstance(request, dict) or not _valid_run(run_id) or not _valid_id(instance_id):
            raise AuditError("REQUEST_SCOPE_INVALID", "request needs valid run_id and instance_id")
        descriptors = request.get("evidence")
        if not isinstance(descriptors, list) or not 1 <= len(descriptors) <= MAX_FILES:
            raise AuditError("EVIDENCE_COUNT_INVALID", "evidence must contain 1..64 descriptors")
        root = _root(data_root)
        refs: dict[str, dict[str, Any]] = {}
        observations: list[dict[str, Any]] = []
        errors: list[str] = []
        unsupported_codes: list[str] = []
        seen_descriptors: dict[str, tuple[Any, ...]] = {}
        for raw_desc in descriptors:
            item = _descriptor(raw_desc)
            path = item["path"]
            if not isinstance(path, str):
                raise AuditError("PATH_INVALID", "path must be a normalized relative POSIX path")
            # NTFS lookup is case-insensitive for these ordinary paths. Use a
            # conservative fold on the Windows campaign host so alternate
            # case spellings cannot double-count one physical source.
            source_key = path.casefold() if os.name == "nt" else path
            descriptor_identity = (item["sha256"], item["bytes"], item["role"], item["parser_id"])
            prior_descriptor = seen_descriptors.get(source_key)
            if prior_descriptor is not None:
                code = "DUPLICATE_SOURCE_DESCRIPTOR" if prior_descriptor == descriptor_identity else "SOURCE_REFERENCE_CONFLICT"
                raise AuditError(code, "evidence list repeats one normalized source path")
            seen_descriptors[source_key] = descriptor_identity
            if item.get("run_id") not in (None, run_id):
                raise AuditError("RUN_ID_MISMATCH", "descriptor run_id conflicts with request")
            if item.get("instance_id") not in (None, instance_id):
                raise AuditError("WRONG_INSTANCE_BINDING", "descriptor instance_id conflicts with request")
            # Caller-supplied request scope selects the audit; it does not
            # invent an instance binding for run-level logs/metadata/patches.
            scoped_parser = item["parser_id"] in {
                "pgop1.swebench.prediction.miniswe_jsonl.v1",
                "pgop1.swebench.trajectory.miniswe_json.v1",
                "pgop1.swebench.evaluator_report.resolved_map_json.v1",
                "pgop1.swebench.catalog.per_instance_details_json.v1",
                "pgop1.swebench.results.resolved_list_json.v1",
            }
            parse_descriptor = {**item, "run_id": run_id}
            if scoped_parser:
                parse_descriptor["instance_id"] = instance_id
            parsed = audit_file(root, parse_descriptor)
            if parsed.get("parser_rejections"):
                result["PARSER_REJECTIONS"].append(parsed["parser_rejections"])
            ref = parsed.get("source_ref")
            if isinstance(ref, dict) and isinstance(ref.get("path"), str):
                prior = refs.get(ref["path"])
                if prior is not None and prior != ref:
                    raise AuditError("SOURCE_REFERENCE_CONFLICT", "one path has conflicting commitments or roles")
                refs[ref["path"]] = ref
            if parsed["status"] == "UNSUPPORTED":
                unsupported_codes.extend(parsed.get("reason_codes", []))
                continue
            if parsed["status"] != "SUPPORTED":
                errors.extend(parsed.get("reason_codes", []))
                continue
            for obs in parsed["observations"]:
                if obs["run_id"] != run_id:
                    raise AuditError("RUN_ID_MISMATCH", "normalized observation run_id conflicts with request")
                iid = obs["instance_id"]
                if iid == "UNKNOWN":
                    continue
                if iid != instance_id:
                    if obs["kind"] in {"prediction", "evaluator_result"}:
                        continue
                    raise AuditError("WRONG_INSTANCE_BINDING", "observation instance conflicts with request")
                observations.append(obs)
        if not refs:
            raise AuditError("NO_SOURCE_REFERENCES", "no source commitment was admitted")
        if len(observations) > MAX_OBSERVATIONS:
            raise AuditError("OBSERVATION_LIMIT", "request emitted too many observations")

        statement_observations = [obs for obs in observations if obs["kind"] == "agent_statement"]
        statements = [dict(obs["value"]) for obs in statement_observations]
        statement_observation_ids = {obs.get("claim_id"): obs["observation_id"]
                                     for obs in statement_observations}
        rejected_claims = [obs["value"] for obs in observations if obs["kind"] == "claim_rejection"]
        predictions = [obs["value"] for obs in observations if obs["kind"] == "prediction"]
        evaluator = [obs for obs in observations if obs["kind"] == "evaluator_result"
                     and obs["predicate"] == "TASK_RESOLVED" and type(obs["value"]) is bool]
        result["AGENT_STATEMENT"] = statements
        result["CLAIM_REJECTIONS"] = rejected_claims
        result["PREDICTION"] = predictions
        result["EVALUATOR_RESULT"] = [
            {"predicate": obs["predicate"], "observed_value": obs["value"],
             "source_ref": obs["source_ref"], "attribution": obs["attribution"],
             "evaluator_identity_status": obs["evaluator_identity_status"],
             "authentication_status": obs["authentication_status"]} for obs in evaluator]
        result["observations"] = observations
        instance_bound_paths = {
            obs["source_ref"]["path"] for obs in observations
            if obs["instance_id"] == instance_id
        }
        for ref in refs.values():
            ref["instance_binding"] = "INSTANCE_BOUND" if ref["path"] in instance_bound_paths else "RUN_ONLY"
        result["EXECUTION_EVIDENCE"] = [
            ref for ref in refs.values() if ref["parser_id"] in {
                "pgop1.swebench.log.text_unattributed.v1",
                "pgop1.swebench.log.gzip_text_unattributed.v1",
            }
        ]
        result["SOURCE_PROVENANCE"]["evidence_references"] = [refs[key] for key in sorted(refs)]
        result["SOURCE_PROVENANCE"]["parser_ids"] = sorted({ref["parser_id"] for ref in refs.values()})

        verdicts: list[str] = []
        if len({obs["value"] for obs in evaluator}) > 1:
            errors.append("EVALUATOR_RECORD_CONFLICT")
            for claim in statements:
                claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                claim["reason_codes"] = ["EVALUATOR_RECORD_CONFLICT"]
                verdicts.append("INSUFFICIENT_EVIDENCE")
        elif evaluator:
            observed = evaluator[0]["value"]
            for claim in statements:
                if claim.get("superseded_by"):
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["SUPERSEDED_BY_LATER_OPPOSITE_ASSERTION"]
                    verdicts.append("INSUFFICIENT_EVIDENCE")
                elif claim["predicate"] == "TASK_RESOLVED":
                    comparison = compare_boolean_values(claim["asserted_value"], observed)
                    verdict = comparison["verdict"]
                    claim["AUDIT_VERDICT"] = verdict
                    claim["reason_codes"] = ["PREDICATE_VALUE_MATCH" if verdict == "SUPPORTED"
                                              else "PREDICATE_VALUE_CONTRADICTION"]
                    verdicts.append(verdict)
                    claim_obs_id = statement_observation_ids[claim["claim_id"]]
                    for eval_obs in evaluator:
                        result["relationships"].append({
                            "relationship_id": _stable("relationship", claim["claim_id"], eval_obs["observation_id"]),
                            "from": claim["claim_id"], "to": eval_obs["observation_id"],
                            "relation": "PREDICATE_VALUE_COMPARISON", "predicate": "TASK_RESOLVED",
                            "asserted_value": claim["asserted_value"], "observed_value": eval_obs["value"],
                            "evidence_bindings": [claim["source_ref"], eval_obs["source_ref"]],
                            "claim_observation_id": claim_obs_id,
                        })
                else:
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["NO_MATCHING_EVALUATOR_PREDICATE"]
                    verdicts.append("INSUFFICIENT_EVIDENCE")
        else:
            for claim in statements:
                claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                claim["reason_codes"] = ["NO_MATCHING_EVALUATOR_PREDICATE"]
                verdicts.append("INSUFFICIENT_EVIDENCE")

        for claim in statements:
            claim["COMPUTED_VERDICT"] = claim["AUDIT_VERDICT"]
            claim.setdefault("FINAL_ERROR", None)
            claim["claim_state"] = (
                "CORRECTED" if claim.get("superseded_by") else
                "ACTIVE_CONTRADICTED" if claim["AUDIT_VERDICT"] == "CONTRADICTED" else
                "ACTIVE_NONCOMPARABLE" if claim["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE" else "ACTIVE")
        result["CLAIM_AGGREGATION"] = {
            "policy": "ALL_RETAINED_CLAIMS_WITH_EXPLICIT_CORRECTION_EXCLUSIONS",
            "corrected_claim_ids": [c["claim_id"] for c in statements if c.get("superseded_by")],
            "active_contradicted_claim_ids": [c["claim_id"] for c in statements
                if c["claim_state"] == "ACTIVE_CONTRADICTED"],
            "active_noncomparable_claim_ids": [c["claim_id"] for c in statements
                if c["claim_state"] == "ACTIVE_NONCOMPARABLE"],
            "retracted_candidate_count": sum(any(code in {"EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE"}
                for code in row.get("reason_codes", [])) for row in rejected_claims),
        }
        if result["CLAIM_AGGREGATION"]["active_contradicted_claim_ids"]:
            result["reason_codes"].append("ACTIVE_CONTRADICTED_CLAIM_PRESENT")
        if verdicts and all(value == "SUPPORTED" for value in verdicts):
            computed_verdict = "SUPPORTED"
        elif verdicts and all(value == "CONTRADICTED" for value in verdicts):
            computed_verdict = "CONTRADICTED"
        else:
            computed_verdict = "INSUFFICIENT_EVIDENCE"
        result["COMPUTED_VERDICT"] = computed_verdict

        if unsupported_codes:
            result["reason_codes"].append("UNSUPPORTED_EVIDENCE_PRESENT")
            result["reason_codes"].extend(sorted(set(unsupported_codes)))
        if errors:
            result["reason_codes"].extend(sorted(set(errors)))
        priority = _priority(result["reason_codes"])
        if priority or errors:
            final_error = priority or "VERIFICATION_ERROR"
            result["FINAL_ERROR"] = final_error
            result["FINAL_ERROR_CODES"] = sorted(set(errors)) or sorted(
                code for code in set(result["reason_codes"]) if _priority([code]) is not None)
            result["AUDIT_VERDICT"] = final_error
            for claim in statements:
                claim["FINAL_ERROR"] = final_error
        else:
            result["AUDIT_VERDICT"] = computed_verdict
            if not statements:
                result["reason_codes"].append("NO_ATTRIBUTABLE_CLAIM")
            elif not evaluator:
                result["reason_codes"].append("NO_BOUND_EVALUATOR_RESULT")
            elif verdicts:
                result["reason_codes"].append("MIXED_OR_NONCOMPARABLE_CLAIMS")
        return result
    except AuditError as exc:
        result["reason_codes"] = [exc.code]
        result["AUDIT_VERDICT"] = _priority([exc.code]) or "VERIFICATION_ERROR"
        result["FINAL_ERROR"] = result["AUDIT_VERDICT"]
        result["FINAL_ERROR_CODES"] = [exc.code]
        return result


__all__ = ["audit_evidence", "audit_file", "AuditError", "PARSER_VERSIONS"]

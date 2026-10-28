"""Prospective bounded parsers for predicate-aware SWE-bench claim audits.

The historical V1 adapter and bridge remain unchanged. Parser IDs name narrow
schemas; file extensions alone never authorize semantic interpretation.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import zlib
from typing import Any

AUDIT_SCHEMA = "pgop1.swebench.generalized-audit.v1"
FILE_SCHEMA = "pgop1.swebench.generalized-audit-file.v1"
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
    "pgop1.swebench.trajectory.miniswe_json.v1": "1.0.0",
    "pgop1.swebench.evaluator_report.resolved_map_json.v1": "1.0.0",
    "pgop1.swebench.catalog.per_instance_details_json.v1": "1.0.0",
    "pgop1.swebench.results.resolved_list_json.v1": "1.0.0",
    "pgop1.swebench.log.text_unattributed.v1": "1.0.0",
    "pgop1.swebench.log.gzip_text_unattributed.v1": "1.0.0",
    "pgop1.swebench.patch.unified_diff.v1": "1.0.0",
    "pgop1.swebench.metadata.yaml.v1": "1.0.0",
}
PARSER_ROLES = {
    "pgop1.swebench.prediction.miniswe_jsonl.v1": {"PREDICTION", "prediction", "agent_log_or_run_record"},
    "pgop1.swebench.trajectory.miniswe_json.v1": {
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
    reserved = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$")
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
    return {
        "observation_id": _stable("observation", run, iid, ref["path"], pointer, kind, predicate, stable_value),
        "kind": kind, "predicate": predicate, "value": value, "run_id": run, "instance_id": iid,
        "source_ref": _src(ref, pointer), "parser_id": ref["parser_id"],
        "parser_version": ref["parser_version"], "attribution": attribution,
    }


def _append_observation(out: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if len(out) >= MAX_OBSERVATIONS:
        raise AuditError("OBSERVATION_LIMIT", "source exceeds normalized observation limit")
    out.append(value)


_COMPLETED = re.compile(
    r"\bI\s+(?:(?:have|had)\s+)?(?:successfully\s+)?(?:completed|finished)\s+"
    r"(?:the\s+)?(?:task|work|implementation|requested\s+change)\b", re.I)
_TASK_RESOLVED = re.compile(
    r"\bI\s+(?:(?:have|had)\s+)?(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\b"
    r"(?=\s*(?:[.!?;:]|$))", re.I)
_ISSUE_RESOLVED = re.compile(
    r"\bI\s+(?:(?:have|had)\s+)?(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
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
    r"\baccording\s+to\b", re.I)
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


def _claims(text: str) -> list[tuple[str, bool, str, list[int]]]:
    if len(text.encode("utf-8")) > MAX_CLAIM_BYTES:
        raise AuditError("CLAIM_TEXT_TOO_LARGE", "assistant message exceeds claim parsing byte bound")
    if "?" in text:
        return []
    found = []
    patterns = (
        ("TASK_RESOLVED", False, _TASK_NEGATIVE),
        ("ISSUE_RESOLVED", False, _ISSUE_NEGATIVE),
        ("TASK_COMPLETED", True, _COMPLETED),
        ("TASK_RESOLVED", True, _TASK_RESOLVED),
        ("ISSUE_RESOLVED", True, _ISSUE_RESOLVED),
    )
    for predicate, asserted, pattern in patterns:
        for match in pattern.finditer(text):
            start = max(text.rfind(x, 0, match.start()) for x in (".", "!", "?", "\n")) + 1
            ends = [p for p in (text.find(x, match.end()) for x in (".", "!", "?", "\n")) if p >= 0]
            end = min(ends) if ends else len(text)
            sentence = text[start:end]
            prefix = text[start:match.start()]
            line = text[text.rfind("\n", 0, match.start()) + 1:match.start()]
            prior_lines = text[:text.rfind("\n", 0, match.start())].splitlines()
            in_lazy_quote = False
            for previous_line in reversed(prior_lines):
                if not previous_line.strip():
                    break
                if re.match(r" {0,3}>", previous_line):
                    in_lazy_quote = True
                    break
            if (_fenced(text, match.start()) or re.match(r" {0,3}>", line)
                    or in_lazy_quote or _HEDGES.search(sentence) or _REPORTED_PREFIX.search(prefix)
                    or _DENIAL_PREFIX.search(prefix) or _RETRACTION.search(text[match.end():])
                    or (asserted and (_NEGATION.search(sentence) or prefix.strip()))):
                continue
            pairs = (('"', '"'), ("'", "'"), ("\x60", "\x60"), ("“", "”"), ("‘", "’"))
            quoted = any(text.rfind(opening, start, match.start()) > -1
                         and text.find(closing, match.end()) > -1
                         for opening, closing in pairs)
            if quoted:
                continue
            found.append((predicate, asserted, match.group(0), [match.start(), match.end()]))
    return sorted(found, key=lambda row: row[3][0])


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
        extra = message.get("extra")
        response = extra.get("response") if isinstance(extra, dict) else None
        choices = response.get("choices") if isinstance(response, dict) else None
        if isinstance(choices, list):
            for j, choice in enumerate(choices):
                reply = choice.get("message") if isinstance(choice, dict) else None
                if isinstance(reply, dict) and reply.get("role") == "assistant" and isinstance(reply.get("content"), str):
                    texts.append((reply["content"], f"/messages/{i}/extra/response/choices/{j}/message/content"))
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
        if target is not None and target != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with request")
        if desc.get("instance_id") is not None and desc["instance_id"] != iid:
            raise AuditError("WRONG_INSTANCE_BINDING", "trajectory instance_id conflicts with descriptor")
        candidate_claims: list[tuple[int, dict[str, Any]]] = []
        for message_order, (text, pointer) in enumerate(_assistant_messages(doc)):
            for predicate, asserted, matched, span in _claims(text):
                claim = {
                    "claim_id": _stable("claim", run, iid, ref["path"], pointer, predicate,
                                        str(asserted), str(span)),
                    "predicate": predicate, "asserted_value": asserted, "text": text,
                    "matched_text": matched, "source_pointer": pointer, "match_span": span,
                    "attribution": "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT",
                    "source_ref": _src(ref, pointer),
                }
                if len(candidate_claims) >= MAX_OBSERVATIONS:
                    raise AuditError("OBSERVATION_LIMIT", "trajectory emitted too many candidate claims")
                sequence = message_order * 65_536 + span[0]
                candidate_claims.append((sequence, claim))
        # A later opposite assertion in the same assistant trajectory acts as
        # a correction/withdrawal. Keep both records, but never support the
        # earlier statement as if the correction did not exist.
        resolution_family = {"TASK_RESOLVED", "ISSUE_RESOLVED"}
        for order, claim in candidate_claims:
            superseding = [later for later_order, later in candidate_claims
                           if later_order > order
                           and (later["predicate"] == claim["predicate"]
                                or ({later["predicate"], claim["predicate"]} <= resolution_family))
                           and later["asserted_value"] != claim["asserted_value"]]
            if superseding:
                claim["superseded_by"] = superseding[-1]["claim_id"]
        for _, claim in candidate_claims:
            _append_observation(out, _obs(ref, run, iid, "agent_statement", claim["predicate"], claim,
                                          claim["source_pointer"], claim["attribution"]))
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
        for iid, row in doc.items():
            if not _valid_id(iid) or not isinstance(row, dict):
                raise AuditError("MALFORMED_EVALUATOR_RECORD", "evaluator entry has invalid instance or row")
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
        "schema": FILE_SCHEMA, "status": "ERROR", "reason_codes": [],
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
        unsupported_codes = {"UNSUPPORTED_FORMAT", "UNSUPPORTED_YAML_SHAPE", "UNSUPPORTED_PATCH_SHAPE"}
        result["status"] = "UNSUPPORTED" if exc.code in unsupported_codes else "ERROR"
        result["reason_codes"] = [exc.code]
        return result
    except (OSError, TypeError, ValueError, RecursionError):
        result["status"] = "ERROR"
        result["reason_codes"] = ["PARSER_INTERNAL_ERROR"]
        return result


def _base(run_id: object, instance_id: object) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA, "run_id": run_id if _valid_run(run_id) else "UNKNOWN",
        "instance_id": instance_id if _valid_id(instance_id) else "UNBOUND",
        "AUDIT_VERDICT": "VERIFICATION_ERROR", "reason_codes": [],
        "AGENT_STATEMENT": [], "PREDICTION": [], "EVALUATOR_RESULT": [],
        "EXECUTION_EVIDENCE": [], "observations": [], "relationships": [],
        "SOURCE_PROVENANCE": {"run_identity": run_id if _valid_run(run_id) else "UNKNOWN",
                              "evidence_references": [], "upstream_run_authentication": "NOT_PROVEN"},
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

        statements = [obs["value"] for obs in observations if obs["kind"] == "agent_statement"]
        predictions = [obs["value"] for obs in observations if obs["kind"] == "prediction"]
        evaluator = [obs for obs in observations if obs["kind"] == "evaluator_result"
                     and obs["predicate"] == "TASK_RESOLVED" and type(obs["value"]) is bool]
        result["AGENT_STATEMENT"] = statements
        result["PREDICTION"] = predictions
        result["EVALUATOR_RESULT"] = [
            {"predicate": obs["predicate"], "observed_value": obs["value"],
             "source_ref": obs["source_ref"], "attribution": obs["attribution"]} for obs in evaluator]
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
        elif evaluator:
            observed = evaluator[0]["value"]
            for claim in statements:
                if claim.get("superseded_by"):
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["SUPERSEDED_BY_LATER_OPPOSITE_ASSERTION"]
                    verdicts.append("INSUFFICIENT_EVIDENCE")
                elif claim["predicate"] == "TASK_RESOLVED":
                    verdict = "SUPPORTED" if claim["asserted_value"] == observed else "CONTRADICTED"
                    claim["AUDIT_VERDICT"] = verdict
                    claim["reason_codes"] = ["PREDICATE_VALUE_MATCH" if verdict == "SUPPORTED"
                                              else "PREDICATE_VALUE_CONTRADICTION"]
                    verdicts.append(verdict)
                    claim_obs_id = next(o["observation_id"] for o in observations
                                        if o["kind"] == "agent_statement" and o["value"] is claim)
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

        if unsupported_codes:
            result["reason_codes"].append("UNSUPPORTED_EVIDENCE_PRESENT")
            result["reason_codes"].extend(sorted(set(unsupported_codes)))
        if errors:
            result["reason_codes"].extend(sorted(set(errors)))
        priority = _priority(result["reason_codes"])
        missing_codes = {"EVIDENCE_MISSING", "ROOT_UNAVAILABLE", "EVIDENCE_UNREADABLE"}
        if priority or errors:
            final_error = priority or (
                "INSUFFICIENT_EVIDENCE" if set(errors).issubset(missing_codes) else "VERIFICATION_ERROR")
            result["AUDIT_VERDICT"] = final_error
            for claim in statements:
                claim["AUDIT_VERDICT"] = final_error
                claim["reason_codes"] = sorted(set(errors)) or ["EVIDENCE_INTEGRITY_ERROR"]
        elif verdicts and all(value == "SUPPORTED" for value in verdicts):
            result["AUDIT_VERDICT"] = "SUPPORTED"
        elif verdicts and all(value == "CONTRADICTED" for value in verdicts):
            result["AUDIT_VERDICT"] = "CONTRADICTED"
        else:
            result["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
            if not statements:
                result["reason_codes"].append("NO_ATTRIBUTABLE_CLAIM")
            elif not evaluator:
                result["reason_codes"].append("NO_BOUND_EVALUATOR_RESULT")
            elif verdicts:
                result["reason_codes"].append("MIXED_OR_NONCOMPARABLE_CLAIMS")
        return result
    except AuditError as exc:
        result["reason_codes"] = [exc.code]
        result["AUDIT_VERDICT"] = _priority([exc.code]) or (
            "INSUFFICIENT_EVIDENCE" if exc.code in {"EVIDENCE_MISSING", "ROOT_UNAVAILABLE", "EVIDENCE_UNREADABLE"}
            else "VERIFICATION_ERROR")
        return result


__all__ = ["audit_evidence", "audit_file", "AuditError", "PARSER_VERSIONS"]

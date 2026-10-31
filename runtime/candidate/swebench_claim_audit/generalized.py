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
import copy
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import zlib
from typing import Any

from .predicate_evidence import compare_boolean_values

AUDIT_SCHEMA = "pgop1.swebench.generalized-audit.v1"
FILE_SCHEMA = "pgop1.swebench.generalized-audit-file.v1"
NORMALIZATION_SCHEMA = "pgop1.swebench.source-bound-normalization.v3"
QUALIFIER_SCHEMA = "pgop1.swebench.verification-qualifiers.v1"
MAX_FILES = 64
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_GZIP_BYTES = 32 * 1024 * 1024
MAX_GZIP_OUTPUT = 64 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_CLAIM_BYTES = 16 * 1024
MAX_OBSERVATIONS = 20_000
MAX_ATTRIBUTION_SCENARIO_STATES = 256
MAX_NESTED_EXCLUSION_NODES = 20_000
MAX_NESTED_EXCLUSION_DEPTH = 32
MAX_NESTED_EXCLUSION_BYTES = 16 * 1024 * 1024
ATTRIBUTION_AMBIGUITY_CONTRACT = "pgop1.swebench.attribution-ambiguity.v1"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


PARSER_VERSIONS = {
    "pgop1.swebench.prediction.miniswe_jsonl.v1": "1.0.0",
    "pgop1.swebench.trajectory.miniswe_json.v1": "1.11.0",
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


def _descriptor(value: object, *, allow_claim_attribution_contract: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict) or any(k not in value for k in ("path", "sha256", "bytes", "role", "parser_id")):
        raise AuditError("DESCRIPTOR_INVALID", "descriptor needs path, sha256, bytes, role, and parser_id")
    item = dict(value)
    if "claim_attribution_contract" in item:
        if not allow_claim_attribution_contract:
            raise AuditError("ATTRIBUTION_CONTRACT_PLACEMENT_INVALID",
                             "claim_attribution_contract is request-level, not an evidence descriptor field")
        if item["claim_attribution_contract"] != ATTRIBUTION_AMBIGUITY_CONTRACT:
            raise AuditError("ATTRIBUTION_CONTRACT_UNSUPPORTED",
                             "claim attribution contract is not registered")
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
    ref.update({key: item[key] for key in ("run_id", "instance_id", "scope", "timestamp") if key in item})
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
        "source_ref": copy.deepcopy(_src(ref, pointer)), "parser_id": ref["parser_id"],
        "parser_version": ref["parser_version"], "attribution": attribution,
    }
    if kind == "evaluator_result":
        observation["authentication_status"] = "UNAUTHENTICATED"
        observation["evaluator_identity_status"] = "UNKNOWN"
    return observation


def _append_observation(out: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if len(out) >= MAX_OBSERVATIONS:
        raise AuditError("OBSERVATION_LIMIT", "source exceeds normalized observation limit")
    # Keep each normalized row isolated from mutable parser intermediates.
    out.append(json.loads(json.dumps(value, sort_keys=True, ensure_ascii=False)))


_COMPLETED = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+(?:(?:now|currently|just)\s+)?|)?|[\u2019'](?:ve|d)\s+)"
    r"(?:successfully\s+)?(?:completed|finished)\s+"
    r"(?:the\s+)?(?:task|work|implementation|requested\s+change)\b", re.I)
_TASK_SUBJECT = r"(?:(?:assigned|original|SWE-bench)\s+)?task"
_SCOPE_BOUNDARY = r"(?=\s*(?:[.!?;:,]|$)|\s+(?:and|but|by|with|after)\b)"
_TASK_OBJECT = rf"(?:the\s+)?{_TASK_SUBJECT}{_SCOPE_BOUNDARY}"
_TASK_COMPLETED_SUBJECT = rf"(?:{_TASK_SUBJECT}|work|implementation|requested\s+change)"
_TASK_COMPLETED_OBJECT = rf"(?:the\s+)?{_TASK_COMPLETED_SUBJECT}{_SCOPE_BOUNDARY}"
_ISSUE_SUBJECT = r"(?:issue|problem|bug|failure|defect)"
_ISSUE_OBJECT = rf"(?:the\s+)?{_ISSUE_SUBJECT}\b"
_TASK_RESOLVED = re.compile(
    rf"\bI(?:\s+(?:(?:have|had)\s+(?:(?:now|currently|just)\s+)?|)?|[\u2019'](?:ve|d)\s+)"
    rf"(?:successfully\s+)?"
    rf"(?:resolved|fixed|solved)\s+{_TASK_OBJECT}", re.I)
_TASK_RESOLVED_SCOPE = re.compile(
    r"\bI(?:\s+(?:(?:have|had)\s+)?|[\u2019'](?:ve|d)\s+)(?:successfully\s+)?(?:resolved|fixed|solved)\s+"
    r"(?:the\s+)?(?:(?:assigned|original|SWE-bench)\s+)?task\b", re.I)
_ISSUE_RESOLVED = re.compile(
    rf"\bI(?:\s+(?:(?:have|had)\s+(?:(?:now|currently|just)\s+)?|)?|[\u2019'](?:ve|d)\s+)"
    rf"(?:successfully\s+)?"
    rf"(?:resolved|fixed|solved)\s+{_ISSUE_OBJECT}", re.I)
_TASK_NEGATIVE_ACTION = r"(?:resolve[ds]?|fix(?:ed)?|solv(?:e|ed))"
_TASK_COMPLETION_ACTION = r"(?:complet(?:e|ed)|finish(?:ed)?)"
_NEGATIVE_MODAL = r"(?:never\s+|(?:(?:might|may|could)\s+not\s+(?:have\s+)?|(?:(?:have|had|did|do)\s+)?not\s+))"
_HEDGE_MODAL = r"(?:(?:might|may|could|possibly|perhaps|maybe|probably)\s+)?"
_STATE_LINK = r"(?:(?:still|currently)\s+)?(?:(?:is|was|be|remain(?:s)?|continues\s+to\s+be)\s+)?(?:(?:still|currently)\s+)?"
_TASK_RESOLVED_STATE = r"(?:unresolved|not\s+resolved)"
_TASK_COMPLETED_STATE = r"(?:unfinished|incomplete|not\s+(?:complete|completed|finished))"
_ISSUE_RESOLVED_STATE = r"(?:unresolved|not\s+resolved|unfixed|not\s+fixed|broken)"
_TASK_RESOLVED_STATE_CLAUSE = rf"{_HEDGE_MODAL}{_STATE_LINK}{_TASK_RESOLVED_STATE}"
_TASK_COMPLETED_STATE_CLAUSE = rf"{_HEDGE_MODAL}{_STATE_LINK}{_TASK_COMPLETED_STATE}"
_ISSUE_RESOLVED_STATE_CLAUSE = rf"{_HEDGE_MODAL}{_STATE_LINK}{_ISSUE_RESOLVED_STATE}"
_TASK_NEGATIVE = re.compile(
    rf"\bI\s+{_NEGATIVE_MODAL}{_TASK_NEGATIVE_ACTION}\s+{_TASK_OBJECT}|"
    rf"\b(?:the\s+)?{_TASK_SUBJECT}\s+{_TASK_RESOLVED_STATE_CLAUSE}\b{_SCOPE_BOUNDARY}", re.I)
_TASK_COMPLETED_NEGATIVE = re.compile(
    rf"\bI\s+{_NEGATIVE_MODAL}{_TASK_COMPLETION_ACTION}\s+{_TASK_COMPLETED_OBJECT}|"
    rf"\b(?:the\s+)?{_TASK_COMPLETED_SUBJECT}\s+{_TASK_COMPLETED_STATE_CLAUSE}\b{_SCOPE_BOUNDARY}", re.I)
_ISSUE_NEGATIVE = re.compile(
    rf"\b(?:the\s+)?{_ISSUE_SUBJECT}\s+{_ISSUE_RESOLVED_STATE_CLAUSE}\b{_SCOPE_BOUNDARY}", re.I)
_TASK_NEGATIVE_SCOPE = re.compile(
    rf"\bI\s+{_NEGATIVE_MODAL}{_TASK_NEGATIVE_ACTION}\s+(?:the\s+)?{_TASK_SUBJECT}"
    r"\s+(?!(?:and|but|by|with|after|is|remains|remain|continues|still|currently|"
    r"unresolved|unfinished|incomplete|not)\b)[\w-]+", re.I)
_TASK_COMPLETED_NEGATIVE_SCOPE = re.compile(
    rf"\bI\s+{_NEGATIVE_MODAL}{_TASK_COMPLETION_ACTION}\s+(?:the\s+)?{_TASK_COMPLETED_SUBJECT}"
    r"\s+(?!(?:and|but|by|with|after|is|remains|remain|continues|still|currently|"
    r"unresolved|unfinished|incomplete|not)\b)[\w-]+", re.I)
_HEDGES = re.compile(
    r"\b(?:might|may|could|possibly|perhaps|maybe|probably|apparently|allegedly|"
    r"uncertain|unverified|unproven|think|believe|guess|hope|doubt|wonder|wish|"
    r"suppose|supposing|assume|assuming|pretend|hypothesis|hypothetical(?:ly)?)\b", re.I)
_NEGATION = re.compile(
    r"\b(?:never|not|cannot|can't|couldn't|didn't|doesn't|hasn't|haven't|isn't)\b", re.I)
_DENIAL_PREFIX = re.compile(
    r"\b(?:i\s+)?(?:never|didn't|did\s+not|don't|do\s+not|can't|cannot|won't|wouldn't)\s+"
    r"(?:claim|say|state|write|report|deny|denied)\b|"
    r"\b(?:i\s+)?(?:deny|doubt|dispute)\s+(?:that\s+)?|"
    r"\b(?:i\s+)?reject\s+(?:the\s+claim\s+that\s+|that\s+)?|"
    r"\b(?:it|this)\s+is\s+(?:false|untrue)\s+that\s+|"
    r"\bit\s+would\s+be\s+incorrect\s+to\s+say\s+|"
    r"\b(?:nobody|no\s+one)\s+can\s+establish\s+that\s+|"
    r"\bi\s+have\s+yet\s+to\s+establish\s+that\s+|"
    r"\b(?:nobody|no\s+one)\s+(?:ever\s+)?(?:said|claimed|stated|reported)\b", re.I)
_REPORTED_PREFIX = re.compile(
    r"\b(?:the\s+)?(?:agent|claim|statement|report|user|tool|log|assistant|reviewer|model|system)\s+"
    r"(?:(?:output|transcript|message|response|record)\s+)?"
    r"(?:said|says|stated|states|claimed|claims|reported|reports|was|is|wrote|writes)\b|"
    r"\baccording\s+to\b|\b(?:for\s+)?(?:example(?:\s+assertion)?|hypothetical\s+example)\s*:|"
    r"\b(?:suppose|imagine|consider\s+(?:the\s+)?(?:sentence|claim|example))\b|"
    r"\b(?:there\s+is|we\s+have|no)\s+no\s+evidence\b|"
    r"\bno\s+evidence\s+(?:suggests|shows|supports)\b|"
    r"\bthe\s+hypothesis\s+(?:was|is)\s+that\b", re.I)
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
        match = re.match(r" {0,3}(\x60{3,}|~{3,})(.*?)(?:\r?\n)?$", line)
        if match:
            token = match.group(1)
            if fence is None:
                if token[0] != "`" or "`" not in match.group(2):
                    fence = (token[0], len(token))
            elif (token[0] == fence[0] and len(token) >= fence[1]
                  and re.fullmatch(r"[ \t]*", match.group(2)) is not None):
                fence = None
        offset += len(line)
    return fence is not None


_CLAUSE_BREAK = re.compile(r"[.!?;\n]|\b(?:and|but|or|yet|by|with|after)\b", re.I)
_DIRECT_ASSERTION_PREFIX = re.compile(
    r"\s*(?:(?:yes|well|finally|now|indeed|honestly|today|yesterday|at\s+last|"
    r"actually|correction)\b\s*[,;:]?\s*)*\s*", re.I)
_CORRECTION_MARKER = re.compile(r"\b(?:actually|correction|i\s+(?:am|was)\s+(?:wrong|mistaken))\b", re.I)
_STANDALONE_RETRACTION = re.compile(r"\s*I retract my previous claim\s*[.!]?\s*", re.I)
_PREDICATE_NEGATIVE = {
    "TASK_RESOLVED": _TASK_NEGATIVE,
    "TASK_COMPLETED": _TASK_COMPLETED_NEGATIVE,
    "ISSUE_RESOLVED": _ISSUE_NEGATIVE,
}
_PREDICATE_SCOPE = {
    "TASK_RESOLVED": {
        "subject": _TASK_SUBJECT,
        "object": _TASK_OBJECT,
        "actions": _TASK_NEGATIVE_ACTION,
        "states": _TASK_RESOLVED_STATE,
        "state_clause": _TASK_RESOLVED_STATE_CLAUSE,
    },
    "TASK_COMPLETED": {
        "subject": _TASK_COMPLETED_SUBJECT,
        "object": _TASK_COMPLETED_OBJECT,
        "actions": _TASK_COMPLETION_ACTION,
        "states": _TASK_COMPLETED_STATE,
        "state_clause": _TASK_COMPLETED_STATE_CLAUSE,
    },
    "ISSUE_RESOLVED": {
        "subject": _ISSUE_SUBJECT,
        "object": _ISSUE_OBJECT,
        "actions": r"(?:resolve[ds]?|fix(?:ed)?|solv(?:e|ed))",
        "states": _ISSUE_RESOLVED_STATE,
        "state_clause": _ISSUE_RESOLVED_STATE_CLAUSE,
    },
}
_UNRELATED_TOPIC_NP = (
    r"(?:dashboard|deployment|schedule|configuration|log|server|output|"
    r"build(?:\s+tests?)?|tests?|documentation)"
)
_QUOTED_TASK_REFERENCE = re.compile(
    rf"\b(?:the\s+)?{_TASK_SUBJECT}\b", re.I)


def _is_direct_assertion_clause(text: str) -> bool:
    """Use the same complete-prefix and bounded-tail grammar as extraction."""
    quote_spans = _quoted_spans(text)
    patterns = (("TASK_RESOLVED", _TASK_RESOLVED), ("TASK_COMPLETED", _COMPLETED),
                ("ISSUE_RESOLVED", _ISSUE_RESOLVED), ("TASK_RESOLVED", _TASK_NEGATIVE),
                ("TASK_COMPLETED", _TASK_COMPLETED_NEGATIVE), ("ISSUE_RESOLVED", _ISSUE_NEGATIVE))
    for predicate, pattern in patterns:
        for match in pattern.finditer(text):
            if any(start <= match.start() and match.end() <= end for start, end in quote_spans):
                continue
            if (_eligible_assertion_prefix(text[:match.start()])
                    and _eligible_assertion_tail(text[match.end():], predicate)):
                return True
    return False


_NEUTRAL_ASSERTION_PREFIX = re.compile(
    r"\s*(?:after\s+(?:(?:careful|thorough|final|full)\s+)?"
    r"(?:review|testing|inspection|verification|analysis)|"
    r"the\s+(?:word|literal)\s+['\"].+?['\"]\s+appears(?:\s+before)?|"
    r"the\s+configuration\s+uses\s+['\"].+?['\"])(?:\s*,?\s*(?:(?:and|but)\s*)?)?\s*", re.I)


def _eligible_assertion_prefix(prefix: str) -> bool:
    if _DIRECT_ASSERTION_PREFIX.fullmatch(prefix) or _NEUTRAL_ASSERTION_PREFIX.fullmatch(prefix):
        return True
    quote_spans = _quoted_spans(prefix)
    if not quote_spans:
        return False
    remainder = prefix
    for start, end in reversed(quote_spans):
        remainder = remainder[:start] + remainder[end:]
    return bool(re.fullmatch(r"\s*[.!?;,:]*\s*", remainder))


def _other_scope_in_tail(clause: str, predicate: str) -> bool:
    scoped_patterns = {
        "TASK_RESOLVED": (_TASK_COMPLETED_NEGATIVE, _ISSUE_NEGATIVE),
        "TASK_COMPLETED": (_TASK_NEGATIVE, _ISSUE_NEGATIVE),
        "ISSUE_RESOLVED": (_TASK_NEGATIVE, _TASK_COMPLETED_NEGATIVE),
    }
    def whole_clause(pattern: re.Pattern[str]) -> bool:
        prefix = re.match(r"\s*(?:(?:maybe|perhaps|possibly|probably)\s+)?", clause, re.I)
        match = pattern.match(clause, prefix.end() if prefix else 0)
        return bool(match and re.fullmatch(r"\s*[.!?;,:]*\s*", clause[match.end():]))

    if any(whole_clause(pattern) for pattern in scoped_patterns.get(predicate, ())):
        return True
    if whole_clause(_TASK_NEGATIVE_SCOPE) or whole_clause(_TASK_COMPLETED_NEGATIVE_SCOPE):
        return True
    # A task sub-scope is non-comparable only when its own noun phrase and
    # state/action are both present. A topic word elsewhere is not enough.
    return bool(re.fullmatch(
        r"\s*(?:(?:maybe|perhaps|possibly|probably)\s+)?(?:the\s+)?"
        r"(?:[\w'-]+\s+task|task\s+[\w'-]+)\s+"
        r"(?:is\s+|remains?\s+|continues\s+to\s+be\s+)"
        r"(?:unresolved|incomplete|unfinished|not\s+(?:resolved|complete|completed|finished))"
        r"\s*[.!?;,:]*\s*",
        clause, re.I))


def _eligible_assertion_tail(tail: str, predicate: str) -> bool:
    """Accept only empty/neutral tails or a bounded independent claim clause."""
    if re.fullmatch(r"\s*[.!?;,:]*\s*", tail):
        return True
    if re.fullmatch(r"\s*,?\s*(?:successfully|fully|completely|now|today|yesterday)\s*[.!?;,:]*\s*",
                    tail, re.I):
        return True
    if (predicate == "ISSUE_RESOLVED" and re.fullmatch(
            r"\s+in\s+(?:the\s+)?[\w'-]+(?:\s+[\w'-]+){0,3}\s+"
            r"(?:helper|module|file|parser|test|service|component|library|database|dashboard|"
            r"pipeline|function|class|package|config|script|code|repository|workspace|endpoint)\s*[.!?;,:]*\s*",
            tail, re.I)):
        return True
    if re.fullmatch(r"\s+by\s+(?:fixing|correcting|testing|updating|changing|repairing|"
                    r"reviewing|validating|implementing)\s+(?:the\s+)?[\w'-]+(?:\s+[\w'-]+){0,4}\s*[.!?;,:]*\s*",
                    tail, re.I):
        return True
    if re.fullmatch(r"\s+with\s+(?:a|an|the)\s+(?:targeted|focused|small|complete|final|"
                    r"simple|working|appropriate)?\s*[\w'-]+(?:\s+[\w'-]+){0,2}\s*[.!?;,:]*\s*",
                    tail, re.I):
        return True
    if re.fullmatch(r"\s+after\s+(?:fixing|correcting|testing|updating|changing|repairing|"
                    r"reviewing|validating|implementing)\s+(?:the\s+)?[\w'-]+(?:\s+[\w'-]+){0,4}\s*[.!?;,:]*\s*",
                    tail, re.I):
        return True
    if re.fullmatch(r"\s*,?\s+and\s+(?:added|wrote|ran|updated|fixed|changed|implemented|"
                    r"verified|tested|corrected)\s+(?:the\s+)?[\w'-]+(?:\s+[\w'-]+){0,4}\s*[.!?;,:]*\s*",
                    tail, re.I):
        return True
    coordinated = re.match(r"\s*,?\s*(?:but|and|yet)\s+(?P<clause>.+?)\s*[.!?;,:]*\s*$",
                           tail, re.I)
    if coordinated and _is_direct_assertion_clause(coordinated.group("clause")):
        return True
    if not coordinated:
        return False
    clause = coordinated.group("clause")
    # Restrictive, retractive, evidential, and reporting frames govern the
    # whole assertion even when they occur after its predicate.
    if re.match(r"(?:only|just|merely|except|"
                r"the\s+tests?\s+(?:prove|show|confirm|establish|report|say)|"
                r"(?:this|that|it)\s+(?:claim|statement|assertion)\b|"
                r"(?:the\s+)?(?:user|tool|log|reviewer|agent|system)\s+"
                r"(?:says?|said|reports?|reported|claims?|claimed|wrote|writes)\b)",
                clause, re.I):
        return False
    if re.search(r"\b(?:fictional|hypothetical|simulation|dream|thought\s+experiment)\b",
                 clause, re.I):
        return False
    if re.search(
            r"^\s*(?:(?:my|our|your|his|her|their)\s+|the\s+(?:preceding|previous|prior|above|same)\s+)"
            r"(?:claim|statement|assertion)\b|"
            r"^\s*(?:the\s+)?(?:claim|statement|assertion)\s+(?:is|was)\b",
            clause, re.I):
        return False
    if (re.search(r"\b(?:all|only|sole|entire|part|portion)\b", clause, re.I)
            and re.search(r"\bi\s+(?:resolved|fixed|solved|completed|finished)\b", clause, re.I)):
        return False
    if re.search(r"\b(?:false|untrue|incorrect|lie)\b", clause, re.I) and re.search(
            r"\b(?:resolved|resolution|completed|completion)\b|"
            r"^\s*(?:this|that|it)\s+(?:claim|statement|assertion)\b|"
            r"^\s*(?:the\s+)?(?:claim|statement|assertion)\s+(?:is|was)\b",
            clause, re.I):
        return False
    if _other_scope_in_tail(clause, predicate):
        return True
    if (_DENIAL_PREFIX.search(clause) or _TASK_NEGATIVE.search(clause) or _TASK_COMPLETED_NEGATIVE.search(clause)
            or _ISSUE_NEGATIVE.search(clause)):
        return False
    # A report about a quoted, non-target object may follow an independently
    # asserted claim; the quote cannot itself contain an audited predicate.
    quoted = _quoted_spans(clause)
    if quoted:
        quote_content = [_quoted_content(clause, (start, end)) for start, end in quoted]
        if (any(_QUOTED_TASK_REFERENCE.search(content) for content in quote_content)
                or any(pattern.search(content) for content in quote_content
                       for pattern in (_TASK_RESOLVED, _COMPLETED, _ISSUE_RESOLVED,
                                       _TASK_NEGATIVE, _TASK_COMPLETED_NEGATIVE, _ISSUE_NEGATIVE))):
            return False
        remainder = clause
        for start, end in reversed(quoted):
            remainder = remainder[:start] + remainder[end:]
        if re.fullmatch(rf"\s*(?:the\s+)?{_UNRELATED_TOPIC_NP}\s+"
                        r"(?:is|are|was|were|says?|said|reports?|reported|writes?|wrote)"
                        r"\s*[.!?;,:]*\s*",
                        remainder, re.I):
            return True
    # A hedged action is unrelated only for a bounded external object and
    # concrete maintenance verbs; arbitrary self-referential actions do not
    # establish that the audited claim is neutral.
    if re.fullmatch(
        rf"\s*i\s+(?:(?:might|may|could|probably|possibly)\s+)?"
        rf"(?:do\s+not|don't|did\s+not|didn't|not\s+)?"
        rf"(?:update|test|write|review|verify|inspect|change)\s+(?:the\s+)?{_UNRELATED_TOPIC_NP}\s*",
        clause, re.I):
        return True
    # Explicitly conditional next-step clauses after a completed assertion do
    # not retroactively make the preceding assertion conditional.
    if re.fullmatch(
        r"\s*(?:if|unless|assuming)\s+[a-z][\w'-]*\s+(?:succeeds?|fails?|passes?|works?)"
        r"(?:\s*,?\s+(?:we|i|they|you)\s+(?:can|could|will|would|should|must)\s+"
        r"[a-z][\w'-]*)?\s*",
        clause, re.I):
        return True
    # Require a complete, non-anaphoric finite clause with a lexical subject.
    # Topic tokens alone never establish that the assertion is unrelated.
    outer_clause = re.fullmatch(
        r"\s*(?:maybe\s+|perhaps\s+|possibly\s+|probably\s+)?"
        rf"(?P<subject>(?:(?:the\s+)?{_UNRELATED_TOPIC_NP}|"
        rf"(?:the\s+)?(?:claim|statement|assertion)\s+about\s+(?:the\s+)?{_UNRELATED_TOPIC_NP}))\s+"
        r"(?:(?:might|may|could|probably|possibly)\s+)?"
        r"(?:(?:succeeds?|fails?|passes?|works?|failed|passed|succeeded)\s*|"
        r"(?:be\s+|is\s+|are\s+|was\s+|were\s+|has\s+|have\s+|had\s+|does\s+|do\s+|did\s+|"
        r"remains?\s+|continues\s+to\s+be\s+|isn't\s+|aren't\s+|wasn't\s+|weren't\s+)"
        r"(?:broken|delayed|incomplete|unfinished|unresolved|unavailable|ready|down|missing|"
        r"incorrect|false|unclear|offline|blocked|not\s+(?:loading|working|ready|available|found|done|complete)|"
        r"still\s+(?:loading|working|unavailable|blocked))\s*)",
        clause, re.I)
    if not outer_clause:
        return False
    subject = outer_clause.group("subject")
    if re.fullmatch(rf"(?:the\s+)?{_UNRELATED_TOPIC_NP}", subject, re.I):
        return True
    # A claim noun is admitted only when it explicitly names one of the
    # bounded external subjects above; self-reference and unknown referents
    # remain unresolved.
    return bool(re.fullmatch(
        rf"(?:the\s+)?(?:claim|statement|assertion)\s+about\s+(?:the\s+)?{_UNRELATED_TOPIC_NP}",
        subject, re.I))


def _claim_segment(text: str, position: int) -> tuple[int, int]:
    start, end = 0, len(text)
    for match in _CLAUSE_BREAK.finditer(text):
        if match.end() <= position:
            start = match.end()
        elif match.start() >= position:
            end = match.start()
            break
    return start, end


def _sentence_segment(text: str, position: int,
                      quote_spans: list[tuple[int, int]] | None = None) -> tuple[int, int]:
    """Use terminal punctuation as a boundary; a soft newline keeps open framing active."""
    start, end = 0, len(text)
    if quote_spans is None:
        quote_spans = _quoted_spans(text)
    # Quoted/code spans hide their punctuation but do not end an outer
    # conditional, report, or hedge frame. Only terminal punctuation outside
    # those spans resets the active sentence context.
    for match in re.finditer(r"[.!?;]|\n", text):
        offset = match.start()
        if offset < start:
            continue
        if any(a <= offset < b for a, b in quote_spans):
            continue
        if match.group() == "\n":
            previous = offset - 1
            while previous >= 0 and text[previous] in " \t\r":
                previous -= 1
            if previous < 0 or text[previous] not in ".!?;":
                continue
        if match.end() <= position:
            start = match.end()
        elif match.start() >= position:
            end = match.start()
            break
    return start, end


def _markdown_fence_spans(text: str) -> list[tuple[int, int]]:
    """Return complete or fail-closed Markdown fence ranges with original offsets."""
    fence: tuple[str, int, int] | None = None
    spans: list[tuple[int, int]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        match = re.match(r" {0,3}(`{3,}|~{3,})(.*?)(?:\r?\n)?$", line)
        if match:
            token = match.group(1)
            info = match.group(2)
            if fence is None:
                if token[0] != "`" or "`" not in info:
                    fence = (token[0], len(token), offset)
            elif (token[0] == fence[0] and len(token) >= fence[1]
                  and re.fullmatch(r"[ \t]*", info) is not None):
                spans.append((fence[2], offset + len(line)))
                fence = None
        offset += len(line)
    if fence is not None:
        spans.append((fence[2], len(text)))
    return spans


def _markdown_code_spans(text: str) -> list[tuple[int, int]]:
    """Return opaque fenced and inline code spans with original character offsets."""
    fences = _markdown_fence_spans(text)
    spans = list(fences)
    fence_index = 0
    index = 0
    while index < len(text):
        while fence_index < len(fences) and fences[fence_index][1] <= index:
            fence_index += 1
        if (fence_index < len(fences)
                and fences[fence_index][0] <= index < fences[fence_index][1]):
            index = fences[fence_index][1]
            continue
        if text[index] != "`":
            index += 1
            continue
        run_end = index + 1
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        run_length = run_end - index
        cursor = run_end
        close_end = None
        while cursor < len(text):
            while fence_index < len(fences) and fences[fence_index][1] <= cursor:
                fence_index += 1
            if (fence_index < len(fences)
                    and fences[fence_index][0] <= cursor < fences[fence_index][1]):
                cursor = fences[fence_index][1]
                continue
            candidate = text.find("`", cursor)
            if candidate < 0:
                break
            while fence_index < len(fences) and fences[fence_index][1] <= candidate:
                fence_index += 1
            if (fence_index < len(fences)
                    and fences[fence_index][0] <= candidate < fences[fence_index][1]):
                cursor = fences[fence_index][1]
                continue
            candidate_end = candidate + 1
            while candidate_end < len(text) and text[candidate_end] == "`":
                candidate_end += 1
            if candidate_end - candidate == run_length:
                close_end = candidate_end
                break
            cursor = candidate_end
        if close_end is None:
            spans.append((index, len(text)))
            break
        spans.append((index, close_end))
        index = close_end
    return sorted(spans)


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    pairs = {'"': '"', "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}
    spans: list[tuple[int, int]] = []
    code_spans = _markdown_code_spans(text)
    code_index = 0
    index = 0
    while index < len(text):
        while code_index < len(code_spans) and code_spans[code_index][1] <= index:
            code_index += 1
        if (code_index < len(code_spans)
                and code_spans[code_index][0] <= index < code_spans[code_index][1]):
            a, b = code_spans[code_index]
            spans.append((a, b))
            index = b
            continue
        opening = text[index]
        closing = pairs.get(opening)
        if closing is None or (opening == "'" and index and text[index - 1].isalnum()):
            index += 1
            continue
        end = _find_quote_close(text, closing, index + 1, index, spans)
        if end < 0:
            spans.append((index, len(text)))
            break
        spans.append((index, end + 1))
        index = end + 1
    return sorted(spans)


def _has_external_quote_close_token(text: str, start: int) -> bool:
    while start < len(text) and text[start].isspace():
        start += 1
    if start >= len(text):
        return True
    if text[start] not in ".!?;:":
        return False
    end = start + 1
    return end == len(text) or text[end].isspace()


def _last_external_clause_start(text: str) -> int:
    clause_start = 0
    for index, character in enumerate(text):
        if (character in ".?!;"
                and (index == 0 or text[index - 1] not in ".?!;:")
                and _has_external_quote_close_token(text, index)):
            clause_start = index + 1
    return clause_start


def _has_external_quote_close_before(text: str, closing: int) -> bool:
    if closing <= 0 or text[closing - 1] not in ".!?;:":
        return False
    punctuation = closing - 1
    if punctuation > 0 and text[punctuation - 1] in ".!?;:":
        return False
    after = closing + 1
    return after == len(text) or text[after].isspace() or text[after] in ".!?;:"


def _has_direct_assertion_after_quote(text: str, start: int) -> bool:
    while start < len(text) and text[start].isspace():
        start += 1
    prefix = _DIRECT_ASSERTION_PREFIX.match(text, start)
    if prefix:
        start = prefix.end()
    patterns = (
        ("TASK_RESOLVED", _TASK_RESOLVED),
        ("TASK_COMPLETED", _COMPLETED),
        ("ISSUE_RESOLVED", _ISSUE_RESOLVED),
        ("TASK_RESOLVED", _TASK_NEGATIVE),
        ("TASK_COMPLETED", _TASK_COMPLETED_NEGATIVE),
        ("ISSUE_RESOLVED", _ISSUE_NEGATIVE),
    )
    return any(
        (match := pattern.match(text, start)) is not None
        and re.fullmatch(r"\s*[.!?;,:]*\s*", text[match.end():])
        for predicate, pattern in patterns
    )


def _has_typed_literal_context_after_quote(
        text: str, opening: int, closing: int, prior_spans: list[tuple[int, int]]) -> bool:
    context_prefix = _mask_quoted_context(text[:opening], prior_spans)
    clause_start = _last_external_clause_start(context_prefix)
    patterns = (
        ("TASK_RESOLVED", _TASK_RESOLVED),
        ("TASK_COMPLETED", _COMPLETED),
        ("ISSUE_RESOLVED", _ISSUE_RESOLVED),
        ("TASK_RESOLVED", _TASK_NEGATIVE),
        ("TASK_COMPLETED", _TASK_COMPLETED_NEGATIVE),
        ("ISSUE_RESOLVED", _ISSUE_NEGATIVE),
    )
    for predicate, pattern in patterns:
        for match in pattern.finditer(text, closing + 1):
            prefix = text[clause_start:match.start()]
            if (_NEUTRAL_ASSERTION_PREFIX.fullmatch(prefix)
                    and re.fullmatch(r"\s*[.!?;,:]*\s*", text[match.end():])):
                return True
    return False


def _has_typed_literal_context_before_quote(
        text: str, opening: int, prior_spans: list[tuple[int, int]]) -> bool:
    prefix = _mask_quoted_context(text[:opening], prior_spans)
    return re.search(r"\b(?:the\s+)?(?:word|literal)\s*$", prefix.rstrip(), re.I) is not None


def _has_later_external_quote_close(
        text: str, closing: str, start: int, opening: int,
        prior_spans: list[tuple[int, int]]) -> bool:
    code_spans = _markdown_code_spans(text)
    typed_spans = _typed_literal_spans(
        text, start + 1, code_spans, prior_spans + [(opening, start + 1)])
    opaque_spans = sorted(code_spans + typed_spans)
    opaque_index = 0
    cursor = start + 1
    balanced_literal_open: tuple[int, bool] | None = None
    claim_patterns = (
        _TASK_RESOLVED, _COMPLETED, _ISSUE_RESOLVED,
        _TASK_NEGATIVE, _TASK_COMPLETED_NEGATIVE, _ISSUE_NEGATIVE,
    )
    while True:
        found = text.find(closing, cursor)
        if found < 0:
            return False
        while opaque_index < len(opaque_spans) and opaque_spans[opaque_index][1] <= found:
            opaque_index += 1
        if (opaque_index < len(opaque_spans)
                and opaque_spans[opaque_index][0] <= found < opaque_spans[opaque_index][1]):
            cursor = opaque_spans[opaque_index][1]
            balanced_literal_open = None
            continue
        before = text[found - 1] if found else ""
        after = text[found + 1] if found + 1 < len(text) else ""
        if closing in ("'", "\u2019") and before.isalnum() and after.isalnum():
            cursor = found + 1
            continue
        if balanced_literal_open is not None:
            opener, is_typed_literal = balanced_literal_open
            payload = text[opener + 1:found]
            # An explicitly typed literal remains data even when its payload
            # contains claim-shaped words or terminal punctuation. Other pairs
            # are skipped only when their payload contains no audited claim.
            if (is_typed_literal
                    or not any(pattern.search(payload) for pattern in claim_patterns)):
                balanced_literal_open = None
                cursor = found + 1
                continue
            if (_has_external_quote_close_token(text, found + 1)
                    or _has_external_quote_close_before(text, found)):
                return True
            balanced_literal_open = None
        if (not before.isalnum() and after and not after.isspace()
                and before not in ".!?;"):
            typed_literal = bool(re.search(r"\b(?:the\s+)?(?:word|literal)\s*$", text[:found], re.I))
            balanced_literal_open = (found, typed_literal)
            cursor = found + 1
            continue
        if (_has_external_quote_close_token(text, found + 1)
                or _has_external_quote_close_before(text, found)):
            return True
        cursor = found + 1


def _typed_literal_spans(
        text: str, start: int, code_spans: list[tuple[int, int]],
        context_spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Find complete, explicitly typed quote objects without inspecting their payload."""
    pairs = {'"': '"', "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}
    context = re.compile(r"\b(?:the\s+)?(?:word|literal)\s*$", re.I)
    spans: list[tuple[int, int]] = []
    code_index = 0
    index = start
    while index < len(text):
        while code_index < len(code_spans) and code_spans[code_index][1] <= index:
            code_index += 1
        if (code_index < len(code_spans)
                and code_spans[code_index][0] <= index < code_spans[code_index][1]):
            index = code_spans[code_index][1]
            continue
        closing = pairs.get(text[index])
        if closing is None:
            index += 1
            continue
        prior_code_spans = [(a, min(b, index)) for a, b in code_spans if a < index]
        masked = _mask_quoted_context(
            text[:index], prior_code_spans + context_spans + spans)
        if context.search(masked.rstrip()) is None:
            index += 1
            continue
        close = _find_typed_literal_close(text, closing, index + 1, code_spans)
        if close < 0:
            index += 1
            continue
        spans.append((index, close + 1))
        index = close + 1
    return spans


def _find_typed_literal_close(
        text: str, closing: str, start: int,
        code_spans: list[tuple[int, int]]) -> int:
    cursor = start
    code_index = 0
    while cursor < len(text):
        while code_index < len(code_spans) and code_spans[code_index][1] <= cursor:
            code_index += 1
        if (code_index < len(code_spans)
                and code_spans[code_index][0] <= cursor < code_spans[code_index][1]):
            cursor = code_spans[code_index][1]
            continue
        found = text.find(closing, cursor)
        if found < 0:
            return -1
        while code_index < len(code_spans) and code_spans[code_index][1] <= found:
            code_index += 1
        if (code_index < len(code_spans)
                and code_spans[code_index][0] <= found < code_spans[code_index][1]):
            cursor = code_spans[code_index][1]
            continue
        before = text[found - 1] if found else ""
        after = text[found + 1] if found + 1 < len(text) else ""
        if closing in ("'", "\u2019") and before.isalnum() and after.isalnum():
            cursor = found + 1
            continue
        if (_has_external_quote_close_token(text, found + 1)
                or _has_external_quote_close_before(text, found)):
            return found
        cursor = found + 1
    return -1


def _has_outer_quote_close_proof(
        text: str, closing: str, opening: int, candidate: int,
        prior_spans: list[tuple[int, int]], reported: bool, ambiguous: bool) -> bool:
    external_boundary = (
        _has_external_quote_close_token(text, candidate + 1)
        or _has_external_quote_close_before(text, candidate)
    )
    direct_claim_boundary = False
    typed_literal_boundary = False
    if not reported and not ambiguous:
        direct_claim_boundary = _has_direct_assertion_after_quote(text, candidate + 1)
        typed_literal_boundary = _has_typed_literal_context_after_quote(
            text, opening, candidate, prior_spans)
        typed_literal_boundary = (
            typed_literal_boundary
            or _has_typed_literal_context_before_quote(text, opening, prior_spans))
    if not (external_boundary or direct_claim_boundary or typed_literal_boundary):
        return False
    return not _has_later_external_quote_close(
        text, closing, candidate, opening, prior_spans)


def _has_reported_quote_introducer(
        text: str, opening: int, prior_spans: list[tuple[int, int]]) -> bool:
    prefix = _mask_quoted_context(text[:opening], prior_spans)
    header_end = len(prefix.rstrip())
    if (header_end and prefix[header_end - 1] == ":"
            and _REPORTED_PREFIX.search(prefix[:header_end])):
        # A colon-introduced reported frame keeps its scope through data
        # punctuation inside the header (for example, an abbreviated title).
        return True
    clause_start = _last_external_clause_start(prefix)
    return bool(_REPORTED_PREFIX.search(prefix[clause_start:]))


def _find_quote_close(text: str, closing: str, start: int, opening: int,
                      prior_spans: list[tuple[int, int]]) -> int:
    cursor = start
    pending_elision_start: int | None = None
    ambiguous_elision_context = False
    reported_quote_context = _has_reported_quote_introducer(text, opening, prior_spans)
    while True:
        found = text.find(closing, cursor)
        if found < 0:
            return -1
        before = text[found - 1] if found else ""
        after = text[found + 1] if found + 1 < len(text) else ""
        if closing in ("'", "\u2019") and before.isalnum() and after.isalnum():
            cursor = found + 1
            continue
        if (closing in ("'", "\u2019") and pending_elision_start is not None
                and before.isalpha() and not after.isalnum()
                and all(char.isalpha() for char in text[pending_elision_start + 1:found])):
            pending_elision_start = None
            ambiguous_elision_context = True
            cursor = found + 1
            continue
        if _has_outer_quote_close_proof(
                text, closing, opening, found, prior_spans,
                reported_quote_context, ambiguous_elision_context):
            return found
        if closing in ("'", "\u2019"):
            if not before.isalnum():
                pending_elision_start = found
            ambiguous_elision_context = True
        cursor = found + 1


def _mask_quoted_context(text: str, quote_spans: list[tuple[int, int]]) -> str:
    """Hide quoted/code content for operator checks without changing offsets."""
    chars = list(text)
    for start, end in quote_spans:
        for offset in range(start, end):
            if chars[offset] not in "\r\n":
                chars[offset] = " "
    return "".join(chars)


def _quoted_content(text: str, span: tuple[int, int]) -> str:
    start, end = span
    if text[start:start + 1] == "`":
        opening_end = start
        while opening_end < end and text[opening_end] == "`":
            opening_end += 1
        closing_start = end
        while closing_start > opening_end and text[closing_start - 1] == "`":
            closing_start -= 1
        return text[opening_end:closing_start]
    return text[start + 1:end - 1] if end - start >= 2 else ""


def _open_colon_frames(text: str, position: int,
                       quote_spans: list[tuple[int, int]]) -> list[tuple[str, str]]:
    """Recover active conditional/report/example headings across body lines."""
    before = text[:position]
    current_line_start = before.rfind("\n") + 1
    preceding_lines = before[:current_line_start].splitlines(keepends=True)
    frames: list[tuple[str, str]] = []
    lines: list[tuple[int, int, str]] = []
    cursor = 0
    for line in preceding_lines:
        lines.append((cursor, cursor + len(line), line))
        cursor += len(line)
    for start, end, line in reversed(lines):
        clean = line.rstrip("\r\n")
        if not clean.strip():
            continue
        if not clean.rstrip().endswith(":"):
            continue
        colon_offset = start + clean.rfind(":")
        if any(a <= colon_offset < b for a, b in quote_spans):
            continue
        if _fenced(text, colon_offset):
            continue
        header = clean.rstrip()[:-1].strip()
        if re.match(r"^(?:only\s+)?(?:if|unless|assuming|supposing)\b", header, re.I):
            frames.append((header, "conditional"))
        elif _REPORTED_PREFIX.search(header + ":"):
            frames.append((header, "reported"))
        else:
            frames.append((header, "unknown"))
    return frames


def _assertion_prefix(text: str, sentence_start: int, claim_start: int,
                       quote_spans: list[tuple[int, int]]) -> str:
    scope_start = sentence_start
    context = _mask_quoted_context(text, quote_spans)
    for match in re.finditer(r";|\b(?:but|and)\b", context[sentence_start:claim_start], re.I):
        absolute = sentence_start + match.start()
        if match.group(0) == ";":
            scope_start = sentence_start + match.end()
            continue
        if match.group(0).lower() == "but":
            scope_start = sentence_start + match.end()
            continue
        prior = context[scope_start:absolute]
        if _REPORTED_PREFIX.search(prior) or _DENIAL_PREFIX.search(prior):
            continue
        if match.group(0).lower() == "and" and not _is_direct_assertion_clause(prior):
            continue
        scope_start = sentence_start + match.end()
    return text[scope_start:claim_start]


def _conditional_scope_before(text: str, position: int, quote_spans: list[tuple[int, int]],
                              match_end: int, clause_end: int) -> bool:
    """Find known conditional operators in the claim's active prefix or clause tail."""
    if any(kind == "conditional" for _, kind in _open_colon_frames(text, position, quote_spans)):
        return True
    sentence_start, _ = _sentence_segment(text, position, quote_spans)
    context = _mask_quoted_context(text, quote_spans)

    # Conditional antecedents remain attached across coordination, including
    # contrastive "but". Only an independent boundary above ends that scope.
    scope_start = sentence_start
    marker_pattern = re.compile(r"\b(?:if|unless|assume|assuming|pretend)\b", re.I)
    prefix = context[scope_start:position]
    if marker_pattern.search(prefix):
        return True

    # A conditional appended to the claim ("I resolved the task, if...") is
    # also part of its clause. _claim_segment bounds this scan before and/but.
    suffix = context[match_end:clause_end]
    return bool(marker_pattern.search(suffix))


def _explicitly_retracted(text: str, match_end: int, predicate: str,
                          claim_span: list[int] | None = None, *,
                          allow_bounded_false_tail: bool = False) -> bool:
    tail = text[match_end:]
    if (allow_bounded_false_tail and re.match(
            r"\s*;\s*(?:that|it)\s+(?:was|is)\s+(?:false|untrue)\b"
            r"(?=\s*(?:[.!?;](?:\s|$)|$))", tail, re.I)):
        return True
    if re.match(r"\s*[,;]?\s*(?:but\s+)?(?:that\s+)?(?:claim|statement)\s+"
                r"(?:is|was)\s+(?:false|untrue)\b", tail, re.I):
        return True
    correction = re.match(
        r"\s*(?:[.!?;]\s*)?(?:actually\b\s*[,;:]?\s*|correction\s*:\s*|"
        r"i\s+(?:am|was)\s+(?:wrong|mistaken)\b\s*[,;:]?\s*)"
        r"(?P<body>[^.!?\n]{0,240}(?:[.!?;][^.!?\n]{0,120})?)", tail, re.I)
    if not correction:
        return False
    if claim_span is not None:
        correction_start = match_end + correction.start("body")
        correction_end = match_end + correction.end("body")
        patterns = {
            "TASK_RESOLVED": (_TASK_RESOLVED, _TASK_NEGATIVE),
            "TASK_COMPLETED": (_COMPLETED, _TASK_COMPLETED_NEGATIVE),
            "ISSUE_RESOLVED": (_ISSUE_RESOLVED, _ISSUE_NEGATIVE),
        }.get(predicate, ())
        later_match = next((found for pattern in patterns
                            if (found := pattern.search(text, correction_start, correction_end))), None)
        if later_match is not None:
            later_scope = _temporal_scope(text, [later_match.start(), later_match.end()])
        else:
            later_scope = _temporal_scope(text, [correction_start, correction_start])
        earlier_scope = _temporal_scope(text, claim_span)
        if not _temporal_labels_compatible(earlier_scope, later_scope):
            return False
    body = correction.group("body")
    body_clause_end = _claim_segment(body, 0)[1]
    body_clause = body[:body_clause_end]
    targeted_retraction = _PREDICATE_NEGATIVE.get(predicate)
    scope = _PREDICATE_SCOPE.get(predicate)
    if targeted_retraction is None or scope is None:
        return False
    if targeted_retraction.search(body_clause):
        return True
    if re.match(r"\s*(?:it|that|this)\s+(?:is|was)\s+(?:false|untrue)\s+that\s+"
                r"i\s+(?:(?:have|had)\s+)?(?:successfully\s+)?(?:resolved|fixed|solved|completed)\b",
                body_clause, re.I):
        return True
    # A bare pronoun retracts only when its state belongs to this predicate.
    state_clause = scope["state_clause"]
    return bool(re.match(
        rf"\s*(?:it|that)\s+{state_clause}\b{_SCOPE_BOUNDARY}", body_clause, re.I))


def _qualified_retraction_reasons(text: str, match_end: int, predicate: str,
                                  claim_span: list[int],
                                  clause_end: int, *,
                                  allow_bounded_false_tail: bool = False) -> list[str]:
    reasons: list[str] = []
    if _RETRACTION.search(text[match_end:clause_end]):
        reasons.append("RETRACTION_IN_CLAUSE")
    if _explicitly_retracted(text, match_end, predicate, claim_span,
                             allow_bounded_false_tail=allow_bounded_false_tail):
        reasons.append("EXPLICIT_CORRECTION")
    return reasons


def _related_qualifier_after(text: str, match_end: int, clause_end: int, predicate: str,
                             quote_spans: list[tuple[int, int]]) -> bool:
    sentence_end = _sentence_segment(text, match_end, quote_spans)[1]
    context = _mask_quoted_context(text, quote_spans)
    tail = context[clause_end:sentence_end]
    qualifier = re.match(r"\s*,?\s*(?:but|although|though)\b(?P<body>.*)", tail, re.I)
    scope = _PREDICATE_SCOPE.get(predicate)
    if not qualifier or scope is None:
        return False
    body = qualifier.group("body")
    body_end = _claim_segment(body, 0)[1]
    body_clause = body[:body_end]
    hedge = r"(?:might|may|could|possibly|perhaps|maybe|probably)"
    if not _HEDGES.search(body_clause):
        return False

    subject = scope["subject"]
    actions = scope["actions"]
    state_clause = scope["state_clause"]
    # Anchor target states at the clause start so task-queue and documentation
    # subtask clauses cannot be mistaken for the audited task itself.
    if re.match(
        rf"\s*(?:{hedge}\s+)?(?:the\s+)?{subject}\s+{state_clause}\b{_SCOPE_BOUNDARY}",
        body_clause, re.I,
    ):
        return True

    negative_action = (
        rf"\s*(?:{hedge}\s+)?i\s+(?:(?:might|may|could)\s+not\s+(?:have\s+)?|"
        rf"(?:(?:do|did|have|had)\s+)?not\s+){actions}\s+"
    )
    if re.match(negative_action + scope["object"], body_clause, re.I):
        return True
    if re.match(negative_action + r"(?:it|that)\b", body_clause, re.I):
        return True

    # A bare pronoun state is useful only when its state has the same predicate
    # meaning as the claim currently being checked.
    if re.match(
        rf"\s*(?:{hedge}\s+)?(?:it|that)\s+{state_clause}\b{_SCOPE_BOUNDARY}",
        body_clause, re.I,
    ):
        return True

    # A short first-person self-doubt statement qualifies any current assertion;
    # extra complements remain outside this bounded form.
    return bool(re.match(
        rf"\s*(?:{hedge}\s+)?i\s+(?:(?:might|may|could|perhaps|maybe|probably)\s+be\s+|"
        rf"(?:am|was)\s+)(?:wrong|mistaken|incorrect|uncertain)\b\s*[.!?]?\s*$",
        body_clause, re.I,
    ))

def _has_explicit_correction(text: str, span: list[int]) -> bool:
    clause_start, _ = _claim_segment(text, span[0])
    return bool(_CORRECTION_MARKER.search(text[clause_start:span[0]]))


_TIME_LABEL = r"(?:today|yesterday|tomorrow|now|currently|last\s+(?:week|month|year)|on\s+\d{4}-\d{2}-\d{2})"
_TEMPORAL_PREFIX = re.compile(
    r"\s*(?:(?:yes|well|finally|now|indeed|honestly|actually|correction|at\s+last|"
    + _TIME_LABEL + r")\s*[,;:]?\s*)*", re.I)
_AMBIGUOUS_TEMPORAL_SCOPE = "AMBIGUOUS_TEMPORAL_SCOPE"


def _temporal_scope(text: str, span: list[int]) -> str | None:
    """Read time only from the complete bounded direct-prefix or postfix grammar."""
    sentence_start, _ = _sentence_segment(text, span[0])
    quote_spans = _quoted_spans(text)
    # Reuse extraction's scoped assertion-prefix grammar: it preserves soft
    # wraps, resets after a validated independent coordinator, and keeps
    # reported/conditional contexts from lending their time labels.
    prefix = _assertion_prefix(text, sentence_start, span[0], quote_spans)
    labels: list[str] = []
    if _TEMPORAL_PREFIX.fullmatch(prefix):
        labels.extend(re.sub(r"\s+", " ", match.group(0).strip().lower())
                      for match in re.finditer(_TIME_LABEL, prefix, re.I))
    sentence_end = _sentence_segment(text, span[1])[1]
    suffix = text[span[1]:sentence_end]
    postfix = re.fullmatch(r"\s*,?\s*(" + _TIME_LABEL + r")\s*[.!?;,:]*\s*", suffix, re.I)
    if postfix:
        labels.append(re.sub(r"\s+", " ", postfix.group(1).lower()))
    labels = list(dict.fromkeys(labels))
    if len(labels) > 1:
        return _AMBIGUOUS_TEMPORAL_SCOPE
    return labels[0] if labels else None


def _temporal_labels_compatible(left: str | None, right: str | None) -> bool:
    if left == _AMBIGUOUS_TEMPORAL_SCOPE or right == _AMBIGUOUS_TEMPORAL_SCOPE:
        return False
    historical = {"today", "yesterday", "tomorrow", "last week", "last month", "last year"}
    left_historical = left in historical or bool(left and left.startswith("on "))
    right_historical = right in historical or bool(right and right.startswith("on "))
    if left_historical or right_historical:
        return left == right
    return True


def _time_scopes_compatible(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    left = _temporal_scope(earlier["text"], earlier["match_span"])
    right = _temporal_scope(later["text"], later["match_span"])
    # An unqualified earlier claim may be corrected by an explicit current
    # statement such as "Actually, now I have resolved the task."
    return _temporal_labels_compatible(left, right)


def _claim_analysis(
    text: str, *, markdown_blankline_closes_quote: bool = False,
    allow_bounded_false_tail: bool = False,
) -> tuple[list[tuple[str, bool, str, list[int]]], list[dict[str, Any]]]:
    if len(text.encode("utf-8")) > MAX_CLAIM_BYTES:
        raise AuditError("CLAIM_TEXT_TOO_LARGE", "assistant message exceeds claim parsing byte bound")
    found = []
    rejected: list[dict[str, Any]] = []
    quote_spans = _quoted_spans(text)
    context_text = _mask_quoted_context(text, quote_spans)
    patterns = (
        ("TASK_RESOLVED", False, _TASK_NEGATIVE),
        ("TASK_COMPLETED", False, _TASK_COMPLETED_NEGATIVE),
        ("ISSUE_RESOLVED", False, _ISSUE_NEGATIVE),
        ("TASK_COMPLETED", True, _COMPLETED),
        ("TASK_RESOLVED", True, _TASK_RESOLVED),
        ("ISSUE_RESOLVED", True, _ISSUE_RESOLVED),
    )
    for predicate, asserted, pattern in patterns:
        for match in pattern.finditer(text):
            start, end = _claim_segment(text, match.start())
            sentence_start, sentence_end = _sentence_segment(text, match.start(), quote_spans)
            clause = text[start:end]
            sentence = text[sentence_start:sentence_end]
            prefix = text[sentence_start:match.start()]
            assertion_prefix = _assertion_prefix(text, sentence_start, match.start(), quote_spans)
            open_frames = _open_colon_frames(text, match.start(), quote_spans)
            if open_frames:
                assertion_prefix = "\n".join(header + ":" for header, _ in reversed(open_frames)) + "\n" + assertion_prefix
            line_start = text.rfind("\n", 0, match.start()) + 1
            line = text[line_start:match.start()]
            full_line_end = text.find("\n", match.start())
            full_line = text[line_start:full_line_end if full_line_end >= 0 else len(text)]
            prior_text = (text[:line_start] if markdown_blankline_closes_quote
                          else text[:text.rfind("\n", 0, match.start())])
            prior_lines = (prior_text.splitlines(keepends=True) if markdown_blankline_closes_quote
                           else prior_text.splitlines())
            in_lazy_quote = False
            for previous_line in reversed(prior_lines):
                if not previous_line.strip():
                    break
                if re.match(r" {0,3}>", previous_line):
                    in_lazy_quote = True
                    break
            reasons: list[str] = []
            sentence_has_unquoted_question = any(
                text[offset] == "?" and not any(a <= offset < b for a, b in quote_spans)
                for offset in range(sentence_start, sentence_end)
            )
            if sentence_has_unquoted_question or text[sentence_end:sentence_end + 1] == "?":
                reasons.append("INTERROGATIVE_CLAUSE")
            if full_line.startswith(("    ", "\t")) or _fenced(text, match.start()):
                reasons.append("MARKDOWN_CODE")
            if re.match(r" {0,3}>", line) or in_lazy_quote:
                reasons.append("MARKDOWN_QUOTE")
            clause_context = context_text[start:end]
            clause_prefix_context = context_text[start:match.start()]
            assertion_context = _mask_quoted_context(assertion_prefix, _quoted_spans(assertion_prefix))
            if (_HEDGES.search(clause_context) or _HEDGES.search(clause_prefix_context)
                    or _HEDGES.search(assertion_context)
                    or re.match(r"\s*(?:it|this)\s+is\s+(?:false|untrue)\s+that\b",
                                assertion_prefix, re.I)
                    or _related_qualifier_after(text, match.end(), end, predicate, quote_spans)):
                reasons.append("HEDGED_CLAUSE")
            if _conditional_scope_before(text, match.start(), quote_spans, match.end(), end):
                reasons.append("CONDITIONAL_CLAUSE")
            # Non-assertive framing can occur in the current clause or earlier
            # in the sentence (e.g. "Nobody said I resolved..."). Keep the
            # source span unchanged; only the interpretation is conservative.
            if _REPORTED_PREFIX.search(assertion_context):
                reasons.append("REPORTED_CLAIM")
            if _DENIAL_PREFIX.search(assertion_context):
                reasons.append("DENIED_CLAIM")
            if asserted and _NEGATION.search(clause_context):
                reasons.append("NEGATED_ASSERTION")
            reasons.extend(_qualified_retraction_reasons(
                context_text, match.end(), predicate,
                [match.start(), match.end()], end,
                allow_bounded_false_tail=allow_bounded_false_tail))
            tail_to_sentence_end = text[match.end():sentence_end]
            tail_context = context_text[match.end():sentence_end]
            if re.match(r"\s*,?\s*(?:or\s+so\s+(?:the\s+)?(?:user|tool|log|agent)\s+"
                        r"(?:claims?|says?|reports?)|hypothetically|in\s+theory)\b",
                        tail_context, re.I):
                reasons.append("REPORTED_CLAIM")
            if re.match(r"\s+(?:is|was)\s+(?:a\s+)?(?:lie|false|untrue|hypothetical|fiction)\b",
                        tail_context, re.I):
                reasons.append("RETRACTION_IN_CLAUSE")
            if ((not _eligible_assertion_prefix(assertion_prefix)
                 or not _eligible_assertion_tail(tail_to_sentence_end, predicate))
                    and not any(code in reasons for code in {
                        "HEDGED_CLAUSE", "CONDITIONAL_CLAUSE", "DENIED_CLAIM", "REPORTED_CLAIM",
                        "INTERROGATIVE_CLAUSE", "MARKDOWN_CODE", "MARKDOWN_QUOTE",
                        "EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE", "NEGATED_ASSERTION", "QUOTED_CLAIM"})):
                reasons.append("EMBEDDED_CLAIM_CONTEXT")
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
    for predicate, pattern in (("TASK_RESOLVED", _TASK_NEGATIVE_SCOPE),
                               ("TASK_COMPLETED", _TASK_COMPLETED_NEGATIVE_SCOPE)):
        for match in pattern.finditer(text):
            span = [match.start(), match.end()]
            rejected.append({"candidate_predicate": predicate, "asserted_value": False,
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


def _apply_attribution_ambiguity_contract(
    text: str,
    source_pointer: str,
    accepted: list[tuple[str, bool, str, list[int]]],
    rejected: list[dict[str, Any]],
    source_message_id: object = None,
) -> tuple[list[tuple[str, bool, str, list[int]]], list[dict[str, Any]]]:
    """Retain claims covered by competing local-close and outer-close parses.

    The trigger requires a source-reported quote opener, a locally paired quote
    close, a later unmatched terminal quote delimiter, and a separately paired
    quote span inside the competing outer frame. Punctuation or first-person
    wording alone never creates attribution ambiguity.
    """
    quote_spans = _quoted_spans(text)
    ambiguous_spans: dict[tuple[str, bool, tuple[int, int]], dict[str, Any]] = {}
    frames: list[tuple[int, int, dict[str, Any]]] = []
    code_spans = _markdown_code_spans(text)
    local_pairs: list[tuple[int, int, str, str]] = []
    unmatched: list[tuple[int, str]] = []
    for delimiter in ("'", '"'):
        tokens = [index for index, char in enumerate(text)
                  if char == delimiter and not any(a <= index < b for a, b in code_spans)
                  and not (delimiter == "'" and index > 0 and index + 1 < len(text)
                           and text[index - 1].isalnum() and text[index + 1].isalnum())]
        local_pairs.extend((tokens[index], tokens[index + 1] + 1, delimiter, delimiter)
                           for index in range(0, len(tokens) - 1, 2))
        if len(tokens) % 2:
            unmatched.append((tokens[-1], delimiter))
    for opening, closing in (("\u2018", "\u2019"), ("\u201c", "\u201d")):
        openings = [index for index, char in enumerate(text)
                    if char == opening and not any(a <= index < b for a, b in code_spans)]
        closings = [index for index, char in enumerate(text)
                    if char == closing and not any(a <= index < b for a, b in code_spans)]
        pending: list[int] = []
        for index in sorted(openings + closings):
            if text[index] == opening:
                pending.append(index)
            elif pending:
                local_pairs.append((pending.pop(), index + 1, opening, closing))
            else:
                unmatched.append((index, closing))
        unmatched.extend((index, closing) for index in pending)
    local_pairs.sort()
    local_quote_spans = [(a, b) for a, b, _open_char, _close_char in local_pairs]
    local_context_text = _mask_quoted_context(text, local_quote_spans)
    locally_accepted, locally_rejected = _claim_analysis(
        local_context_text, markdown_blankline_closes_quote=True,
        allow_bounded_false_tail=True)
    local_acceptance = {(predicate, asserted, tuple(span))
                        for predicate, asserted, _matched, span in locally_accepted}
    local_rejection_reasons = {
        (row.get("predicate"), row.get("asserted_value"), tuple(row.get("match_span", []))):
        set(row.get("reason_codes", [])) for row in locally_rejected
        if isinstance(row.get("match_span"), list)
    }

    def direct_after_closed_quote(span: list[int], matched_text: str) -> bool:
        completed = sorted(((a, b) for a, b, _o, _c in local_pairs if b <= span[0]),
                           key=lambda pair: pair[1])
        if not completed or not re.match(r"\s*I\b", matched_text, re.I):
            return False
        start, end = completed[-1]
        prefix = text[end:span[0]]
        quote_body = text[start + 1:end - 1].rstrip()
        explicit_separator = bool(re.fullmatch(r"\s*[;.!?]\s*", prefix))
        completed_sentence = (
            bool(re.search(r"[.!?]['\"\u2019\u201d]?$", quote_body))
            and bool(re.fullmatch(r"\s*", prefix)))
        prefix_after_separator = ("" if explicit_separator else prefix)
        return ((explicit_separator or completed_sentence)
                and _eligible_assertion_prefix(prefix_after_separator))

    def local_candidate_state(predicate: str, asserted: bool, span: list[int]) -> str:
        match_end = span[1]
        key = (predicate, asserted, tuple(span))
        local_reasons = local_rejection_reasons.get(key, set())
        direct_prefix_match = direct_after_closed_quote(span, text[span[0]:span[1]])
        nonassertive_reasons = {
            "HEDGED_CLAUSE", "CONDITIONAL_CLAUSE", "DENIED_CLAIM",
            "INTERROGATIVE_CLAUSE", "MARKDOWN_CODE", "MARKDOWN_QUOTE", "QUOTED_CLAIM",
            "NEGATED_ASSERTION",
        }
        if (local_reasons.intersection(nonassertive_reasons)
                or ("REPORTED_CLAIM" in local_reasons and not direct_prefix_match)):
            return "INELIGIBLE"
        retraction_reasons = local_reasons.intersection(
            {"EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE"})
        if retraction_reasons:
            return "EXPLICIT_RETRACTION" if direct_prefix_match else "INELIGIBLE"
        parser_eligible = key in local_acceptance or (
            key in local_rejection_reasons
            and local_reasons.issubset({"QUOTED_CLAIM", "REPORTED_CLAIM", "EMBEDDED_CLAIM_CONTEXT"})
            and direct_prefix_match
        )
        if not parser_eligible:
            return "INELIGIBLE"
        local_clause_end = _claim_segment(local_context_text, span[0])[1]
        if _qualified_retraction_reasons(
                local_context_text, match_end, predicate, span, local_clause_end,
                allow_bounded_false_tail=True):
            return "EXPLICIT_RETRACTION"
        if _has_explicit_correction(local_context_text, span):
            return "CORRECTION"
        return "ACTIVE_ASSERTION"
    # Keep both the legacy parser's outer-closer interpretation and the
    # alternative local-pair interpretation. An unmatched terminal delimiter
    # plus an independently paired inner quote is the competing-closure
    # witness; delimiter balance is derived from original character offsets.
    terminal, terminal_char = max(unmatched) if unmatched else (None, None)
    if terminal is not None and text[terminal] in {terminal_char, "\u2019", "\u201d"} and not text[terminal + 1:].strip(" .!?\t\r\n"):
        report_matches = list(_REPORTED_PREFIX.finditer(text[:terminal]))
        for reported in report_matches:
            opens = [(a, b, opening_char, closing_char) for a, b, opening_char, closing_char in local_pairs
                     if reported.end() <= a <= reported.end() + 4 and b <= terminal
                     and closing_char == terminal_char]
            for opening, local_close, opening_char, _closing_char in opens:
                paired_inside = [[a, b] for a, b, _open_char, _close_char in local_pairs
                                 if opening < a < b <= terminal]
                if paired_inside:
                    frames.append((opening, terminal + 1, {
                        "reported_prefix_span": [reported.start(), reported.end()],
                        "outer_open_delimiter": [opening, opening + 1],
                        "local_close_delimiter": [local_close - 1, local_close],
                        "local_quote_span": [opening, local_close],
                        "quote_delimiter_type": opening_char,
                        "terminal_close_candidate": [terminal, terminal + 1],
                        "nested_paired_quote_spans": paired_inside,
                        "legacy_outer_quote_spans": [[a, b] for a, b in quote_spans
                                                      if a <= opening and terminal < b],
                        "ambiguity_group_id": _stable(
                            "attribution-frame", source_pointer, str(opening),
                            str(local_close), str(terminal)),
                    }))

    def frame_witness(span: list[int]) -> dict[str, Any] | None:
        for opening, end, witness in frames:
            if (witness["local_quote_span"][1] <= span[0] and span[1] <= end
                    and not any(a <= span[0] and span[1] <= b
                                for a, b in witness["nested_paired_quote_spans"])):
                return {**witness, "candidate_span": list(span)}
        return None

    for predicate, asserted, _matched, span in accepted:
        witness = frame_witness(span)
        if witness is not None:
            witness["candidate_state"] = local_candidate_state(predicate, asserted, span)
            ambiguous_spans[(predicate, asserted, tuple(span))] = witness
    kept_accepted = [row for row in accepted
                     if (row[0], row[1], tuple(row[3])) not in ambiguous_spans]
    promoted: list[tuple[str, bool, str, list[int]]] = []
    converted: list[dict[str, Any]] = []
    kept_rejected: list[dict[str, Any]] = []
    for row in rejected:
        predicate = row.get("predicate")
        asserted = row.get("asserted_value")
        span = row.get("match_span")
        if (isinstance(predicate, str) and type(asserted) is bool
                and isinstance(span, list) and len(span) == 2
                and frame_witness(span) is not None):
            witness = frame_witness(span) or {}
            witness["candidate_state"] = local_candidate_state(predicate, asserted, span)
            ambiguous_spans[(predicate, asserted, tuple(span))] = witness
            continue
        reasons = set(row.get("reason_codes", []))
        span_is_quoted = any(a <= span[0] and span[1] <= b for a, b, _o, _c in local_pairs)
        direct_after_quote = direct_after_closed_quote(span, row.get("matched_text", ""))
        promotable_reasons = {"QUOTED_CLAIM", "REPORTED_CLAIM", "EMBEDDED_CLAIM_CONTEXT"}
        if (isinstance(predicate, str) and type(asserted) is bool
                and isinstance(span, list) and len(span) == 2
                and not span_is_quoted and frame_witness(span) is None
                and direct_after_quote and reasons
                and reasons.issubset(promotable_reasons)):
            promoted.append((predicate, asserted, row["matched_text"], span))
            continue
        row = dict(row)
        row["attribution_status"] = (
            "QUOTED" if span_is_quoted or reasons.intersection({"QUOTED_CLAIM", "MARKDOWN_QUOTE", "REPORTED_CLAIM"}) else
            "RETRACTION" if reasons.intersection({"EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE"}) else
            "UNKNOWN")
        row["claim_classification"] = row["attribution_status"]
        if reasons.intersection({"EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE"}):
            row["claim_state"] = "EXPLICIT_RETRACTION"
        kept_rejected.append(row)
    for predicate, asserted, span in sorted(ambiguous_spans, key=lambda item: item[2][0]):
        matched = text[span[0]:span[1]]
        witness = ambiguous_spans[(predicate, asserted, span)]
        reported = witness["reported_prefix_span"]
        converted.append({
            "predicate": predicate,
            "candidate_predicate": predicate,
            "asserted_value": None,
            "candidate_asserted_value": asserted,
            "candidate_state": witness.get("candidate_state", "ACTIVE_ASSERTION"),
            "ambiguity_group_id": witness["ambiguity_group_id"],
            "matched_text": matched,
            "match_span": list(span),
            "byte_span": [len(text[:span[0]].encode("utf-8")),
                          len(text[:span[1]].encode("utf-8"))],
            "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
            "content_sha256": _sha(text.encode("utf-8")),
            "source_pointer": source_pointer,
            "source_message_id": source_message_id if isinstance(source_message_id, str) else "UNKNOWN",
            "message_identity_status": (
                "SOURCE_DECLARED_UNVERIFIED" if isinstance(source_message_id, str) and source_message_id else "UNKNOWN"),
            "text": text,
            "attribution_status": "AMBIGUOUS_ATTRIBUTION",
            "attribution": "UNKNOWN",
            "claim_classification": "UNKNOWN",
            "claim_state": (
                "RETRACTED" if witness.get("candidate_state") == "EXPLICIT_RETRACTION" else
                "CORRECTION_CANDIDATE" if witness.get("candidate_state") == "CORRECTION" else
                "INELIGIBLE" if witness.get("candidate_state") == "INELIGIBLE" else "ACTIVE"),
            "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
            "comparison_consequence": {
                "EXPLICIT_RETRACTION": "LOCAL_PARSE_EXPLICITLY_RETRACTS_CANDIDATE",
                "CORRECTION": "LOCAL_PARSE_MAY_SUPERSEDE_PRIOR_ACTIVE_CLAIM",
                "INELIGIBLE": "LOCAL_PARSE_GRAMMAR_EXCLUDES_CANDIDATE",
                "ACTIVE_ASSERTION": "OWNER_ASSIGNMENT_CHANGES_COMPARABILITY",
            }.get(witness.get("candidate_state"), "OWNER_UNKNOWN_CANDIDATE_NOT_COMPARABLE"),
            "incompatibility_reason": "LOCAL_QUOTE_CLOSE_AND_OUTER_TERMINAL_CLOSE_ASSIGN_DIFFERENT_OWNERS",
            "available_evidence": {
                "reported_prefix_span": reported,
                "outer_open_delimiter": witness["outer_open_delimiter"],
                "local_close_delimiter": witness["local_close_delimiter"],
                "local_quote_span": witness["local_quote_span"],
                "quote_delimiter_type": witness["quote_delimiter_type"],
                "terminal_close_candidate": witness["terminal_close_candidate"],
            "nested_paired_quote_spans": witness["nested_paired_quote_spans"],
                "legacy_outer_quote_spans": witness["legacy_outer_quote_spans"],
            },
            "owner_alternatives": [
                {"owner": "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT",
                 "interpretation": "local_quote_closes_before_candidate_and_candidate_is_assistant_content",
                 "witness_spans": {"local_close_delimiter": witness["local_close_delimiter"],
                                   "candidate": list(span)}},
                {"owner": "REPORTED_OR_QUOTE_DELIMITED_CONTENT",
                 "interpretation": "outer_quote_closes_at_terminal_candidate_and_contains_candidate",
                 "witness_spans": {"reported_prefix": reported,
                                   "outer_open_delimiter": witness["outer_open_delimiter"],
                                   "terminal_close_candidate": witness["terminal_close_candidate"],
                                   "candidate": list(span)}},
            ],
            "reason_codes": (
                ["REPORT_FRAME_OWNER_UNRESOLVED", "CANDIDATE_NOT_ASSERTION_ELIGIBLE_IN_LOCAL_PARSE"]
                if witness.get("candidate_state") == "INELIGIBLE"
                else ["REPORT_FRAME_OWNER_UNRESOLVED"]),
        })
    return kept_accepted + promoted, kept_rejected + converted

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
        excluded_count = 0
        excluded_bytes_total = 0
        nested_visited = 0

        def record_exclusion(content_value: Any, pointer: str, reason: str, stage: str) -> None:
            nonlocal excluded_count, excluded_bytes_total
            payload = (content_value.encode("utf-8") if isinstance(content_value, str) else
                       json.dumps(content_value, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8"))
            excluded_count += 1
            excluded_bytes_total += len(payload)
            if excluded_count > MAX_NESTED_EXCLUSION_NODES or excluded_bytes_total > MAX_NESTED_EXCLUSION_BYTES:
                raise AuditError("NESTED_CONTENT_SCAN_LIMIT", "excluded trajectory content exceeds scan bounds")
            _append_observation(out, _obs(
                ref, run, iid, "excluded_content", "EXCLUDED_CONTENT",
                {"sha256": _sha(payload), "bytes": len(payload),
                 "content_type": "text" if isinstance(content_value, str) else type(content_value).__name__,
                 "attribution_status": "UNKNOWN", "exclusion_reason": reason,
                 "stage_classification": stage}, pointer, "UNKNOWN"))

        def scan_nested(value: Any, pointer: str, depth: int) -> None:
            nonlocal nested_visited
            nested_visited += 1
            if nested_visited > MAX_NESTED_EXCLUSION_NODES or depth > MAX_NESTED_EXCLUSION_DEPTH:
                raise AuditError("NESTED_CONTENT_SCAN_LIMIT", "nested trajectory JSON exceeds scan bounds")
            if isinstance(value, dict):
                for key in sorted(value):
                    child = value[key]
                    child_pointer = pointer + "/" + _escape(str(key))
                    if str(key).lower() == "content":
                        stage = ("NESTED_MODEL_RESPONSE" if re.search(
                            r"(?:/messages/\d+)?/extra/response/choices/\d+/message/content$",
                            child_pointer) else "NESTED_EXTRA_CONTENT")
                        record_exclusion(child, child_pointer, "NESTED_EXTRA_CONTENT", stage)
                    else:
                        scan_nested(child, child_pointer, depth + 1)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    scan_nested(child, pointer + "/" + str(index), depth + 1)

        if doc.get("extra") is not None:
            scan_nested(doc["extra"], "/extra", 0)

        for message_order, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            pointer = f"/messages/{message_order}/content"
            content = message.get("content")
            if message.get("extra") is not None:
                scan_nested(message["extra"], f"/messages/{message_order}/extra", 0)
            if message.get("role") != "assistant":
                if "content" in message:
                    record_exclusion(content, pointer, "NON_ASSISTANT_ROLE", "TOP_LEVEL_MESSAGE")
                continue
            message_actor_unscoped = any(key in message for key in ("agent_id", "agent_ids", "speaker_id"))
            if not isinstance(content, str):
                if "content" in message:
                    record_exclusion(content, pointer, "STRUCTURED_ASSISTANT_CONTENT", "TOP_LEVEL_MESSAGE")
                    if isinstance(content, (list, dict)):
                        rejected_claims.append({"source_pointer": pointer, "text": None,
                                                "match_span": None, "byte_span": None,
                                                "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                                                "reason_codes": ["STRUCTURED_CONTENT_UNSUPPORTED"]})
                continue
            selected_attribution_contract = (
                desc.get("claim_attribution_contract") == ATTRIBUTION_AMBIGUITY_CONTRACT)
            if (selected_attribution_contract and not root_actor_unscoped
                    and not message_actor_unscoped
                    and _STANDALONE_RETRACTION.fullmatch(content)):
                span = [0, len(content)]
                event_id = _stable("retraction-event", run, iid, ref["path"], ref["sha256"],
                                   pointer, str(span))
                event = {
                    "event_id": event_id,
                    "event_type": "STANDALONE_CLAIM_RETRACTION",
                    "matched_text": content,
                    "text": content,
                    "source_pointer": pointer,
                    "source_message_id": message.get("message_id")
                    if isinstance(message.get("message_id"), str) else "UNKNOWN",
                    "message_identity_status": (
                        "SOURCE_DECLARED_UNVERIFIED"
                        if isinstance(message.get("message_id"), str) and message.get("message_id")
                        else "UNKNOWN"),
                    "match_span": span,
                    "byte_span": [0, len(content.encode("utf-8"))],
                    "span_unit": "MESSAGE_RELATIVE_UTF8_BYTES",
                    "content_sha256": _sha(content.encode("utf-8")),
                    "attribution_status": "SOURCE_DECLARED_UNVERIFIED",
                    "speaker_scope": "SAME_TRAJECTORY_DECLARED_ASSISTANT_ROLE",
                    "speaker_identity_status": "UNKNOWN",
                    "authentication_status": "UNAUTHENTICATED",
                    "target_claim_id": None,
                    "target_status": "UNKNOWN_NO_PRIOR_COMPATIBLE_ACTIVE_CLAIM",
                }
                _append_observation(out, _obs(
                    ref, run, iid, "claim_retraction", "EXPLICIT_RETRACTION_EVENT",
                    event, pointer, "SOURCE_DECLARED_ASSISTANT_ROLE_UNAUTHENTICATED"))
            accepted, rejected = _claim_analysis(
                content, markdown_blankline_closes_quote=selected_attribution_contract,
                allow_bounded_false_tail=selected_attribution_contract)
            if selected_attribution_contract:
                accepted, rejected = _apply_attribution_ambiguity_contract(
                    content, pointer, accepted, rejected, message.get("message_id"))
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
                if desc.get("claim_attribution_contract") == ATTRIBUTION_AMBIGUITY_CONTRACT:
                    claim["attribution_status"] = "DIRECT"
                    claim["claim_classification"] = "DIRECT"
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
                           and _time_scopes_compatible(claim, later)
                           and _has_explicit_correction(later["text"], later["match_span"])]
            if superseding:
                claim["superseded_by"] = superseding[-1]["claim_id"]
                if desc.get("claim_attribution_contract") == ATTRIBUTION_AMBIGUITY_CONTRACT:
                    claim["attribution_status"] = "SUPERSEDED"
                    claim["claim_classification"] = "SUPERSEDED"
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
        "audit_contract_version": "pgop1.swebench.audit-contract.v2",
        "status": "ERROR", "reason_codes": [],
        "source_ref": {k: d.get(k) for k in ("path", "sha256", "bytes", "role", "parser_id",
                                                "run_id", "instance_id", "scope", "timestamp")
                       if k in d},
        "run_id": d.get("run_id", "UNKNOWN"), "instance_id": d.get("instance_id", "UNKNOWN"),
        "observations": [],
    }
    try:
        item = _descriptor(descriptor, allow_claim_attribution_contract=True)
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
        if "claim_attribution_contract" in item:
            result["claim_attribution_contract"] = item["claim_attribution_contract"]
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
        "audit_contract_version": "pgop1.swebench.audit-contract.v2",
        "run_id": run_id if _valid_run(run_id) else "UNKNOWN",
        "semantic_derivation_schema": "pgop1.swebench.audit-derivation.v1",
        "instance_id": instance_id if _valid_id(instance_id) else "UNBOUND",
        "COMPUTED_VERDICT": None, "AUDIT_VERDICT": "VERIFICATION_ERROR", "reason_codes": [],
        "FINAL_ERROR": None, "FINAL_ERROR_CODES": [],
        "verification_qualifiers": {
            "schema": QUALIFIER_SCHEMA, "logical_verdict": "VERIFICATION_ERROR",
            "byte_integrity_status": "NOT_PROVEN",
            "semantic_derivation_status": "NOT_VERIFIED_AT_EXTRACTION",
            "evaluator_authentication_status": "NOT_APPLICABLE",
            "evaluator_authentication_basis": "NO_BOUND_BOOLEAN_EVALUATOR_RESULT",
        },
        "AGENT_STATEMENT": [], "CLAIM_REJECTIONS": [], "EXCLUDED_CONTENT": [],
        "PARSER_REJECTIONS": [], "PREDICTION": [], "EVALUATOR_RESULT": [],
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
                    "METADATA_ENCODING_INVALID", "CLAIM_TEXT_TOO_LARGE", "OBSERVATION_LIMIT",
                    "ATTRIBUTION_SCENARIO_LIMIT"}
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
        attribution_contract = request.get("claim_attribution_contract")
        if attribution_contract not in (None, ATTRIBUTION_AMBIGUITY_CONTRACT):
            raise AuditError("ATTRIBUTION_CONTRACT_UNSUPPORTED", "claim attribution contract is not registered")
        if attribution_contract is not None:
            result["claim_attribution_contract"] = attribution_contract
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
            if attribution_contract is not None:
                parse_descriptor["claim_attribution_contract"] = attribution_contract
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
        statements = [copy.deepcopy(obs["value"]) for obs in statement_observations]
        statement_observation_ids = {obs.get("claim_id"): obs["observation_id"]
                                     for obs in statement_observations}
        rejected_claims = [copy.deepcopy(obs["value"]) for obs in observations
                           if obs["kind"] == "claim_rejection"]
        retraction_observations = [obs for obs in observations if obs["kind"] == "claim_retraction"]
        retraction_events = [obs["value"] for obs in retraction_observations]
        retraction_sources = {obs["value"]["event_id"]: obs.get("source_ref")
                              for obs in retraction_observations}
        rejection_sources = {
            obs.get("rejection_id"): obs.get("source_ref") for obs in observations
            if obs["kind"] == "claim_rejection"
        }

        def message_order(pointer: object, span: object) -> tuple[int, int] | None:
            if not isinstance(pointer, str):
                return None
            match = re.fullmatch(r"/messages/(\d+)/content", pointer)
            if not match or not isinstance(span, list) or len(span) != 2 or type(span[0]) is not int:
                return None
            return int(match.group(1)), span[0]

        for row in rejected_claims:
            if (row.get("attribution_status") != "AMBIGUOUS_ATTRIBUTION"
                    or row.get("candidate_state") != "CORRECTION"):
                continue
            source_ref = rejection_sources.get(row.get("rejection_id"))
            path = source_ref.get("path") if isinstance(source_ref, dict) else None
            current_order = message_order(row.get("source_pointer"), row.get("match_span"))
            if not isinstance(path, str) or current_order is None:
                continue
            superseded_ids: list[str] = []
            for prior in statements:
                prior_ref = prior.get("source_ref")
                prior_order = message_order(prior.get("source_pointer"), prior.get("match_span"))
                if (not isinstance(prior_ref, dict) or prior_ref.get("path") != path
                        or prior_order is None or prior_order >= current_order
                        or prior.get("predicate") != row.get("candidate_predicate")
                        or prior.get("asserted_value") == row.get("candidate_asserted_value")
                        or prior.get("superseded_by")):
                    continue
                if _time_scopes_compatible(prior, row):
                    claim_id = prior.get("claim_id")
                    if isinstance(claim_id, str):
                        superseded_ids.append(claim_id)
            row["supersedes_claim_ids"] = sorted(set(superseded_ids))
            for prior in statements:
                if prior.get("claim_id") in row["supersedes_claim_ids"]:
                    prior.setdefault("possible_superseded_by", []).append(row["rejection_id"])
        ambiguity_candidate_rows = [row for row in rejected_claims
            if (row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                and row.get("candidate_state") in {"ACTIVE_ASSERTION", "CORRECTION"}
                and isinstance(row.get("ambiguity_group_id"), str)
                and isinstance(row.get("candidate_predicate"), str)
                and type(row.get("candidate_asserted_value")) is bool)]
        for event in sorted(retraction_events, key=lambda row: (
                message_order(row.get("source_pointer"), row.get("match_span"))
                or (MAX_OBSERVATIONS, MAX_OBSERVATIONS))):
            source_ref = retraction_sources.get(event.get("event_id"))
            path = source_ref.get("path") if isinstance(source_ref, dict) else None
            event_order = message_order(event.get("source_pointer"), event.get("match_span"))
            if not isinstance(path, str) or event_order is None:
                continue
            compatible_prior: list[tuple[tuple[int, int], dict[str, Any]]] = []
            for prior in statements:
                prior_ref = prior.get("source_ref")
                prior_order = message_order(prior.get("source_pointer"), prior.get("match_span"))
                if (not isinstance(prior_ref, dict) or prior_ref.get("path") != path
                        or prior_order is None or prior_order >= event_order
                        or prior.get("retracted_by")):
                    continue
                superseder_id = prior.get("superseded_by")
                if isinstance(superseder_id, str):
                    superseder = next((claim for claim in statements
                                       if claim.get("claim_id") == superseder_id), None)
                    superseder_order = (message_order(superseder.get("source_pointer"),
                                                      superseder.get("match_span"))
                                        if superseder else None)
                    if superseder_order is None or superseder_order < event_order:
                        continue
                event_context = {**event, "predicate": prior.get("predicate")}
                if _time_scopes_compatible(prior, event_context):
                    compatible_prior.append((prior_order, prior))
            if compatible_prior:
                _order, target = max(compatible_prior, key=lambda item: item[0])
            else:
                _order, target = None, None
            target_order = _order if target is not None else None
            possible_ambiguous_targets: list[dict[str, Any]] = []
            for candidate in ambiguity_candidate_rows:
                candidate_ref = rejection_sources.get(candidate.get("rejection_id"))
                candidate_order = message_order(candidate.get("source_pointer"),
                                                candidate.get("match_span"))
                if (not isinstance(candidate_ref, dict) or candidate_ref.get("path") != path
                        or candidate_order is None or candidate_order >= event_order
                        or (target_order is not None and candidate_order <= target_order)):
                    continue
                event_context = {**event, "predicate": candidate.get("candidate_predicate")}
                if _time_scopes_compatible(candidate, event_context):
                    possible_ambiguous_targets.append(candidate)
            if possible_ambiguous_targets:
                alternatives: list[dict[str, Any]] = []
                if target is not None:
                    target["possible_retracted_by"] = sorted(set(
                        target.get("possible_retracted_by", []) + [event["event_id"]]))
                    alternatives.append({
                        "claim_id": target["claim_id"], "target_kind": "CLEAR_CLAIM",
                        "predicate": target["predicate"], "asserted_value": target["asserted_value"],
                        "source_ref": copy.deepcopy(target["source_ref"]),
                        "source_pointer": target["source_pointer"],
                        "match_span": copy.deepcopy(target["match_span"]),
                    })
                for candidate in possible_ambiguous_targets:
                    candidate["possible_retracted_by"] = sorted(set(
                        candidate.get("possible_retracted_by", []) + [event["event_id"]]))
                    candidate_ref = rejection_sources.get(candidate.get("rejection_id"))
                    alternatives.append({
                        "claim_id": candidate["rejection_id"], "target_kind": "AMBIGUOUS_CLAIM",
                        "predicate": candidate["candidate_predicate"],
                        "asserted_value": candidate["candidate_asserted_value"],
                        "ambiguity_group_id": candidate["ambiguity_group_id"],
                        "source_ref": copy.deepcopy(candidate_ref),
                        "source_pointer": candidate["source_pointer"],
                        "match_span": copy.deepcopy(candidate["match_span"]),
                    })
                event["target_status"] = "AMBIGUOUS_TARGET"
                event["target_claim_id"] = None
                event["target_claim_alternatives"] = alternatives
            elif target is not None:
                event["target_claim_id"] = target["claim_id"]
                event["target_predicate"] = target["predicate"]
                event["target_status"] = "LINKED"
                event["target_asserted_value"] = target["asserted_value"]
                event["target_source_ref"] = copy.deepcopy(target["source_ref"])
                event["target_source_pointer"] = target["source_pointer"]
                event["target_match_span"] = copy.deepcopy(target["match_span"])
                target.setdefault("retracted_by", []).append(event["event_id"])
        excluded_content = [obs for obs in observations if obs["kind"] == "excluded_content"]
        predictions = [obs["value"] for obs in observations if obs["kind"] == "prediction"]
        evaluator = [obs for obs in observations if obs["kind"] == "evaluator_result"
                     and obs["predicate"] == "TASK_RESOLVED" and type(obs["value"]) is bool]
        evaluator_source_present = any(ref["parser_id"] in {
            "pgop1.swebench.evaluator_report.resolved_map_json.v1",
            "pgop1.swebench.catalog.per_instance_details_json.v1",
            "pgop1.swebench.results.resolved_list_json.v1",
        } for ref in refs.values())
        result["AGENT_STATEMENT"] = statements
        result["CLAIM_REJECTIONS"] = rejected_claims
        if attribution_contract == ATTRIBUTION_AMBIGUITY_CONTRACT:
            result["CLAIM_RETRACTIONS"] = retraction_events
        result["EXCLUDED_CONTENT"] = [
            {"source_ref": copy.deepcopy(obs["source_ref"]), "sha256": obs["value"]["sha256"],
             "bytes": obs["value"]["bytes"], "content_type": obs["value"]["content_type"],
             "attribution_status": "UNKNOWN", "exclusion_reason": obs["value"]["exclusion_reason"],
             "stage_classification": obs["value"].get("stage_classification", "UNKNOWN")}
            for obs in excluded_content]
        result["EXCLUDED_CONTENT_SUMMARY"] = {
            "record_count": len(excluded_content),
            "stage_counts": {stage: sum(1 for obs in excluded_content
                                         if obs["value"].get("stage_classification", "UNKNOWN") == stage)
                             for stage in sorted({obs["value"].get("stage_classification", "UNKNOWN")
                                                  for obs in excluded_content})},
        }
        result["PREDICTION"] = predictions
        result["EVALUATOR_RESULT"] = [
            {"predicate": obs["predicate"], "observed_value": obs["value"],
             "source_ref": copy.deepcopy(obs["source_ref"]), "attribution": obs["attribution"],
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
            copy.deepcopy(ref) for ref in refs.values() if ref["parser_id"] in {
                "pgop1.swebench.log.text_unattributed.v1",
                "pgop1.swebench.log.gzip_text_unattributed.v1",
            }
        ]
        result["SOURCE_PROVENANCE"]["evidence_references"] = [copy.deepcopy(refs[key])
                                                               for key in sorted(refs)]
        result["SOURCE_PROVENANCE"]["parser_ids"] = sorted({ref["parser_id"] for ref in refs.values()})

        verdicts: list[str] = []
        scenario_consensus_outcome: str | None = None
        inactive_in_all_scenarios: set[str] = set()
        ambiguity_groups: dict[str, list[dict[str, Any]]] = {}
        ambiguous_retraction_target_ids = {
            alternative.get("claim_id")
            for event in retraction_events
            if event.get("target_status") == "AMBIGUOUS_TARGET"
            for alternative in event.get("target_claim_alternatives", [])
            if (isinstance(alternative, dict)
                and alternative.get("target_kind") == "AMBIGUOUS_CLAIM"
                and isinstance(alternative.get("claim_id"), str))
        }
        for row in rejected_claims:
            if (row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                    and (row.get("candidate_predicate") == "TASK_RESOLVED"
                         or row.get("rejection_id") in ambiguous_retraction_target_ids)
                    and isinstance(row.get("ambiguity_group_id"), str)):
                ambiguity_groups.setdefault(row["ambiguity_group_id"], []).append(row)
        clear_active_claims = {
            claim["claim_id"]: claim for claim in statements
            if not claim.get("superseded_by") and not claim.get("retracted_by")
        }
        clear_resolved_claims = {
            claim_id: claim["asserted_value"] for claim_id, claim in clear_active_claims.items()
            if claim["predicate"] == "TASK_RESOLVED"
        }
        noncomparable_claim_ids = {
            claim_id for claim_id, claim in clear_active_claims.items()
            if claim["predicate"] != "TASK_RESOLVED"
        }

        def comparison_outcome(values: set[bool], observed: bool,
                               noncomparable_active_claim: bool) -> str:
            outcomes = {compare_boolean_values(value, observed)["verdict"] for value in values}
            if noncomparable_active_claim or not outcomes:
                outcomes.add("INSUFFICIENT_EVIDENCE")
            if outcomes == {"SUPPORTED"}:
                return "SUPPORTED"
            if outcomes == {"CONTRADICTED"}:
                return "CONTRADICTED"
            return "INSUFFICIENT_EVIDENCE"

        ambiguity_affects_comparison = False
        if ambiguity_groups and len({obs["value"] for obs in evaluator}) == 1 and not errors:
            observed_value = evaluator[0]["value"]
            value_by_claim_id = dict(clear_resolved_claims)
            for group_rows in ambiguity_groups.values():
                for row in group_rows:
                    candidate_id = row.get("rejection_id")
                    candidate_predicate = row.get("candidate_predicate")
                    if (row.get("candidate_state") in {"ACTIVE_ASSERTION", "CORRECTION"}
                            and isinstance(candidate_id, str)
                            and isinstance(candidate_predicate, str)):
                        if candidate_predicate == "TASK_RESOLVED" and type(row.get("candidate_asserted_value")) is bool:
                            value_by_claim_id[candidate_id] = row["candidate_asserted_value"]
                        elif candidate_predicate != "TASK_RESOLVED":
                            noncomparable_claim_ids.add(candidate_id)
            all_supersession_targets = {
                target for group_rows in ambiguity_groups.values() for row in group_rows
                for target in row.get("supersedes_claim_ids", []) if isinstance(target, str)
            }
            retraction_target_ids = {
                alternative.get("claim_id")
                for event in retraction_events
                if event.get("target_status") == "AMBIGUOUS_TARGET"
                for alternative in event.get("target_claim_alternatives", [])
                if isinstance(alternative, dict) and isinstance(alternative.get("claim_id"), str)
            }
            clear_claim_ids = set(clear_active_claims)
            tracked_claim_ids = all_supersession_targets | retraction_target_ids | clear_claim_ids
            initial_ids = clear_claim_ids
            initial_tracked = frozenset(initial_ids)
            initial_values = frozenset()
            possible_states: set[tuple[frozenset[str], frozenset[bool], bool]] = {
                (initial_tracked, initial_values, False)
            }
            ordered_groups = sorted(ambiguity_groups.items(), key=lambda item: min(
                (message_order(row.get("source_pointer"), row.get("match_span"))
                 or (MAX_OBSERVATIONS, 0)) for row in item[1]))
            scenario_limit_exceeded = False
            for group_index, (_group_id, group_rows) in enumerate(ordered_groups):
                targets_after = {
                    target for _later_id, later_rows in ordered_groups[group_index + 1:]
                    for row in later_rows for target in row.get("supersedes_claim_ids", [])
                    if isinstance(target, str)
                }
                group_rows = sorted(group_rows, key=lambda row: (
                    message_order(row.get("source_pointer"), row.get("match_span"))
                    or (MAX_OBSERVATIONS, MAX_OBSERVATIONS),
                    row["match_span"][0],
                ))
                next_states: set[tuple[frozenset[str], frozenset[bool], bool]] = set()
                for active_ids, residual_values, residual_noncomparable in possible_states:
                    branches = [(set(active_ids), set(residual_values), residual_noncomparable, False),
                                (set(active_ids), set(residual_values), residual_noncomparable, True)]
                    for branch_ids, branch_values, branch_noncomparable, include_local in branches:
                        if include_local:
                            for row in group_rows:
                                state = row.get("candidate_state")
                                if state not in {"ACTIVE_ASSERTION", "CORRECTION"}:
                                    continue
                                branch_ids.difference_update(row.get("supersedes_claim_ids", []))
                                candidate_id = row.get("rejection_id")
                                candidate_value = row.get("candidate_asserted_value")
                                candidate_predicate = row.get("candidate_predicate")
                                if not isinstance(candidate_id, str) or not isinstance(candidate_predicate, str):
                                    continue
                                if candidate_id in tracked_claim_ids:
                                    branch_ids.add(candidate_id)
                                elif candidate_predicate == "TASK_RESOLVED" and type(candidate_value) is bool:
                                    branch_values.add(candidate_value)
                                elif candidate_predicate != "TASK_RESOLVED":
                                    branch_noncomparable = True
                        values = set(branch_values)
                        retained_ids = set(branch_ids) & (
                            targets_after | retraction_target_ids | clear_claim_ids)
                        collapsed_ids = branch_ids - retained_ids
                        values.update(value_by_claim_id[claim_id] for claim_id in collapsed_ids
                                      if claim_id in value_by_claim_id)
                        collapsed_noncomparable = branch_noncomparable or any(
                            claim_id in noncomparable_claim_ids for claim_id in collapsed_ids)
                        next_states.add((frozenset(retained_ids), frozenset(values),
                                         collapsed_noncomparable))
                        if len(next_states) > MAX_ATTRIBUTION_SCENARIO_STATES:
                            scenario_limit_exceeded = True
                            break
                    if scenario_limit_exceeded:
                        break
                if scenario_limit_exceeded:
                    break
                possible_states = next_states
            if scenario_limit_exceeded:
                errors.append("ATTRIBUTION_SCENARIO_LIMIT")
            else:
                possible_outcomes: set[str] = set()
                scenario_active_sets: list[set[str]] = []
                for active_ids, residual_values, residual_noncomparable in possible_states:
                    scenario_active_ids = set(active_ids)
                    for event in sorted(retraction_events, key=lambda row: (
                            message_order(row.get("source_pointer"), row.get("match_span"))
                            or (MAX_OBSERVATIONS, MAX_OBSERVATIONS))):
                        if event.get("target_status") != "AMBIGUOUS_TARGET":
                            continue
                        alternatives = event.get("target_claim_alternatives", [])
                        eligible_ids = {item.get("claim_id") for item in alternatives
                                        if isinstance(item, dict)
                                        and isinstance(item.get("claim_id"), str)
                                        and item.get("claim_id") in scenario_active_ids}
                        if not eligible_ids:
                            continue
                        alternative_by_id = {item["claim_id"]: item for item in alternatives
                                             if isinstance(item, dict)
                                             and isinstance(item.get("claim_id"), str)}
                        target_id = max(eligible_ids, key=lambda claim_id: (
                            message_order(alternative_by_id[claim_id].get("source_pointer"),
                                          alternative_by_id[claim_id].get("match_span"))
                            or (-1, -1), claim_id))
                        scenario_active_ids.discard(target_id)
                    scenario_active_sets.append(scenario_active_ids & clear_claim_ids)
                    scenario_values = set(residual_values) | {
                        value_by_claim_id[claim_id] for claim_id in scenario_active_ids
                        if claim_id in value_by_claim_id}
                    scenario_noncomparable = residual_noncomparable or any(
                        claim_id in noncomparable_claim_ids for claim_id in scenario_active_ids)
                    possible_outcomes.add(comparison_outcome(
                        scenario_values, observed_value, scenario_noncomparable))
                if scenario_active_sets:
                    active_in_any_scenario = set().union(*scenario_active_sets)
                    inactive_in_all_scenarios = clear_claim_ids - active_in_any_scenario
                    scenario_consensus_outcome = (next(iter(possible_outcomes))
                                                  if len(possible_outcomes) == 1 else None)
                ambiguity_affects_comparison = len(possible_outcomes) > 1
        if ambiguity_affects_comparison:
            result["reason_codes"].append("ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON")
        if len({obs["value"] for obs in evaluator}) > 1:
            errors.append("EVALUATOR_RECORD_CONFLICT")
            for claim in statements:
                claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                claim["reason_codes"] = ["EVALUATOR_RECORD_CONFLICT"]
                verdicts.append("INSUFFICIENT_EVIDENCE")
        elif evaluator:
            observed = evaluator[0]["value"]
            for claim in statements:
                if claim.get("claim_id") in inactive_in_all_scenarios:
                    claim["inactive_in_all_attribution_scenarios"] = True
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["INACTIVE_IN_ALL_ATTRIBUTION_SCENARIOS"]
                elif claim.get("retracted_by"):
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["EXPLICITLY_RETRACTED_BY_STANDALONE_EVENT"]
                elif claim.get("superseded_by"):
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["SUPERSEDED_BY_LATER_OPPOSITE_ASSERTION"]
                    # Retain the corrected historical claim for auditability,
                    # but exclude it from the active-claim aggregate.
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
                            "evidence_bindings": [copy.deepcopy(claim["source_ref"]),
                                                  copy.deepcopy(eval_obs["source_ref"])],
                            "claim_observation_id": claim_obs_id,
                        })
                else:
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["NO_MATCHING_EVALUATOR_PREDICATE"]
                    verdicts.append("INSUFFICIENT_EVIDENCE")
        else:
            for claim in statements:
                if claim.get("claim_id") in inactive_in_all_scenarios:
                    claim["inactive_in_all_attribution_scenarios"] = True
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = ["INACTIVE_IN_ALL_ATTRIBUTION_SCENARIOS"]
                else:
                    claim["AUDIT_VERDICT"] = "INSUFFICIENT_EVIDENCE"
                    claim["reason_codes"] = (
                        ["EXPLICITLY_RETRACTED_BY_STANDALONE_EVENT"]
                        if claim.get("retracted_by") else ["NO_MATCHING_EVALUATOR_PREDICATE"])
                if (not claim.get("retracted_by")
                        and claim.get("claim_id") not in inactive_in_all_scenarios):
                    verdicts.append("INSUFFICIENT_EVIDENCE")

        for claim in statements:
            claim["COMPUTED_VERDICT"] = claim["AUDIT_VERDICT"]
            claim.setdefault("FINAL_ERROR", None)
            claim["claim_state"] = (
                "INACTIVE_IN_ALL_ATTRIBUTION_SCENARIOS"
                if claim.get("inactive_in_all_attribution_scenarios") else
                "RETRACTED" if claim.get("retracted_by") else
                "CORRECTED" if claim.get("superseded_by") else
                "ACTIVE_CONTRADICTED" if claim["AUDIT_VERDICT"] == "CONTRADICTED" else
                "ACTIVE_NONCOMPARABLE" if claim["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE" else "ACTIVE")
        claim_aggregation = {
            "policy": "ALL_RETAINED_CLAIMS_WITH_EXPLICIT_CORRECTION_EXCLUSIONS",
            "corrected_claim_ids": [c["claim_id"] for c in statements if c.get("superseded_by")],
            "active_contradicted_claim_ids": [c["claim_id"] for c in statements
                if c["claim_state"] == "ACTIVE_CONTRADICTED"],
            "active_noncomparable_claim_ids": [c["claim_id"] for c in statements
                if c["claim_state"] == "ACTIVE_NONCOMPARABLE"],
            "retracted_candidate_count": sum(any(code in {"EXPLICIT_CORRECTION", "RETRACTION_IN_CLAUSE"}
                for code in row.get("reason_codes", [])) for row in rejected_claims),
        }
        if attribution_contract == ATTRIBUTION_AMBIGUITY_CONTRACT:
            claim_aggregation["retracted_claim_ids"] = [
                claim["claim_id"] for claim in statements if claim.get("retracted_by")]
            claim_aggregation["standalone_retraction_event_ids"] = [
                event["event_id"] for event in retraction_events]
        result["CLAIM_AGGREGATION"] = claim_aggregation
        if result["CLAIM_AGGREGATION"]["active_contradicted_claim_ids"]:
            result["reason_codes"].append("ACTIVE_CONTRADICTED_CLAIM_PRESENT")
        if scenario_consensus_outcome is not None:
            computed_verdict = scenario_consensus_outcome
        elif ambiguity_affects_comparison:
            computed_verdict = "INSUFFICIENT_EVIDENCE"
        elif (verdicts and all(value == "SUPPORTED" for value in verdicts)
                and not result["CLAIM_AGGREGATION"]["active_contradicted_claim_ids"]):
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
            elif (attribution_contract == ATTRIBUTION_AMBIGUITY_CONTRACT
                  and not verdicts
                  and result["CLAIM_AGGREGATION"].get("retracted_claim_ids")):
                result["reason_codes"].append("NO_ACTIVE_CLAIM_AFTER_RETRACTION")
                if not evaluator:
                    result["reason_codes"].append("NO_BOUND_EVALUATOR_RESULT")
            elif not evaluator:
                result["reason_codes"].append("NO_BOUND_EVALUATOR_RESULT")
            elif verdicts:
                result["reason_codes"].append("MIXED_OR_NONCOMPARABLE_CLAIMS")
        evaluator_authentication_status = "UNAUTHENTICATED" if evaluator_source_present else "NOT_APPLICABLE"
        evaluator_authentication_basis = (
            "SOURCE_ROLE_IS_DECLARED_AND_EVALUATOR_IDENTITY_UNKNOWN" if evaluator_source_present else
            "NO_BOUND_BOOLEAN_EVALUATOR_RESULT")
        byte_integrity_status = "SOURCE_HASH_VERIFIED" if len(refs) == len(descriptors) else "NOT_PROVEN"
        result["verification_qualifiers"] = {
            "schema": QUALIFIER_SCHEMA,
            "logical_verdict": result["AUDIT_VERDICT"],
            "byte_integrity_status": byte_integrity_status,
            "semantic_derivation_status": "NOT_VERIFIED_AT_EXTRACTION",
            "evaluator_authentication_status": evaluator_authentication_status,
            "evaluator_authentication_basis": evaluator_authentication_basis,
        }
        for claim in statements:
            claim["verification_qualifiers"] = {
                "schema": QUALIFIER_SCHEMA,
                "logical_verdict": claim["AUDIT_VERDICT"],
                "byte_integrity_status": (
                    "SOURCE_HASH_VERIFIED" if isinstance(claim.get("source_ref"), dict)
                    and isinstance(claim["source_ref"].get("sha256"), str) else "NOT_PROVEN"),
                "semantic_derivation_status": "NOT_VERIFIED_AT_EXTRACTION",
                "evaluator_authentication_status": (
                    "UNAUTHENTICATED" if claim["predicate"] == "TASK_RESOLVED" and evaluator_source_present
                    else "NOT_APPLICABLE"),
                "evaluator_authentication_basis": (
                    "SOURCE_ROLE_IS_DECLARED_AND_EVALUATOR_IDENTITY_UNKNOWN"
                    if claim["predicate"] == "TASK_RESOLVED" and evaluator_source_present else
                    "NO_BOUND_BOOLEAN_EVALUATOR_RESULT"),
            }
        return result
    except AuditError as exc:
        result["reason_codes"] = [exc.code]
        result["AUDIT_VERDICT"] = _priority([exc.code]) or "VERIFICATION_ERROR"
        result["FINAL_ERROR"] = result["AUDIT_VERDICT"]
        result["FINAL_ERROR_CODES"] = [exc.code]
        result["verification_qualifiers"]["logical_verdict"] = result["AUDIT_VERDICT"]
        return result


__all__ = ["audit_evidence", "audit_file", "AuditError", "PARSER_VERSIONS"]

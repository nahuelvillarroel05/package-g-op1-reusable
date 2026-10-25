# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Engineering-only digest, I4 graph, and I5 attribution for pg_i7."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import sys
from typing import Any, Mapping

sys.dont_write_bytecode = True

_WORKSPACE = Path(__file__).resolve().parent
_VENDOR = _WORKSPACE / "deps" / "i4_i5"
_SRC = _VENDOR / "src"
_SUPPORT = _VENDOR / "tests" / "support"
_SNAPSHOT = _VENDOR / "source_snapshots" / "frozen_i4_i5"
_DEPENDENCY_MANIFEST = _VENDOR / "I4_I5_DEPENDENCY_MANIFEST.json"
_I4_SHA = "df1be33dcc85fefced28275808429cd9b6a39b0344e3521644300d0f3d3e2db3"
_I5_SHA = "0e3e105925848182ff7b7e59aba3057e9647082f8f058797a07224d96eb6212b"
_FIXTURE_SHA = "4a574976eaa7443505eaa4850ff9c000e5f1077fb636920a701d4da1e9b9a1b5"


class EvidenceSidecarError(ValueError):
    """Evidence could not be safely created or verified."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def current_i5_compatibility(i4_semantic_raw: bytes) -> dict[str, Any]:
    """Report whether frozen I5 can consume this exact current I4 graph.

    The frozen I5 implementation currently pins one historical semantic graph.
    This adapter deliberately does not rewrite that pin or synthesize I5
    identities when the current graph is incompatible.
    """
    expected = _FIXTURE_SHA
    actual = _sha(i4_semantic_raw)
    if actual != expected:
        return {
            "status": "BLOCKED_FROZEN_I5_FIXTURE_FINGERPRINT_MISMATCH",
            "i4_semantic_sha256": actual,
            "frozen_i5_required_sha256": expected,
            "i5_append_attempted": False,
            "attribution": "UNKNOWN",
            "reason": "Frozen ProvenanceLedger.__init__ rejects any I4 semantic bytes whose SHA-256 differs from its pinned fixture.",
        }
    return {
        "status": "FINGERPRINT_MATCH_REQUIRES_FROZEN_API_VALIDATION",
        "i4_semantic_sha256": actual,
        "frozen_i5_required_sha256": expected,
        "i5_append_attempted": False,
        "attribution": "UNKNOWN",
    }


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _paired_document_references(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Require each parsed literal target to align with its exact resolution row."""
    document = row.get("document")
    explicit = document.get("explicit_references", []) if isinstance(document, Mapping) else []
    resolved = row.get("references", [])
    if not isinstance(explicit, list) or not isinstance(resolved, list) or len(explicit) != len(resolved):
        raise EvidenceSidecarError("document reference parse and resolution records do not pair one-to-one")
    for parsed, checked in zip(explicit, resolved):
        if (not isinstance(parsed, Mapping) or not isinstance(checked, Mapping)
                or not isinstance(parsed.get("target_id"), str) or len(parsed["target_id"]) != 64
                or checked.get("target_id") != parsed.get("target_id")):
            raise EvidenceSidecarError("document reference target identity differs from its exact parsed source")
        status = checked.get("status")
        if status == "RESOLVED_EXACT_PATH":
            if (not isinstance(checked.get("sha256"), str) or len(checked["sha256"]) != 64
                    or not isinstance(checked.get("size"), int) or checked["size"] < 0):
                raise EvidenceSidecarError("resolved document reference lacks exact target bytes")
        elif status == "MISSING_OR_UNRESOLVED":
            if checked.get("sha256") is not None or checked.get("size") is not None:
                raise EvidenceSidecarError("unknown document reference carries fabricated target bytes")
        else:
            raise EvidenceSidecarError("document reference has an unrecognized resolution status")
    return resolved


def _load_frozen_apis():
    if not _SRC.is_dir():
        raise EvidenceSidecarError("vendored frozen I4/I5 dependency closure is unavailable")
    try:
        manifest = json.loads(_DEPENDENCY_MANIFEST.read_bytes())
        rows = manifest["records"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise EvidenceSidecarError("frozen I4/I5 dependency manifest is unavailable or invalid") from exc
    if manifest.get("schema") != "I7_FROZEN_I4_I5_DEPENDENCY_CLOSURE_V1" or not rows:
        raise EvidenceSidecarError("frozen I4/I5 dependency manifest schema mismatch")
    base = _VENDOR.resolve()
    seen: set[str] = set()
    for row in rows:
        rel = row.get("path")
        if (not isinstance(rel, str) or "\\" in rel or Path(rel).is_absolute()
                or any(part in {"", ".", ".."} for part in rel.split("/")) or rel in seen):
            raise EvidenceSidecarError("unsafe or duplicate path in frozen I4/I5 manifest")
        seen.add(rel)
        path = _VENDOR.joinpath(*rel.split("/"))
        if path.is_symlink() or not path.resolve().is_relative_to(base):
            raise EvidenceSidecarError("dependency path escapes frozen I4/I5 closure")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise EvidenceSidecarError("pinned I4/I5 dependency is missing: " + rel) from exc
        if len(raw) != row.get("byte_length") or _sha(raw) != row.get("sha256"):
            raise EvidenceSidecarError("frozen I4/I5 dependency commitment mismatch: " + rel)
    if _sha((_SNAPSHOT / "i4_graph.py").read_bytes()) != _I4_SHA:
        raise EvidenceSidecarError("frozen I4 implementation pin mismatch")
    if _sha((_SNAPSHOT / "i5_provenance.py").read_bytes()) != _I5_SHA:
        raise EvidenceSidecarError("frozen I5 implementation pin mismatch")
    if _sha((_SRC / "package_g" / "op1_reusable" / "i4_graph.py").read_bytes()) != _I4_SHA:
        raise EvidenceSidecarError("imported I4 implementation differs from the exact frozen snapshot")
    if _sha((_SRC / "package_g" / "op1_reusable" / "i5_provenance.py").read_bytes()) != _I5_SHA:
        raise EvidenceSidecarError("imported I5 implementation differs from the exact frozen snapshot")
    # Public derivative: protected native fixtures are deliberately absent.
    # Frozen I4/I5 module pins remain checked; this does not reproduce formal fixtures.
    for path in (str(_SRC),):
        if path not in sys.path:
            sys.path.insert(0, path)
    from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes, strict_json_loads
    from package_g.op1_reusable.i4_graph import CausalGraph, SourceCorpus, pointer, require_dag
    import package_g.op1_reusable.i4_graph as imported_i4
    from package_g.op1_reusable.schema_registry import SchemaRegistry
    from package_g.op1_reusable.i5_provenance import ProvenanceLedger
    import package_g.op1_reusable.i5_provenance as imported_i5
    Catalog = None  # Native historical fixtures are not part of this public export.
    if Path(imported_i4.__file__).resolve() != (_SRC / "package_g" / "op1_reusable" / "i4_graph.py").resolve():
        raise EvidenceSidecarError("I4 module import escaped the vendored source closure")
    if Path(imported_i5.__file__).resolve() != (_SRC / "package_g" / "op1_reusable" / "i5_provenance.py").resolve():
        raise EvidenceSidecarError("I5 module import escaped the vendored source closure")
    return canonical_json, generate_id, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus, pointer, require_dag, SchemaRegistry, ProvenanceLedger, Catalog


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _binding(path: Path, corpus_path: str, raw: bytes) -> dict[str, Any]:
    return {"corpus_path": corpus_path, "sha256": _sha(raw), "byte_length": len(raw)}


def _contained_attempt(value: str) -> Path:
    if not value:
        raise EvidenceSidecarError("attempt directory is absent")
    attempt = Path(value).resolve(strict=True)
    expected = (_WORKSPACE / "engine" / "cases" / "CASE-LOCAL-TOTALS" / "attempts").resolve()
    if not attempt.is_dir() or not attempt.is_relative_to(expected):
        raise EvidenceSidecarError("attempt directory is outside the pinned local engine case")
    return attempt


def _verify_execution_chain(input_doc: Mapping[str, Any], result_doc: Mapping[str, Any]) -> dict[str, Any]:
    """Recheck the exact local request/provider/consumer/result chain without dispatch."""
    try:
        input_bytes = base64.b64decode(input_doc["input_bytes_base64"], validate=True)
        input_value = json.loads(input_bytes.decode("utf-8"))
        expected_input_hash = input_doc["input_sha256"]
        values = input_doc["values"]
        engine_result = result_doc["result"]
        attempt_result = result_doc["attempt_result"]
        attempt = _contained_attempt(str(result_doc["attempt_directory"]))
    except (KeyError, TypeError, ValueError, UnicodeError, OSError) as exc:
        raise EvidenceSidecarError("CLI input or attempt binding is malformed") from exc
    if (_sha(input_bytes) != expected_input_hash or len(input_bytes) != input_doc.get("input_byte_length")
            or input_value.get("values") != values or input_value.get("schema") != input_doc.get("input_schema")):
        raise EvidenceSidecarError("exact CLI input bytes do not match the committed values and schema")
    transfer = input_doc.get("pipeline_transfer")
    if transfer is not None:
        try:
            manifest_raw = base64.b64decode(transfer["stage_a_manifest_base64"], validate=True)
            ledger_raw = base64.b64decode(transfer["stage_a_ledger_base64"], validate=True)
            ledger_rows = [json.loads(line.decode("utf-8")) for line in ledger_raw.splitlines()]
            documents = transfer["documents"]
            manifest_doc = json.loads(manifest_raw.decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise EvidenceSidecarError("pipeline transfer envelope is malformed") from exc
        transfer_count = transfer.get("document_count")
        transfer_schema = transfer.get("selection_schema")
        expected_provider = ("safe.documents.metadata.v1" if transfer_schema == "i7.focused.real-document-selection.v1"
                             else "safe.documents.metadata.v2" if transfer_schema == "pg_i7.documents.selection.v2"
                             else None)
        if (transfer.get("schema") != "i7.pipeline-transfer.v1"
                or not isinstance(transfer.get("transfer_id"), str)
                or not re.fullmatch(r"TRANSFER-[0-9a-f]{32}", transfer["transfer_id"])
                or type(transfer_count) is not int or not 1 <= transfer_count <= 64
                or not isinstance(documents, list) or len(documents) != transfer_count
                or transfer.get("metadata_provider_id") != expected_provider
                or _sha(manifest_raw) != transfer.get("stage_a_manifest_sha256")
                or len(manifest_raw) != transfer.get("stage_a_manifest_bytes")
                or _sha(ledger_raw) != transfer.get("stage_a_ledger_sha256")
                or len(ledger_raw) != transfer.get("stage_a_ledger_bytes")
                or transfer.get("stage_b_input_sha256") != expected_input_hash
                or transfer.get("stage_b_input_bytes") != len(input_bytes)
                or transfer.get("stage_b_values") != values or len(ledger_rows) != transfer_count
                or transfer.get("documentary_references_are_causal") is not False
                or manifest_doc.get("snapshot_id") != transfer.get("stage_a_id")
                or manifest_doc.get("document_count") != transfer_count
                or manifest_doc.get("coverage_status") != "COMPLETE"):
            raise EvidenceSidecarError("pipeline transfer commitments do not match exact A and B bytes")
        cli = next((module for module in (sys.modules.get("__main__"), *sys.modules.values())
                    if getattr(module, "WORKSPACE", None) == _WORKSPACE
                    and callable(getattr(module, "_checked_absolute", None))), None)
        if cli is None:
            raise EvidenceSidecarError("bound CLI is unavailable for pipeline source revalidation")
        b_path = cli._checked_absolute(input_doc.get("input_path", ""), base=cli.WORKSPACE, must_exist=True)
        if (not cli._beneath(b_path, cli.INPUTS_ROOT) or not b_path.is_file()
                or b_path.read_bytes() != input_bytes):
            raise EvidenceSidecarError("pipeline B input file differs from the exact verified input bytes")
        documents_policy = cli._documents_policy_module()
        embedded_selection = base64.b64decode(transfer.get("selection_manifest_base64", ""), validate=True)
        if (len(embedded_selection) > documents_policy.MAX_SELECTION_BYTES
                or transfer.get("selection_sha256") != _sha(embedded_selection)):
            raise EvidenceSidecarError("pipeline selection bytes differ from their exact transfer commitment")
        if transfer_schema == "i7.focused.real-document-selection.v1":
            if _sha(embedded_selection) != cli.REAL_DOCUMENT_SELECTION_SHA256:
                raise EvidenceSidecarError("v1 pipeline selection differs from its exact legacy pin")
            selected_rows = json.loads(embedded_selection.decode("utf-8")).get("documents", [])
            if len(selected_rows) != 8 or transfer_count != 8:
                raise EvidenceSidecarError("v1 selection no longer has exactly eight rows")
        else:
            try:
                policy_value, selected_rows, policy_root = documents_policy.validate_selection_bytes(
                    cli, cli._engineering_api(), embedded_selection)
            except Exception as exc:
                raise EvidenceSidecarError("v2 embedded selection failed independent policy and commitment validation") from exc
            if (transfer.get("selection_commitment_sha256") != policy_value.get("selection_commitment_sha256")
                    or manifest_doc.get("selection_commitment_sha256") != policy_value.get("selection_commitment_sha256")
                    or manifest_doc.get("selection_manifest_sha256") != _sha(embedded_selection)
                    or os.path.normcase(os.path.normpath(manifest_doc.get("source_root", "")))
                       != os.path.normcase(os.path.normpath(str(policy_root)))
                    or manifest_doc.get("snapshot_consistency") != "PER_FILE_STABLE_READS_ONLY"
                    or manifest_doc.get("cross_document_snapshot_claim") != "NOT_ASSERTED"
                    or manifest_doc.get("content_parsed") is not False
                    or manifest_doc.get("content_disclosed") is not False
                    or manifest_doc.get("documentary_references_are_causal") is not False):
                raise EvidenceSidecarError("v2 transfer selection commitment or snapshot limits differ")
        expected_documents = [{"path_id": row.get("path_id"), "sha256": row.get("sha256"), "bytes": row.get("bytes"),
                              **({"file_identity": row.get("file_identity")} if "file_identity" in row else {})}
                             for row in selected_rows]
        if documents != expected_documents:
            raise EvidenceSidecarError("pipeline document vector differs from the exact selected row vector")
        scan_dir = cli._checked_absolute(transfer.get("stage_a_output_dir", ""),
                                         base=cli.WORKSPACE, must_exist=True)
        if (not cli._beneath(scan_dir, cli.WORKSPACE / "runs")
                or not cli._same_path(scan_dir.parent, cli.WORKSPACE / "runs") or not scan_dir.is_dir()):
            raise EvidenceSidecarError("pipeline A output escaped its bound workspace runs")
        manifest_path = cli._checked_absolute(scan_dir / "document-scan-manifest.jsonl",
                                              base=scan_dir, must_exist=True)
        ledger_path = cli._checked_absolute(scan_dir / "document-scan-ledger.jsonl",
                                            base=scan_dir, must_exist=True)
        current_manifest = manifest_path.read_bytes()
        current_ledger = ledger_path.read_bytes()
        if current_manifest != manifest_raw or current_ledger != ledger_raw:
            raise EvidenceSidecarError("pipeline A output bytes differ from the embedded transfer evidence")
        ledger_by_id = {row.get("path_id"): row for row in ledger_rows}
        for document in documents:
            row = ledger_by_id.get(document.get("path_id"))
            if (row is None or row.get("status") != "HASHED" or row.get("sha256") != document.get("sha256")
                    or row.get("size") != document.get("bytes")
                    or row.get("bytes_read_hash") != document.get("bytes")):
                raise EvidenceSidecarError("pipeline A ledger differs from the exact transfer document list")
        if transfer_schema == "pg_i7.documents.selection.v2":
            expected_ledger = [{"path_id": row["path_id"], "status": "HASHED", "size": row["bytes"],
                                "sha256": row["sha256"], "bytes_read_hash": row["bytes"],
                                "document": row["document"], "references": [], "detail": None}
                               for row in selected_rows]
            if ledger_rows != expected_ledger:
                raise EvidenceSidecarError("v2 A ledger differs from the exact committed metadata-only rows")
        if [row.get("bytes") for row in documents] != values:
            raise EvidenceSidecarError("pipeline totals values differ from ordered document sizes")
    if engine_result.get("directory") != str(attempt):
        raise EvidenceSidecarError("engine result attempt identity differs from the pinned attempt directory")
    names = ("request.json", "provider.stdout", "consumer.stdout", "result.json")
    raw = {name: (attempt / name).read_bytes() for name in names}
    request, provider, consumer, engine_run = (json.loads(raw[name].decode("utf-8"))
                                                for name in names)
    if request.get("values") != values or request.get("expected_sum") != sum(values):
        raise EvidenceSidecarError("engine request values do not match exact CLI input")
    if (provider.get("request_id") != request.get("REQUEST_ID") or provider.get("nonce") != request.get("nonce")
            or provider.get("values") != request.get("values") or provider.get("sum") != sum(values)
            or provider.get("squares") != sum(value * value for value in values)):
        raise EvidenceSidecarError("provider output is not a verified response to the exact request")
    provider_sha = _sha(raw["provider.stdout"])
    consumer_result = {
        "processed_sha256": provider_sha, "rows_processed": len(values),
        "sum": sum(values), "squares": sum(value * value for value in values),
    }
    if consumer != consumer_result or attempt_result.get("CONSUMER_RESULT") != consumer_result:
        raise EvidenceSidecarError("consumer stdout or engine consumer result differs from recomputation")
    if (engine_run.get("FINAL_STATUS") != "CLEAN_EXECUTION_PASS"
            or engine_run.get("CONSUMER_RESULT") != consumer_result
            or engine_result.get("FINAL_STATUS") != "CLEAN_EXECUTION_PASS"):
        raise EvidenceSidecarError("engine result is not a clean verified local execution")
    relationship = request.get("relationship", {})
    for label in ("provider", "consumer"):
        source_path = _WORKSPACE / "engine" / f"{label}_structured.py"
        role = label.upper()
        if relationship.get(role + "_SOURCE") != str(source_path) or relationship.get(role + "_SHA256") != _sha(source_path.read_bytes()):
            raise EvidenceSidecarError("request source pin differs from composition " + label)
    req_sha, result_sha = _sha(raw["request.json"]), _sha(raw["result.json"])
    if (engine_result.get("request_sha256") != req_sha or engine_result.get("result_sha256") != result_sha
            or attempt_result != engine_run):
        raise EvidenceSidecarError("wrapper request/result commitments differ from exact attempt bytes")
    engine = sys.modules.get("engine")
    if engine is None or not callable(getattr(engine, "recover", None)):
        raise EvidenceSidecarError("pinned read-only engine recovery API is unavailable")
    helper_path = _WORKSPACE / "readonly_recovery.py"
    if not helper_path.is_file() or helper_path.is_symlink():
        raise EvidenceSidecarError("pinned read-only recovery adapter is unavailable")
    helper_name = "_pg_i7_readonly_recovery_sidecar"
    helper = sys.modules.get(helper_name)
    if helper is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(helper_name, helper_path)
        if spec is None or spec.loader is None:
            raise EvidenceSidecarError("read-only recovery adapter could not be loaded")
        helper = importlib.util.module_from_spec(spec)
        sys.modules[helper_name] = helper
        spec.loader.exec_module(helper)
    recovered = helper.recover(engine, str(attempt), req_sha, result_sha)
    if recovered.get("status") != "PASS" or recovered.get("replay_rejected") is not True:
        raise EvidenceSidecarError("read-only fresh recovery did not verify the exact attempt")
    return {
        "input": {"path": input_doc.get("input_path"), "sha256": expected_input_hash,
                  "byte_length": len(input_bytes), "values": list(values)},
        "request": {"path": "request.json", "sha256": req_sha, "values_match_input": True,
                    "request_id": request["REQUEST_ID"], "nonce": request["nonce"]},
        "provider": {"path": "provider.stdout", "sha256": provider_sha,
                     "byte_length": len(raw["provider.stdout"]),
                     "request_id_match": True, "nonce_match": True, "values_match": True},
        "consumer": {"path": "consumer.stdout", "sha256": _sha(raw["consumer.stdout"]),
                     "byte_length": len(raw["consumer.stdout"]),
                     "recomputed_result": consumer_result, "matches_provider_bytes": True},
        "engine_result": {"path": "result.json", "sha256": result_sha,
                          "status": engine_run["FINAL_STATUS"], "wrapper_result_sha256": result_doc.get("result_sha256")},
        "recovery": {"status": recovered["status"], "replay_rejected": True,
                     "source_commitments_verified": recovered.get("source_commitments_verified") is True},
        "attempt_directory": str(attempt),
        "claim_scope": "SELF_REPORTED_ENGINEERING_DERIVATION_ONLY",
    }


def _dot(graph_doc: Mapping[str, Any]) -> bytes:
    # IDs and relations are validated against exact I4 projection before export.
    lines = ["digraph engineering_observations {", "  rankdir=LR;"]
    for node in graph_doc["nodes"]:
        label = str(node["type"]) + "\\n" + str(node["id"])
        lines.append(f'  "{node["id"]}" [label="{label}"];')
    for edge in graph_doc["edges"]:
        lines.append(f'  "{edge["source_id"]}" -> "{edge["target_id"]}" [label="{edge["relation"]}"];')
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _make_event(generate_id, schemas, *, ids: Mapping[str, str], actor_id: str,
                role: str, sequence: int, occurred: str, payload_sha: str,
                caused_by: list[dict[str, str]] | None = None) -> dict[str, Any]:
    entry = schemas.find_document("OP1_EVENT_SCHEMA.json")
    event_id = ids["event_id"]
    identity = {"entity_id": event_id, "entity_type": "EVENT", "schema_id": entry.schema_id,
                "schema_version": entry.version, "actor_id": actor_id, "created_at_utc": occurred,
                "status": "COMMITTED", "project_id": ids["project_id"], "product_id": ids["product_id"],
                "lineage_id": ids["lineage_id"], "version_id": ids["version_id"],
                "session_id": ids["session_id"], "run_id": ids["run_id"]}
    return {"identity": identity, "event_id": event_id, "event_kind": "ENGINEERING_" + role,
            "event_role": "OBSERVATION", "session_id": ids["session_id"], "run_id": ids["run_id"],
            "attempt_id": ids["attempt_id"], "actor_id": actor_id, "occurred_at_utc": occurred,
            "committed_sequence": sequence, "parent_ids": [], "caused_by_ids": caused_by or [],
            "payload_sha256": payload_sha, "produced_artifact_ids": [], "produced_finding_ids": [],
            "resolved_finding_ids": [], "triggered_decision_ids": [], "evidence_ids": [],
            "writer_authentication_ref": "ENGINEERING_SIDECAR_SELF_REPORTED"}


def build_artifacts(operation_id: str, actor: str, provider_id: str,
                    input_record: Mapping[str, Any], result_record: Mapping[str, Any],
                    output_dir: str | os.PathLike[str], flags: Mapping[str, bool]) -> dict[str, Any]:
    """Write requested run evidence, calling frozen I4/I5 APIs and local recovery."""
    if flags.get("provenance", False):
        raise EvidenceSidecarError("FROZEN_I5_FIXTURE_UNAVAILABLE_PUBLIC_EXPORT")
    (canonical_json, generate_id, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     i4_pointer, require_dag, SchemaRegistry, ProvenanceLedger, Catalog) = _load_frozen_apis()
    destination = Path(output_dir).resolve(strict=True)
    if not destination.is_dir():
        raise EvidenceSidecarError("run output directory must already exist")
    input_doc, result_doc = dict(input_record), dict(result_record)
    input_raw, result_raw = canonical_json(input_doc), canonical_json(result_doc)
    input_hash, result_hash = sha256_bytes(input_raw), sha256_bytes(result_raw)
    produced: dict[str, Any] = {"schema_version": "pg_i7.evidence-result.v1", "operation_id": operation_id,
                                "status": "PASS", "artifacts": {}, "limitations": []}
    enabled = {key: bool(flags.get(key, False)) for key in ("data_digest", "causal_data", "provenance")}
    checked_chain = _verify_execution_chain(input_doc, result_doc) if any(enabled.values()) else None
    if checked_chain is not None:
        binding_doc = {"schema_version": "pg_i7.evidence-binding.v1", "operation_id": operation_id,
                       "actor_declared": actor or "UNKNOWN",
                       "provider_id": provider_id, "input_record": input_doc, "result_record": result_doc,
                       "input_record_sha256": input_hash, "result_record_sha256": result_hash,
                       "claim_scope": "SELF_REPORTED_ENGINEERING_BINDING_ONLY"}
        binding_raw = canonical_json(binding_doc)
        _write_new(destination / "I7_EVIDENCE_BINDING.json", binding_raw)
        produced["artifacts"]["evidence_binding"] = {"path": str(destination / "I7_EVIDENCE_BINDING.json"),
                                                       "sha256": sha256_bytes(binding_raw),
                                                       "byte_length": len(binding_raw)}

    if enabled["data_digest"]:
        raw_input = base64.b64decode(input_doc.get("input_bytes_base64", ""), validate=True)
        if _sha(raw_input) != input_doc.get("input_sha256") or len(raw_input) != input_doc.get("input_byte_length"):
            raise EvidenceSidecarError("data digest input bytes differ from input record identity")
        digest = {"schema_version": "pg_i7.data-digest.v1", "operation_id": operation_id,
                  "input": {"path": input_doc.get("input_path", "UNKNOWN"),
                            "sha256": input_doc["input_sha256"], "byte_length": len(raw_input),
                            "schema": input_doc.get("input_schema", "UNKNOWN"),
                            "values": input_doc.get("values", []), "identity_basis": "EXACT_CLI_INPUT_BYTES"},
                  "result": {"sha256": result_doc.get("result_sha256", result_hash),
                             "path": result_doc.get("result_path", "UNKNOWN"),
                             "status": result_doc.get("status", "UNKNOWN"),
                             "summary": result_doc.get("attempt_result", {}).get("CONSUMER_RESULT", {}),
                             "provider_stdout_sha256": result_doc.get("attempt_result", {}).get("OUTPUT_HASHES", {}).get("stdout", "UNKNOWN"),
                             "provider_stdout_byte_length": checked_chain["provider"]["byte_length"],
                             "consumer_stdout_sha256": checked_chain["consumer"]["sha256"],
                             "consumer_stdout_byte_length": checked_chain["consumer"]["byte_length"]},
                  "provider_id": provider_id,
                  "sources": [{"kind": "INPUT_RECORD", "sha256": input_hash},
                              {"kind": "RESULT_RECORD", "sha256": result_hash},
                              {"kind": "PROVIDER_STDOUT", "sha256": checked_chain["provider"]["sha256"]},
                              {"kind": "CONSUMER_STDOUT", "sha256": checked_chain["consumer"]["sha256"]}],
                  "statistics": "ONLY_ENGINE_RESULT_FIELDS_RECOMPUTED_BY_CONSUMER",
                  "limitations": ["Engineering-local evidence; no operational custody or qualification."]}
        raw = canonical_json(digest)
        _write_new(destination / "DATA_DIGEST.json", raw)
        produced["artifacts"]["data_digest"] = {"path": str(destination / "DATA_DIGEST.json"),
                                                  "sha256": sha256_bytes(raw), "byte_length": len(raw)}

    if enabled["causal_data"]:
        proof = checked_chain
        if proof is None:
            raise EvidenceSidecarError("execution chain was not verified")
        attempt = Path(proof["attempt_directory"])
        evidence = {
            "input.json": base64.b64decode(input_doc["input_bytes_base64"], validate=True),
            "input_record.json": canonical_json(input_doc),
            "result_record.json": canonical_json(result_doc),
            "request.json": (attempt / "request.json").read_bytes(),
            "provider.stdout": (attempt / "provider.stdout").read_bytes(),
            "consumer.stdout": (attempt / "consumer.stdout").read_bytes(),
            "result.json": (attempt / "result.json").read_bytes(),
            "ENGINEERING_DERIVATION.json": canonical_json(proof),
        }
        transfer = input_doc.get("pipeline_transfer")
        if transfer is not None:
            evidence["pipeline_document_manifest.json"] = base64.b64decode(transfer["stage_a_manifest_base64"], validate=True)
            evidence["pipeline_document_ledger.jsonl"] = base64.b64decode(transfer["stage_a_ledger_base64"], validate=True)
            evidence["pipeline_transfer.json"] = canonical_json(transfer)
        corpus_dir = destination / "i4_source_corpus"
        corpus_dir.mkdir(exist_ok=False)
        bindings = {name: {"corpus_path": name, "sha256": sha256_bytes(raw), "byte_length": len(raw)}
                    for name, raw in evidence.items()}
        for name, raw in evidence.items():
            _write_new(corpus_dir / name, raw)
        actor_id = generate_id("ACTOR")
        ids = {name: generate_id(kind) for name, kind in (
            ("project_id", "PROJECT"), ("product_id", "PRODUCT"), ("lineage_id", "LINEAGE"),
            ("version_id", "VERSION"), ("session_id", "SESSION"), ("run_id", "RUN"),
            ("attempt_id", "ATTEMPT"), ("input_event", "EVENT"), ("provider_event", "EVENT"),
            ("consumer_event", "EVENT"), ("metadata_event", "EVENT"), ("transfer_event", "EVENT"))}
        schemas, occurred = SchemaRegistry(), _utc_now()
        if transfer is not None:
            specs = [
                ("metadata_event", "DOCUMENT_METADATA_PRODUCED", 1, "pipeline_transfer.json", "OBSERVES_HASHED_DOCUMENT_METADATA", "/documents", []),
                ("transfer_event", "PROVIDER_INPUT_TRANSFORMED", 2, "pipeline_transfer.json", "OBSERVES_EXACT_METADATA_TO_TOTALS_TRANSFER", "/stage_b_values",
                 [{"entity_type": "EVENT", "entity_id": ids["metadata_event"]}]),
                ("input_event", "INPUT_OBSERVED", 3, "input.json", "OBSERVES_CLI_INPUT", "/values",
                 [{"entity_type": "EVENT", "entity_id": ids["transfer_event"]}]),
                ("provider_event", "PROVIDER_OUTPUT_OBSERVED", 4, "provider.stdout", "OBSERVES_VERIFIED_PROVIDER_OUTPUT", "/request_id",
                 [{"entity_type": "EVENT", "entity_id": ids["input_event"]}]),
                ("consumer_event", "CONSUMER_RECOMPUTATION_OBSERVED", 5, "consumer.stdout", "OBSERVES_VERIFIED_CONSUMER_RECOMPUTATION", "/processed_sha256",
                 [{"entity_type": "EVENT", "entity_id": ids["provider_event"]}]),
            ]
        else:
            specs = [
                ("input_event", "INPUT_OBSERVED", 1, "input.json", "OBSERVES_CLI_INPUT", "/values", []),
                ("provider_event", "PROVIDER_OUTPUT_OBSERVED", 2, "provider.stdout", "OBSERVES_VERIFIED_PROVIDER_OUTPUT", "/request_id",
                 [{"entity_type": "EVENT", "entity_id": ids["input_event"]}]),
                ("consumer_event", "CONSUMER_RECOMPUTATION_OBSERVED", 3, "consumer.stdout", "OBSERVES_VERIFIED_CONSUMER_RECOMPUTATION", "/processed_sha256",
                 [{"entity_type": "EVENT", "entity_id": ids["provider_event"]}]),
            ]
        graph_nodes = []
        graph_records = []
        for key, role, sequence, source_name, relation, pointer, caused_by in specs:
            ids["event_id"] = ids[key]
            event = _make_event(generate_id, schemas, ids=ids, actor_id=actor_id, role=role,
                                sequence=sequence, occurred=occurred,
                                payload_sha=bindings[source_name]["sha256"], caused_by=caused_by)
            event_name = key + ".json"
            event_raw = canonical_json(event)
            _write_new(corpus_dir / event_name, event_raw)
            event_binding = {"corpus_path": event_name, "sha256": sha256_bytes(event_raw), "byte_length": len(event_raw)}
            # Append these exact reifications to the evidence corpus before graph
            # construction so I4 verifies the source record and evidence identities.
            node_bindings = [bindings[source_name], bindings["ENGINEERING_DERIVATION.json"], event_binding]
            if transfer is not None and key == "metadata_event":
                node_bindings.extend([bindings["pipeline_document_manifest.json"],
                                      bindings["pipeline_document_ledger.jsonl"]])
            graph_nodes.append((event, node_bindings, event_binding, source_name, relation, pointer))
        # Bind/rebuild through the frozen API using the complete, byte-pinned
        # corpus. The manifest is written once after its members are complete.
        manifest = {"files": sorted([*bindings.values(), *[row[2] for row in graph_nodes]], key=lambda row: row["corpus_path"])}
        manifest_raw = canonical_json(manifest)
        _write_new(corpus_dir / "manifest.json", manifest_raw)
        corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
        graph = CausalGraph(corpus)
        node_views: list[dict[str, Any]] = []
        edge_views: list[dict[str, Any]] = []
        i4_records: list[bytes] = []
        for event, source_bindings, record_binding, source_name, relation, pointer in graph_nodes:
            node = graph.append({"kind": "NODE", "record": event, "source_bindings": source_bindings,
                                 "record_binding": {**record_binding, "pointer": ""}})
            i4_records.append(canonical_json(node))
            node_views.append({"id": event["event_id"], "type": "EVENT", "source": source_name,
                               "evidence_identity": bindings[source_name]["sha256"], "relation": relation,
                               "reference": {"corpus_path": source_name, "pointer": pointer},
                               "confidence": "SELF_REPORTED_ENGINEERING_OBSERVATION_VERIFIED_BY_REPLAY"})
        edge_specs = ([
            ("transfer_event", "metadata_event", "pipeline_transfer.json", "/documents", "EXACT_METADATA_TRANSFER_REFERENCE"),
            ("input_event", "transfer_event", "input.json", "/values", "EXACT_TOTALS_INPUT_REFERENCE"),
            ("provider_event", "input_event", "request.json", "/values", "ENGINEERING_DERIVATION_REFERENCE"),
            ("consumer_event", "provider_event", "consumer.stdout", "/processed_sha256", "ENGINEERING_RECOMPUTATION_REFERENCE"),
        ] if transfer is not None else [
            ("provider_event", "input_event", "request.json", "/values", "ENGINEERING_DERIVATION_REFERENCE"),
            ("consumer_event", "provider_event", "consumer.stdout", "/processed_sha256", "ENGINEERING_RECOMPUTATION_REFERENCE"),
        ])
        for source_key, target_key, source_name, pointer, relation in edge_specs:
            source_id, target_id = ids[source_key], ids[target_key]
            source_event = next(item[0] for item in graph_nodes if item[0]["event_id"] == source_id)
            source_event_binding = next(item[2] for item in graph_nodes if item[0]["event_id"] == source_id)
            caused_by = source_event["caused_by_ids"]
            edge = graph.append({"kind": "EDGE", "edge_type": "caused_by_ids", "source_id": source_id,
                                 "target_id": target_id,
                                 "source_bindings": [bindings[source_name], bindings["ENGINEERING_DERIVATION.json"], source_event_binding],
                                 "basis": {"kind": "EXPLICIT_REFERENCE", "corpus_path": source_key + ".json",
                                           "pointer": "/caused_by_ids", "value": caused_by,
                                           "binding_value": target_id}})
            i4_records.append(canonical_json(edge))
            edge_views.append({"id": _sha(canonical_json(edge)), "type": "caused_by_ids",
                               "source_id": source_id, "target_id": target_id, "relation": relation,
                               "source": source_name, "evidence_identity": bindings[source_name]["sha256"],
                               "reference": {"corpus_path": source_name, "pointer": pointer},
                               "confidence": "SELF_REPORTED_ENGINEERING_DERIVATION_VERIFIED_BY_REPLAY"})
        require_dag(graph.nodes, graph.edges)
        graph_doc = {"schema_version": "pg_i7.causal-graph.v1", "status": "DERIVED_UNQUALIFIED_ENGINEERING_GRAPH",
                     "graph_root": graph.root(), "node_count": len(graph.nodes), "edge_count": len(graph.edges),
                     "nodes": node_views, "edges": edge_views,
                     "source_corpus_manifest_sha256": corpus.manifest_sha256,
                     "i4_interface": ["CausalGraph.append", "CausalGraph.rebuild", "require_dag"],
                     "derivation": proof, "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED",
                     "i5_binding": "NOT_BOUND_TO_THIS_GRAPH",
                     "limitations": ["Self-reported local Engineering observations only.",
                                     "No historical identity, signed closure, custody, or operational acceptance is asserted.",
                                     "Every edge is checked against exact input, request, provider, consumer, result, and recovery bytes."]}
        graph_raw, dot_raw = canonical_json(graph_doc), _dot(graph_doc)
        _write_new(destination / "CAUSAL_GRAPH.json", graph_raw)
        _write_new(destination / "CAUSAL_GRAPH.dot", dot_raw)
        for index, raw in enumerate(i4_records):
            _write_new(destination / "i4_graph_records" / f"record-{index:03d}.json", raw)
        rebuilt = CausalGraph.rebuild(corpus, [path.read_bytes() for path in sorted((destination / "i4_graph_records").glob("record-*.json"))])
        require_dag(rebuilt.nodes, rebuilt.edges)
        if _projection(rebuilt, graph_doc, i4_pointer) is not True:
            raise EvidenceSidecarError("I4 graph projection differs after reconstruction")
        produced["artifacts"]["causal_graph"] = {"path": str(destination / "CAUSAL_GRAPH.json"),
                                                   "sha256": sha256_bytes(graph_raw), "byte_length": len(graph_raw)}
        produced["artifacts"]["causal_graph_dot"] = {"path": str(destination / "CAUSAL_GRAPH.dot"),
                                                       "sha256": sha256_bytes(dot_raw), "byte_length": len(dot_raw)}
        produced["i4"] = {"graph_root": rebuilt.root(), "nodes": len(rebuilt.nodes), "edges": len(rebuilt.edges),
                           "signed_tip": False, "closure": False, "recovery_replay": "REJECTED_AS_EXPECTED"}

    if enabled["provenance"]:
        provenance = {"schema_version": "pg_i7.provenance.v1", "operation_id": operation_id,
                      "actor_declared": actor or "UNKNOWN", "model_declared": "UNKNOWN", "model_effective": "UNKNOWN",
                      "tool": "pg_i7.py / evidence_sidecar.py", "provider_id": provider_id,
                      "inputs": [{"sha256": input_doc.get("input_sha256", "UNKNOWN"), "ref": "CLI_INPUT_BYTES"}],
                      "outputs": [{"sha256": result_doc.get("result_sha256", result_hash), "ref": "CLI_RESULT_RECORD"}],
                      "decisions": [{"decision": "PROVIDER_ALLOWLIST_AND_INPUT_SCHEMA_VALIDATION",
                                     "reference": "local composition registry and CLI validation"}],
                      "references": [{"kind": "INPUT_RECORD", "sha256": input_hash},
                                     {"kind": "RESULT_RECORD", "sha256": result_hash}],
                      "verified_execution_chain": {"request_sha256": checked_chain["request"]["sha256"],
                                                    "provider_stdout_sha256": checked_chain["provider"]["sha256"],
                                                    "consumer_stdout_sha256": checked_chain["consumer"]["sha256"],
                                                    "engine_result_sha256": checked_chain["engine_result"]["sha256"],
                                                    "recovery_status": checked_chain["recovery"]["status"]},
                      "confidence": "SELF_REPORTED_ENGINEERING_ATTRIBUTION",
                      "i4_graph_binding": "NOT_BOUND",
                      "limitations": ["No effective model identity, custodian, or operational authority is asserted.",
                                      "The following frozen I5 fixture exercise is separate and wholly synthetic."]}
        cat_root = destination / "i5_fixture_exercise"
        if Catalog is None:
            raise EvidenceSidecarError("FROZEN_I5_NATIVE_FIXTURES_NOT_DISTRIBUTED")
        cat = Catalog(cat_root, level="SYNTHETIC")
        cat.bootstrap()
        fixture_operation = cat.operation("frozen I5 synthetic fixture exercise",
                                          context={"phase": "I5_FIXTURE", "scope": ["SYNTHETIC_FIXTURE_ONLY"]})
        fixture_task = cat.task("synthetic fixture task", fixture_operation, cat.ids["luna"],
                                objective="Exercise frozen I5 fixture admission only", level="SYNTHETIC")
        report_raw = canonical_json({"report": "synthetic I5 fixture only", "model_effective": "UNKNOWN",
                                     "operational_admission": "NOT_PROVEN"})
        fixture_report = cat.report("synthetic fixture report", fixture_task, raw=report_raw, level="SYNTHETIC")
        ledger = ProvenanceLedger(cat.corpus, cat.i4_bytes, cat.contexts)
        for row in cat.rows:
            ledger.append(row)
        looked_up = ledger.lookup(fixture_report["record"]["report_id"], "REPORT")
        if looked_up["metadata"]["evidence_level"] != "SYNTHETIC":
            raise EvidenceSidecarError("frozen I5 lookup did not preserve SYNTHETIC classification")
        provenance["i5_fixture_exercise"] = {"status": "PASS_SYNTHETIC_FIXTURE_EXERCISE",
                                              "interface": ["ProvenanceLedger.append", "ProvenanceLedger.lookup"],
                                              "record_count": len(ledger.records),
                                              "report_id": fixture_report["record"]["report_id"],
                                              "evidence_level": "SYNTHETIC", "i4_fingerprint": _FIXTURE_SHA,
                                              "fixture_actor_identity": "SYNTHETIC_CATALOG_HANDLE_ONLY",
                                              "current_run_attribution": False,
                                              "fixture_i4_is_current_engineering_graph": False,
                                              "publisher": "NONE", "operational_credit": "NONE"}
        current_graph_path = destination / "CAUSAL_GRAPH.json"
        if current_graph_path.is_file():
            # Frozen I5 pins canonical bytes of CausalGraph.semantic_view(),
            # not the display/projection JSON written for this composition.
            current_semantic_raw = canonical_json(rebuilt.semantic_view())
            current_i5 = current_i5_compatibility(current_semantic_raw)
            try:
                ProvenanceLedger(corpus, current_semantic_raw, {})
            except Exception as exc:
                current_i5["frozen_api_constructor"] = "REJECTED_CURRENT_I4_GRAPH"
                current_i5["frozen_api_error_type"] = type(exc).__name__
                current_i5["i5_append_attempted"] = False
            else:
                current_i5["frozen_api_constructor"] = "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED"
                current_i5["i5_append_attempted"] = False
        else:
            current_i5 = {
                "status": "BLOCKED_CURRENT_I4_GRAPH_NOT_PRODUCED",
                "i5_append_attempted": False,
                "attribution": "UNKNOWN",
                "reason": "The current I4 graph is unavailable; a historical fixture is not substituted.",
            }
        provenance["current_i4_i5_integration"] = current_i5
        raw = canonical_json(provenance)
        _write_new(destination / "PROVENANCE.json", raw)
        produced["artifacts"]["provenance"] = {"path": str(destination / "PROVENANCE.json"),
                                                "sha256": sha256_bytes(raw), "byte_length": len(raw)}
        produced["i5"] = provenance["i5_fixture_exercise"]
        produced["i5_current_graph_integration"] = current_i5
    return produced


def build_document_graph(document_scan_dir: str | os.PathLike[str], independent_receipt_path: str | os.PathLike[str],
                        output_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Create a bounded I4 observation graph from an already-read document set.

    This path consumes only the committed Stage B ledger and the independently
    produced byte-verification receipt. It never rereads Engineering sources
    and never interprets document references as causal edges.
    """
    (canonical_json, generate_id, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     _, require_dag, SchemaRegistry, ProvenanceLedger, _) = _load_frozen_apis()
    scan_dir = Path(document_scan_dir).resolve(strict=True)
    receipt_path = Path(independent_receipt_path).resolve(strict=True)
    destination = Path(output_dir).resolve(strict=True)
    if not scan_dir.is_dir() or not destination.is_dir() or destination in {scan_dir, receipt_path.parent}:
        raise EvidenceSidecarError("bounded document scan, receipt, and output locations must be distinct")
    manifest_path = scan_dir / "document-scan-manifest.jsonl"
    ledger_path = scan_dir / "document-scan-ledger.jsonl"
    manifest_raw = manifest_path.read_bytes()
    ledger_raw = ledger_path.read_bytes()
    root_receipt_raw = receipt_path.read_bytes()
    manifest_lines = [line for line in manifest_raw.splitlines() if line.strip()]
    if len(manifest_lines) != 1:
        raise EvidenceSidecarError("bounded document manifest must contain exactly one snapshot row")
    manifest = strict_json_loads(manifest_lines[0])
    root_receipt = strict_json_loads(root_receipt_raw)
    snapshot_id = manifest.get("snapshot_id")
    if (manifest.get("schema") != "i7-engineering-document-scan@1"
            or manifest.get("scope") != "EXPLICIT_DOCUMENTS_AND_LITERAL_REFERENTS"
            or manifest.get("coverage_status") != "COMPLETE"
            or manifest.get("read_coverage_status") != "COMPLETE"
            or manifest.get("structure_status") != "EXTRACTED"
            or root_receipt.get("schema") != "pg_i7.root-independent-document-verification.v1"
            or root_receipt.get("status") != "PASS"
            or root_receipt.get("producer_imports") is not False
            or root_receipt.get("snapshot_id") != snapshot_id
            or root_receipt.get("ledger_sha256") != _sha(ledger_raw)):
        raise EvidenceSidecarError("bounded document manifest and independent receipt do not form a coherent exact snapshot")
    ledger_rows = [strict_json_loads(line) for line in ledger_raw.splitlines() if line.strip()]
    files = root_receipt.get("files")
    if not isinstance(files, list) or len(files) != root_receipt.get("unique_files_verified"):
        raise EvidenceSidecarError("independent receipt file rows are incomplete")
    files_by_id: dict[str, dict[str, Any]] = {}
    for row in files:
        path_id, digest, size = row.get("path_id"), row.get("sha256"), row.get("bytes_read")
        if (not isinstance(path_id, str) or len(path_id) != 64 or path_id in files_by_id
                or not isinstance(digest, str) or len(digest) != 64 or not isinstance(size, int) or size < 0):
            raise EvidenceSidecarError("independent receipt has duplicate or malformed file identity")
        files_by_id[path_id] = row
    selected_docs: set[str] = set()
    reference_rows: list[dict[str, Any]] = []
    resolved_count = unknown_count = selected_bytes = all_read_bytes = 0
    for row in ledger_rows:
        path_id = row.get("path_id")
        if not isinstance(path_id, str) or len(path_id) != 64:
            raise EvidenceSidecarError("document ledger contains malformed path identity")
        if row.get("status") != "HASHED" or path_id not in files_by_id:
            raise EvidenceSidecarError("a selected document is not independently byte-verified")
        checked = files_by_id[path_id]
        if row.get("sha256") != checked.get("sha256") or row.get("size") != checked.get("bytes_read"):
            raise EvidenceSidecarError("selected document hash or size differs from independent receipt")
        if path_id in selected_docs:
            raise EvidenceSidecarError("document scan ledger repeats a selected document")
        selected_docs.add(path_id)
        selected_bytes += row["size"]
        all_read_bytes += row["size"]
        row_refs = _paired_document_references(row)
        for ref in row_refs:
            target_id, status = ref.get("target_id"), ref.get("status")
            if not isinstance(target_id, str) or len(target_id) != 64:
                raise EvidenceSidecarError("document reference has malformed target identity")
            if status == "RESOLVED_EXACT_PATH":
                verified_target = files_by_id.get(target_id)
                if (verified_target is None or ref.get("sha256") != verified_target.get("sha256")
                        or ref.get("size") != verified_target.get("bytes_read")):
                    raise EvidenceSidecarError("resolved document reference differs from independent byte receipt")
                resolved_count += 1
                all_read_bytes += ref["size"]
                target_sha = ref["sha256"]
                target_size = ref["size"]
            elif status == "MISSING_OR_UNRESOLVED":
                if ref.get("sha256") is not None or ref.get("size") is not None:
                    raise EvidenceSidecarError("unknown document reference has fabricated target bytes")
                unknown_count += 1
                target_sha = target_size = None
            else:
                raise EvidenceSidecarError("document reference has an unrecognized resolution status")
            reference_rows.append({"snapshot_id": snapshot_id, "source_id": path_id,
                                   "source_sha256": row["sha256"], "target_id": target_id,
                                   "target_sha256": target_sha, "target_byte_length": target_size,
                                   "status": "VERIFIED_DOCUMENT_REFERENCE" if target_sha else "UNKNOWN_REFERENT",
                                   "relation": "DOCUMENT_REFERENCE", "causal": False})
    if (len(selected_docs) != manifest.get("document_count") or len(selected_docs) != root_receipt.get("documents")
            or all_read_bytes != manifest.get("document_bytes_read")
            or len(reference_rows) != manifest.get("explicit_reference_count")
            or resolved_count != manifest.get("reference_resolved_count")
            or unknown_count != manifest.get("reference_unknown_count")
            or resolved_count != root_receipt.get("resolved_references")
            or unknown_count != root_receipt.get("unresolved_references")
            or len(files_by_id) != root_receipt.get("unique_files_expected")
            or sum(row["bytes_read"] for row in files_by_id.values()) != root_receipt.get("actual_bytes_read")):
        raise EvidenceSidecarError("bounded document counters differ from committed ledger or independent receipt")
    reference_rows.sort(key=lambda row: (row["source_id"], row["target_id"], row["status"]))
    references_raw = b"".join(canonical_json(row) + b"\n" for row in reference_rows)
    manifest_commitment = {"snapshot_id": snapshot_id, "scan_manifest_sha256": _sha(manifest_raw),
                           "scan_manifest_byte_length": len(manifest_raw), "scan_ledger_sha256": _sha(ledger_raw),
                           "scan_ledger_byte_length": len(ledger_raw), "document_count": len(selected_docs),
                           "document_bytes_read": all_read_bytes, "selected_document_unique_bytes": selected_bytes,
                           "explicit_reference_count": len(reference_rows),
                           "resolved_reference_count": resolved_count, "unknown_reference_count": unknown_count,
                           "structure_status": manifest["structure_status"], "scope": manifest["scope"]}
    reference_commitment = {"snapshot_id": snapshot_id, "artifact": "DOCUMENT_REFERENCES.jsonl",
                            "sha256": _sha(references_raw), "byte_length": len(references_raw),
                            "row_count": len(reference_rows), "resolved_count": resolved_count,
                            "unknown_count": unknown_count, "semantics": "DOCUMENTARY_ONLY_NO_CAUSAL_EDGES"}
    receipt_summary = {key: root_receipt[key] for key in (
        "schema", "status", "producer_imports", "documents", "resolved_references", "unresolved_references",
        "unique_files_expected", "unique_files_verified", "actual_bytes_read", "ledger_sha256", "snapshot_id")}
    source_receipt = {"schema": "pg_i7.bounded-document-i4-source-receipt.v1", "snapshot_id": snapshot_id,
                      "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "scan_commitment": manifest_commitment,
                      "independent_receipt": receipt_summary, "independent_receipt_sha256": _sha(root_receipt_raw),
                      "independent_receipt_byte_length": len(root_receipt_raw),
                      "document_reference_commitment": reference_commitment,
                      "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN", "model_identity": "UNKNOWN",
                      "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    outputs = {"DOCUMENT_SCAN_MANIFEST.jsonl": manifest_raw, "DOCUMENT_SCAN_LEDGER.jsonl": ledger_raw,
               "ROOT_INDEPENDENT_BYTE_VERIFICATION.json": root_receipt_raw,
               "DOCUMENT_SET_COMMITMENT.json": canonical_json(manifest_commitment),
               "DOCUMENT_REFERENCES.jsonl": references_raw,
               "DOCUMENT_REFERENCE_COMMITMENT.json": canonical_json(reference_commitment),
               "DOCUMENT_I4_SOURCE_RECEIPT.json": canonical_json(source_receipt)}
    for name, raw in outputs.items():
        _write_new(destination / name, raw)
    corpus_sources = {"DOCUMENT_SET_COMMITMENT.json": outputs["DOCUMENT_SET_COMMITMENT.json"],
                      "ROOT_INDEPENDENT_BYTE_VERIFICATION.json": root_receipt_raw,
                      "DOCUMENT_REFERENCE_COMMITMENT.json": outputs["DOCUMENT_REFERENCE_COMMITMENT.json"],
                      "DOCUMENT_I4_SOURCE_RECEIPT.json": outputs["DOCUMENT_I4_SOURCE_RECEIPT.json"]}
    corpus_dir = destination / "i4_document_source_corpus"
    corpus_dir.mkdir(exist_ok=False)
    bindings = {name: {"corpus_path": name, "sha256": sha256_bytes(raw), "byte_length": len(raw)}
                for name, raw in corpus_sources.items()}
    for name, raw in corpus_sources.items():
        _write_new(corpus_dir / name, raw)
    actor_id = generate_id("ACTOR")
    ids = {name: generate_id(kind) for name, kind in (
        ("project_id", "PROJECT"), ("product_id", "PRODUCT"), ("lineage_id", "LINEAGE"),
        ("version_id", "VERSION"), ("session_id", "SESSION"), ("run_id", "RUN"), ("attempt_id", "ATTEMPT"),
        ("scan_event", "EVENT"), ("verification_event", "EVENT"), ("reference_event", "EVENT"))}
    specs = [("scan_event", "DOCUMENT_SET_OBSERVED", "DOCUMENT_SET_COMMITMENT.json"),
             ("verification_event", "INDEPENDENT_BYTE_VERIFICATION_OBSERVED", "ROOT_INDEPENDENT_BYTE_VERIFICATION.json"),
             ("reference_event", "DOCUMENTARY_REFERENCE_SET_OBSERVED", "DOCUMENT_REFERENCE_COMMITMENT.json")]
    occurred, schemas, events, records, views = _utc_now(), SchemaRegistry(), [], [], []
    for sequence, (key, role, source_name) in enumerate(specs, 1):
        ids["event_id"] = ids[key]
        event = _make_event(generate_id, schemas, ids=ids, actor_id=actor_id, role=role,
                            sequence=sequence, occurred=occurred, payload_sha=bindings[source_name]["sha256"])
        event_raw = canonical_json(event)
        event_name = key + ".json"
        _write_new(corpus_dir / event_name, event_raw)
        event_binding = {"corpus_path": event_name, "sha256": sha256_bytes(event_raw), "byte_length": len(event_raw)}
        events.append((event, source_name, event_binding))
    corpus_manifest_raw = canonical_json({"files": sorted([*bindings.values(), *[
        row[2] for row in events]], key=lambda row: row["corpus_path"])})
    _write_new(corpus_dir / "manifest.json", corpus_manifest_raw)
    corpus = SourceCorpus(corpus_dir, strict_json_loads(corpus_manifest_raw), sha256_bytes(corpus_manifest_raw),
                          manifest_bytes=corpus_manifest_raw)
    graph = CausalGraph(corpus)
    for event, source_name, event_binding in events:
        node = graph.append({"kind": "NODE", "record": event,
                             "source_bindings": [bindings[source_name], bindings["DOCUMENT_I4_SOURCE_RECEIPT.json"], event_binding],
                             "record_binding": {**event_binding, "pointer": ""}})
        raw = canonical_json(node)
        records.append(raw)
        _write_new(destination / "i4_document_graph_records" / f"record-{len(records)-1:03d}.json", raw)
        views.append({"id": event["event_id"], "type": "EVENT", "source": source_name,
                      "evidence_identity": bindings[source_name]["sha256"], "relation": "OBSERVATION_ONLY",
                      "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN", "causal_edges": []})
    require_dag(graph.nodes, graph.edges)
    graph_doc = {"schema_version": "pg_i7.bounded-document-i4-graph.v1",
                 "status": "DERIVED_UNQUALIFIED_BOUNDED_DOCUMENT_GRAPH", "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION",
                 "snapshot_id": snapshot_id, "graph_root": graph.root(), "node_count": len(graph.nodes),
                 "edge_count": 0, "nodes": views, "edges": [],
                 "documentary_reference_artifact": reference_commitment,
                 "source_corpus_manifest_sha256": sha256_bytes(corpus_manifest_raw),
                 "i4_interface": ["CausalGraph.append", "CausalGraph.rebuild", "require_dag"],
                 "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED", "i5_binding": "NOT_BOUND"}
    graph_raw = canonical_json(graph_doc)
    _write_new(destination / "REAL_DOCUMENT_I4_GRAPH.json", graph_raw)
    _write_new(destination / "REAL_DOCUMENT_I4_GRAPH.dot", _dot(graph_doc))
    rebuilt = CausalGraph.rebuild(corpus, records)
    require_dag(rebuilt.nodes, rebuilt.edges)
    if rebuilt.root() != graph.root() or rebuilt.edges:
        raise EvidenceSidecarError("bounded document graph rebuild mismatch")
    semantic_raw = canonical_json(rebuilt.semantic_view())
    i5 = current_i5_compatibility(semantic_raw)
    try:
        ProvenanceLedger(corpus, semantic_raw, {})
    except Exception as exc:
        i5.update({"frozen_api_constructor": "REJECTED_CURRENT_I4_GRAPH", "frozen_api_error_type": type(exc).__name__,
                   "i5_append_attempted": False})
    else:
        i5.update({"frozen_api_constructor": "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED", "i5_append_attempted": False})
    integration = {"schema": "pg_i7.bounded-document-i4-i5-integration.v1",
                   "status": i5["status"], "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "snapshot_id": snapshot_id,
                   "i4_graph_status": graph_doc["status"], "i4_graph_root": rebuilt.root(),
                   "i4_nodes": len(rebuilt.nodes), "i4_edges": len(rebuilt.edges),
                   "i4_semantic_sha256": _sha(semantic_raw), "i4_projection_sha256": _sha(graph_raw),
                   "i4_rebuild": "PASS", "current_i4_i5_integration": i5,
                   "document_reference_rows": len(reference_rows), "verified_document_references": resolved_count,
                   "unknown_referents": unknown_count, "documentary_references_are_causal": False,
                   "attribution": "UNKNOWN", "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    _write_new(destination / "REAL_DOCUMENT_I5_INTEGRATION.json", canonical_json(integration))
    _write_new(destination / "PROVENANCE.json", canonical_json({"schema": "pg_i7.bounded-document-provenance.v1",
        "status": "DERIVED_UNQUALIFIED_OBSERVATION_ONLY", "snapshot_id": snapshot_id,
        "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "actor_class": "TOOL_OBSERVER",
        "actor_authenticity": "UNKNOWN", "model_identity": "UNKNOWN", "operational_authority": "NONE_ASSERTED",
        "i5_status": i5["status"], "i5_append_attempted": False,
        "independent_verification_receipt_sha256": _sha(root_receipt_raw), "document_reference_commitment": reference_commitment,
        "causal_edges": 0, "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}))
    verification = verify_document_graph(destination, expected_snapshot_id=snapshot_id)
    return {**integration, "semantic_verification": verification,
            "independent_verification": {"status": root_receipt["status"], "unique_files_verified": len(files_by_id),
                                         "actual_bytes_read": root_receipt["actual_bytes_read"]}}


def verify_document_graph(output_dir: str | os.PathLike[str], *, expected_snapshot_id: str) -> dict[str, Any]:
    """Reconstruct bounded Stage B graph and reject rehashed semantic forgeries."""
    (canonical_json, _, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     _, require_dag, _, ProvenanceLedger, _) = _load_frozen_apis()
    base = Path(output_dir).resolve(strict=True)
    corpus_dir = base / "i4_document_source_corpus"
    manifest_raw = (corpus_dir / "manifest.json").read_bytes()
    manifest = strict_json_loads(manifest_raw)
    corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
    record_paths = sorted((base / "i4_document_graph_records").glob("record-*.json"))
    raw_records = [path.read_bytes() for path in record_paths]
    if len(raw_records) != 3:
        raise EvidenceSidecarError("bounded document graph must have exactly three observation records")
    graph = CausalGraph.rebuild(corpus, raw_records)
    require_dag(graph.nodes, graph.edges)
    graph_doc = strict_json_loads((base / "REAL_DOCUMENT_I4_GRAPH.json").read_bytes())
    source_receipt = strict_json_loads(corpus.read("DOCUMENT_I4_SOURCE_RECEIPT.json"))
    commitment = strict_json_loads(corpus.read("DOCUMENT_REFERENCE_COMMITMENT.json"))
    root_receipt_raw = corpus.read("ROOT_INDEPENDENT_BYTE_VERIFICATION.json")
    root_receipt = strict_json_loads(root_receipt_raw)
    references_raw = (base / "DOCUMENT_REFERENCES.jsonl").read_bytes()
    manifest_raw_b = (base / "DOCUMENT_SCAN_MANIFEST.jsonl").read_bytes()
    ledger_raw = (base / "DOCUMENT_SCAN_LEDGER.jsonl").read_bytes()
    scan_commitment = strict_json_loads(corpus.read("DOCUMENT_SET_COMMITMENT.json"))
    manifest_rows = [strict_json_loads(line) for line in manifest_raw_b.splitlines() if line.strip()]
    ledger_rows = [strict_json_loads(line) for line in ledger_raw.splitlines() if line.strip()]
    verified_files = root_receipt.get("files", [])
    files_by_id = {row.get("path_id"): row for row in verified_files if isinstance(row, dict)}
    if len(manifest_rows) != 1 or len(files_by_id) != len(verified_files):
        raise EvidenceSidecarError("bounded document manifest or independent file list is malformed")
    manifest_row = manifest_rows[0]
    reconstructed_references = []
    resolved = unknown = doc_bytes = all_read_bytes = 0
    seen_docs: set[str] = set()
    for row in ledger_rows:
        path_id = row.get("path_id")
        checked = files_by_id.get(path_id)
        if (not isinstance(path_id, str) or checked is None or row.get("status") != "HASHED"
                or row.get("sha256") != checked.get("sha256") or row.get("size") != checked.get("bytes_read")
                or path_id in seen_docs):
            raise EvidenceSidecarError("stored selected document differs from independent receipt")
        seen_docs.add(path_id); doc_bytes += row["size"]; all_read_bytes += row["size"]
        for ref in _paired_document_references(row):
            target_id, status = ref.get("target_id"), ref.get("status")
            if status == "RESOLVED_EXACT_PATH":
                target = files_by_id.get(target_id)
                if (target is None or target.get("sha256") != ref.get("sha256")
                        or target.get("bytes_read") != ref.get("size")):
                    raise EvidenceSidecarError("stored resolved reference differs from independent receipt")
                resolved += 1; all_read_bytes += ref["size"]
                target_sha = ref["sha256"]; target_size = ref["size"]
            elif status == "MISSING_OR_UNRESOLVED" and ref.get("sha256") is None and ref.get("size") is None:
                unknown += 1; target_sha = target_size = None
            else:
                raise EvidenceSidecarError("stored unresolved reference carries false status or bytes")
            reconstructed_references.append({"snapshot_id": expected_snapshot_id, "source_id": path_id,
                "source_sha256": row["sha256"], "target_id": target_id, "target_sha256": target_sha,
                "target_byte_length": target_size,
                "status": "VERIFIED_DOCUMENT_REFERENCE" if target_sha else "UNKNOWN_REFERENT",
                "relation": "DOCUMENT_REFERENCE", "causal": False})
    reconstructed_references.sort(key=lambda row: (row["source_id"], row["target_id"], row["status"]))
    expected_references_raw = b"".join(canonical_json(row) + b"\n" for row in reconstructed_references)
    expected_scan_commitment = {"snapshot_id": expected_snapshot_id, "scan_manifest_sha256": _sha(manifest_raw_b),
        "scan_manifest_byte_length": len(manifest_raw_b), "scan_ledger_sha256": _sha(ledger_raw),
        "scan_ledger_byte_length": len(ledger_raw), "document_count": len(seen_docs),
        "document_bytes_read": all_read_bytes, "selected_document_unique_bytes": doc_bytes,
        "explicit_reference_count": len(reconstructed_references),
        "resolved_reference_count": resolved, "unknown_reference_count": unknown,
        "structure_status": manifest_row.get("structure_status"), "scope": manifest_row.get("scope")}
    expected_ref_commitment = {"snapshot_id": expected_snapshot_id, "artifact": "DOCUMENT_REFERENCES.jsonl",
        "sha256": _sha(expected_references_raw), "byte_length": len(expected_references_raw),
        "row_count": len(reconstructed_references), "resolved_count": resolved, "unknown_count": unknown,
        "semantics": "DOCUMENTARY_ONLY_NO_CAUSAL_EDGES"}
    receipt_summary = {key: root_receipt.get(key) for key in (
        "schema", "status", "producer_imports", "documents", "resolved_references", "unresolved_references",
        "unique_files_expected", "unique_files_verified", "actual_bytes_read", "ledger_sha256", "snapshot_id")}
    expected_source_receipt = {"schema": "pg_i7.bounded-document-i4-source-receipt.v1",
        "snapshot_id": expected_snapshot_id, "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION",
        "scan_commitment": expected_scan_commitment, "independent_receipt": receipt_summary,
        "independent_receipt_sha256": _sha(root_receipt_raw),
        "independent_receipt_byte_length": len(root_receipt_raw),
        "document_reference_commitment": expected_ref_commitment,
        "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN", "model_identity": "UNKNOWN",
        "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    if (source_receipt.get("snapshot_id") != expected_snapshot_id or root_receipt.get("snapshot_id") != expected_snapshot_id
            or root_receipt.get("status") != "PASS" or root_receipt.get("ledger_sha256") != _sha(ledger_raw)
            or manifest_row.get("snapshot_id") != expected_snapshot_id
            or manifest_row.get("document_count") != len(seen_docs)
            or manifest_row.get("explicit_reference_count") != len(reconstructed_references)
            or manifest_row.get("reference_resolved_count") != resolved
            or manifest_row.get("reference_unknown_count") != unknown
            or manifest_row.get("document_bytes_read") != all_read_bytes
            or root_receipt.get("documents") != len(seen_docs)
            or root_receipt.get("resolved_references") != resolved
            or root_receipt.get("unresolved_references") != unknown
            or _sha(expected_references_raw) != _sha(references_raw)
            or scan_commitment != expected_scan_commitment
            or source_receipt != expected_source_receipt
            or scan_commitment.get("snapshot_id") != expected_snapshot_id
            or scan_commitment.get("scan_manifest_sha256") != _sha(manifest_raw_b)
            or scan_commitment.get("scan_ledger_sha256") != _sha(ledger_raw)
            or commitment.get("snapshot_id") != expected_snapshot_id
            or commitment.get("sha256") != _sha(references_raw)
            or source_receipt.get("independent_receipt_sha256") != _sha(root_receipt_raw)):
        raise EvidenceSidecarError("bounded document source commitments do not reconstruct")
    views = []
    allowed = {"DOCUMENT_SET_COMMITMENT.json": "ENGINEERING_DOCUMENT_SET_OBSERVED",
               "ROOT_INDEPENDENT_BYTE_VERIFICATION.json": "ENGINEERING_INDEPENDENT_BYTE_VERIFICATION_OBSERVED",
               "DOCUMENT_REFERENCE_COMMITMENT.json": "ENGINEERING_DOCUMENTARY_REFERENCE_SET_OBSERVED"}
    source_by_hash = {binding["sha256"]: binding["corpus_path"] for binding in manifest["files"]}
    for raw in raw_records:
        node = strict_json_loads(raw); event = node["record"]
        source_name = source_by_hash.get(event.get("payload_sha256"))
        if source_name not in allowed or event.get("event_kind") != allowed[source_name]:
            raise EvidenceSidecarError("bounded document graph event source or role differs")
        views.append({"id": event["event_id"], "type": "EVENT", "source": source_name,
                      "evidence_identity": event["payload_sha256"], "relation": "OBSERVATION_ONLY",
                      "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN", "causal_edges": []})
    expected_graph = {"schema_version": "pg_i7.bounded-document-i4-graph.v1",
                      "status": "DERIVED_UNQUALIFIED_BOUNDED_DOCUMENT_GRAPH",
                      "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "snapshot_id": expected_snapshot_id,
                      "graph_root": graph.root(), "node_count": 3, "edge_count": 0, "nodes": views, "edges": [],
                      "documentary_reference_artifact": commitment,
                      "source_corpus_manifest_sha256": corpus.manifest_sha256,
                      "i4_interface": ["CausalGraph.append", "CausalGraph.rebuild", "require_dag"],
                      "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED", "i5_binding": "NOT_BOUND"}
    if graph.edges or graph_doc != expected_graph or (base / "REAL_DOCUMENT_I4_GRAPH.dot").read_bytes() != _dot(graph_doc):
        raise EvidenceSidecarError("bounded document I4 graph projection differs from exact rebuilt graph")
    semantic_raw = canonical_json(graph.semantic_view())
    expected_i5 = current_i5_compatibility(semantic_raw)
    try:
        ProvenanceLedger(corpus, semantic_raw, {})
    except Exception as exc:
        expected_i5.update({"frozen_api_constructor": "REJECTED_CURRENT_I4_GRAPH", "frozen_api_error_type": type(exc).__name__,
                            "i5_append_attempted": False})
    else:
        expected_i5.update({"frozen_api_constructor": "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED", "i5_append_attempted": False})
    integration = strict_json_loads((base / "REAL_DOCUMENT_I5_INTEGRATION.json").read_bytes())
    expected_result = {"schema": "pg_i7.bounded-document-i4-i5-integration.v1", "status": expected_i5["status"],
                       "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "snapshot_id": expected_snapshot_id,
                       "i4_graph_status": expected_graph["status"], "i4_graph_root": graph.root(),
                       "i4_nodes": 3, "i4_edges": 0, "i4_semantic_sha256": _sha(semantic_raw),
                       "i4_projection_sha256": _sha(canonical_json(expected_graph)), "i4_rebuild": "PASS",
                       "current_i4_i5_integration": expected_i5,
                       "document_reference_rows": commitment["row_count"],
                       "verified_document_references": commitment["resolved_count"],
                       "unknown_referents": commitment["unknown_count"], "documentary_references_are_causal": False,
                       "attribution": "UNKNOWN", "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    if integration != expected_result:
        raise EvidenceSidecarError("bounded document I4/I5 integration receipt differs from reconstructed API result")
    expected_provenance = {"schema": "pg_i7.bounded-document-provenance.v1",
        "status": "DERIVED_UNQUALIFIED_OBSERVATION_ONLY", "snapshot_id": expected_snapshot_id,
        "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "actor_class": "TOOL_OBSERVER",
        "actor_authenticity": "UNKNOWN", "model_identity": "UNKNOWN", "operational_authority": "NONE_ASSERTED",
        "i5_status": expected_i5["status"], "i5_append_attempted": False,
        "independent_verification_receipt_sha256": _sha(root_receipt_raw),
        "document_reference_commitment": commitment, "causal_edges": 0,
        "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    if strict_json_loads((base / "PROVENANCE.json").read_bytes()) != expected_provenance:
        raise EvidenceSidecarError("bounded document provenance differs from reconstructed evidence and authority limits")
    return {"status": "PASS", "scope": "EXPLICIT_EIGHT_DOCUMENT_FOCUSED_SELECTION", "snapshot_id": expected_snapshot_id,
            "i4_nodes": 3, "i4_edges": 0, "i4_semantic_sha256": _sha(semantic_raw),
            "i5_status": expected_i5["status"], "attribution": "UNKNOWN",
            "forged_projection_and_integration_rejected_by_reconstruction": True}


def _projection(graph: Any, graph_doc: Mapping[str, Any], pointer_fn) -> bool:
    node_by_id = graph.nodes
    if set(node_by_id) != {row.get("id") for row in graph_doc.get("nodes", [])}:
        return False
    expected_nodes = {}
    for entity, node in node_by_id.items():
        expected_nodes[entity] = {"id": entity, "type": graph.envelope(node)["entity_type"]}
    role_sources = {
        "DOCUMENT_METADATA_PRODUCED": ("pipeline_transfer.json", "OBSERVES_HASHED_DOCUMENT_METADATA", "/documents"),
        "PROVIDER_INPUT_TRANSFORMED": ("pipeline_transfer.json", "OBSERVES_EXACT_METADATA_TO_TOTALS_TRANSFER", "/stage_b_values"),
        "INPUT_OBSERVED": ("input.json", "OBSERVES_CLI_INPUT", "/values"),
        "PROVIDER_OUTPUT_OBSERVED": ("provider.stdout", "OBSERVES_VERIFIED_PROVIDER_OUTPUT", "/request_id"),
        "CONSUMER_RECOMPUTATION_OBSERVED": ("consumer.stdout", "OBSERVES_VERIFIED_CONSUMER_RECOMPUTATION", "/processed_sha256"),
    }
    role_by_id = {node["record"]["event_id"]: node["record"].get("event_kind", "").removeprefix("ENGINEERING_")
                  for node in node_by_id.values()}
    expected_node_rows = {
        node["record"]["event_id"]: {"id": node["record"]["event_id"], "type": "EVENT",
                                      "source": role_sources[role_by_id[node["record"]["event_id"]]][0],
                                      "evidence_identity": node["record"]["payload_sha256"],
                                      "relation": role_sources[role_by_id[node["record"]["event_id"]]][1],
                                      "reference": {"corpus_path": role_sources[role_by_id[node["record"]["event_id"]]][0],
                                                    "pointer": role_sources[role_by_id[node["record"]["event_id"]]][2]},
                                      "confidence": "SELF_REPORTED_ENGINEERING_OBSERVATION_VERIFIED_BY_REPLAY"}
        for node in node_by_id.values()
    }
    if len(graph_doc.get("nodes", [])) != len(expected_node_rows):
        return False
    for row in graph_doc.get("nodes", []):
        expected = expected_nodes[row["id"]]
        if row != expected_node_rows.get(row.get("id")):
            return False
    semantic_edges = graph.edges
    observed_edges = {(row.get("type"), row.get("source_id"), row.get("target_id")) for row in graph_doc.get("edges", [])}
    actual_edges = {(row.get("edge_type"), row.get("source_id"), row.get("target_id")) for row in semantic_edges}
    if observed_edges != actual_edges or len(observed_edges) != len(graph_doc.get("edges", [])):
        return False
    edge_declarations = [
        ("PROVIDER_OUTPUT_OBSERVED", "INPUT_OBSERVED", "request.json", "/values", "ENGINEERING_DERIVATION_REFERENCE"),
        ("CONSUMER_RECOMPUTATION_OBSERVED", "PROVIDER_OUTPUT_OBSERVED", "consumer.stdout", "/processed_sha256", "ENGINEERING_RECOMPUTATION_REFERENCE"),
    ]
    if "DOCUMENT_METADATA_PRODUCED" in role_by_id.values():
        edge_declarations = [
            ("PROVIDER_INPUT_TRANSFORMED", "DOCUMENT_METADATA_PRODUCED", "pipeline_transfer.json", "/documents", "EXACT_METADATA_TRANSFER_REFERENCE"),
            ("INPUT_OBSERVED", "PROVIDER_INPUT_TRANSFORMED", "input.json", "/values", "EXACT_TOTALS_INPUT_REFERENCE"),
            *edge_declarations,
        ]
    expected_edge_info = {
        ("caused_by_ids", source_id, target_id): (source_name, pointer, relation)
        for source_role, target_role, source_name, pointer, relation in edge_declarations
        for source_id in [entity for entity, role in role_by_id.items() if role == source_role]
        for target_id in [entity for entity, role in role_by_id.items() if role == target_role]
    }
    if len(graph_doc.get("edges", [])) != len(expected_edge_info):
        return False
    raw_edge_ids = {}
    for raw in graph.records:
        record = json.loads(raw.decode("utf-8"))
        if record.get("kind") == "EDGE":
            raw_edge_ids[(record.get("edge_type"), record.get("source_id"), record.get("target_id"))] = _sha(raw)
    for row in graph_doc.get("edges", []):
        key = (row.get("type"), row.get("source_id"), row.get("target_id"))
        expected = expected_edge_info.get(key)
        if not expected or row.get("id") != raw_edge_ids.get(key):
            return False
        source_name, pointer, relation = expected
        if (row.get("relation") != relation or row.get("source") != source_name
                or row.get("reference") != {"corpus_path": source_name, "pointer": pointer}
                or row.get("confidence") != "SELF_REPORTED_ENGINEERING_DERIVATION_VERIFIED_BY_REPLAY"):
            return False
    source_by_path = {binding["corpus_path"]: binding for value in node_by_id.values()
                      for binding in value.get("source_bindings", [])}
    source_by_path.update({binding["corpus_path"]: binding for value in semantic_edges
                           for binding in value.get("source_bindings", [])})
    for row in graph_doc.get("nodes", []) + graph_doc.get("edges", []):
        ref = row.get("reference", {})
        binding = source_by_path.get(ref.get("corpus_path"))
        if not binding or row.get("evidence_identity") != binding.get("sha256"):
            return False
        try:
            observed = pointer_fn(json.loads(graph.corpus.read(ref["corpus_path"]).decode("utf-8")), ref.get("pointer", ""))
        except (KeyError, TypeError, ValueError, UnicodeError):
            return False
        role = role_by_id.get(row.get("id"))
        if role == "DOCUMENT_METADATA_PRODUCED" and observed != json.loads(graph.corpus.read("pipeline_transfer.json").decode("utf-8"))["documents"]:
            return False
        if role == "PROVIDER_INPUT_TRANSFORMED" and observed != graph_doc["derivation"]["input"]["values"]:
            return False
        if role == "INPUT_OBSERVED" and observed != graph_doc["derivation"]["input"]["values"]:
            return False
        if role == "PROVIDER_OUTPUT_OBSERVED" and observed != graph_doc["derivation"]["request"]["request_id"]:
            return False
        if role == "CONSUMER_RECOMPUTATION_OBSERVED" and observed != graph_doc["derivation"]["provider"]["sha256"]:
            return False
        if row.get("relation") == "ENGINEERING_DERIVATION_REFERENCE" and observed != graph_doc["derivation"]["input"]["values"]:
            return False
        if row.get("relation") == "ENGINEERING_RECOMPUTATION_REFERENCE" and observed != graph_doc["derivation"]["provider"]["sha256"]:
            return False
    return True


def verify_evidence(run_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Reverify sidecar sources, full graph projection, and deterministic DOT view."""
    canonical_json, _, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus, pointer, require_dag, _, ProvenanceLedger, _ = _load_frozen_apis()
    base = Path(run_dir).resolve(strict=True)
    checks: list[dict[str, Any]] = []
    graph_path = base / "CAUSAL_GRAPH.json"
    expected_current_i5: dict[str, Any] | None = None
    if graph_path.exists():
        graph_doc = strict_json_loads(graph_path.read_bytes())
        corpus_dir = base / "i4_source_corpus"
        manifest_raw = (corpus_dir / "manifest.json").read_bytes()
        manifest = strict_json_loads(manifest_raw)
        corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
        for path in sorted((base / "i4_graph_records").glob("record-*.json")):
            strict_json_loads(path.read_bytes())
        graph = CausalGraph.rebuild(corpus, [path.read_bytes() for path in sorted((base / "i4_graph_records").glob("record-*.json"))])
        require_dag(graph.nodes, graph.edges)
        semantic_raw = canonical_json(graph.semantic_view())
        expected_current_i5 = current_i5_compatibility(semantic_raw)
        try:
            ProvenanceLedger(corpus, semantic_raw, {})
        except Exception as exc:
            expected_current_i5["frozen_api_constructor"] = "REJECTED_CURRENT_I4_GRAPH"
            expected_current_i5["frozen_api_error_type"] = type(exc).__name__
            expected_current_i5["i5_append_attempted"] = False
        else:
            expected_current_i5["frozen_api_constructor"] = "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED"
            expected_current_i5["i5_append_attempted"] = False
        if (graph.root() != graph_doc.get("graph_root") or not _projection(graph, graph_doc, pointer)
                or graph_doc.get("node_count") != len(graph.nodes)
                or graph_doc.get("edge_count") != len(graph.edges)
                or graph_doc.get("source_corpus_manifest_sha256") != corpus.manifest_sha256
                or graph_doc.get("status") != "DERIVED_UNQUALIFIED_ENGINEERING_GRAPH"
                or graph_doc.get("closure") != "NOT_CREATED"
                or graph_doc.get("signed_tip") != "NOT_CREATED"
                or graph_doc.get("i5_binding") != "NOT_BOUND_TO_THIS_GRAPH"):
            raise EvidenceSidecarError("causal graph differs from the exact reconstructed I4 projection")
        derivation = graph_doc.get("derivation")
        if not isinstance(derivation, dict):
            raise EvidenceSidecarError("causal graph lacks derivation evidence")
        _contained_attempt(derivation.get("attempt_directory", ""))
        input_source = corpus.read("input.json")
        if _sha(input_source) != derivation.get("input", {}).get("sha256"):
            raise EvidenceSidecarError("graph input evidence identity differs")
        input_doc = strict_json_loads(corpus.read("input_record.json"))
        result_doc = strict_json_loads(corpus.read("result_record.json"))
        verified_proof = _verify_execution_chain(input_doc, result_doc)
        if verified_proof != derivation or strict_json_loads(corpus.read("ENGINEERING_DERIVATION.json")) != derivation:
            raise EvidenceSidecarError("causal derivation differs from read-only attempt reconstruction")
        if not (base / "CAUSAL_GRAPH.dot").is_file() or (base / "CAUSAL_GRAPH.dot").read_bytes() != _dot(graph_doc):
            raise EvidenceSidecarError("DOT export differs from graph JSON projection")
        checks.append({"artifact": "CAUSAL_GRAPH.json", "status": "PASS", "graph_root": graph.root(),
                       "nodes": len(graph.nodes), "edges": len(graph.edges),
                       "closure": "NOT_CREATED", "dot_matches": True})
    if expected_current_i5 is None:
        expected_current_i5 = {
            "status": "BLOCKED_CURRENT_I4_GRAPH_NOT_PRODUCED",
            "i5_append_attempted": False,
            "attribution": "UNKNOWN",
            "reason": "The current I4 graph is unavailable; a historical fixture is not substituted.",
        }
    binding_path = base / "I7_EVIDENCE_BINDING.json"
    binding_doc = strict_json_loads(binding_path.read_bytes()) if binding_path.is_file() else None
    if binding_doc is not None:
        if (binding_doc.get("schema_version") != "pg_i7.evidence-binding.v1"
                or binding_doc.get("claim_scope") != "SELF_REPORTED_ENGINEERING_BINDING_ONLY"):
            raise EvidenceSidecarError("evidence binding schema or scope mismatch")
        input_doc, result_doc = binding_doc.get("input_record"), binding_doc.get("result_record")
        if (not isinstance(input_doc, dict) or not isinstance(result_doc, dict)
                or sha256_bytes(canonical_json(input_doc)) != binding_doc.get("input_record_sha256")
                or sha256_bytes(canonical_json(result_doc)) != binding_doc.get("result_record_sha256")
                or sha256_bytes(canonical_json(input_doc)) != binding_doc.get("input_record_sha256")
                or sha256_bytes(canonical_json(result_doc)) != binding_doc.get("result_record_sha256")):
            raise EvidenceSidecarError("evidence binding record identities mismatch")
        if (binding_doc.get("operation_id") != result_doc.get("operation_id")
                or binding_doc.get("provider_id") != result_doc.get("provider_id")
                or input_doc.get("input_sha256") != result_doc.get("input_sha256")):
            raise EvidenceSidecarError("evidence binding operation, provider, or input identity mismatch")
        if graph_path.exists() and (input_doc != strict_json_loads((base / "i4_source_corpus" / "input_record.json").read_bytes())
                                    or result_doc != strict_json_loads((base / "i4_source_corpus" / "result_record.json").read_bytes())):
            raise EvidenceSidecarError("evidence binding differs from I4 source corpus records")
        checked_chain = _verify_execution_chain(input_doc, result_doc)
        if graph_path.exists() and checked_chain != strict_json_loads(graph_path.read_bytes()).get("derivation"):
            raise EvidenceSidecarError("evidence binding differs from reconstructed I4 derivation")
        checks.append({"artifact": "I7_EVIDENCE_BINDING.json", "status": "PASS",
                       "input_record_sha256": binding_doc["input_record_sha256"],
                       "result_record_sha256": binding_doc["result_record_sha256"]})
    elif any((base / name).exists() for name in ("DATA_DIGEST.json", "PROVENANCE.json")):
        raise EvidenceSidecarError("digest or provenance lacks the exact evidence binding records")
    for name in ("DATA_DIGEST.json", "PROVENANCE.json"):
        path = base / name
        if not path.exists():
            continue
        body = path.read_bytes()
        artifact = strict_json_loads(body)
        if binding_doc is None or checked_chain is None:
            raise EvidenceSidecarError(name + " lacks a verified execution chain")
        if name == "DATA_DIGEST.json":
            raw_input = base64.b64decode(input_doc["input_bytes_base64"], validate=True)
            expected_summary = result_doc["attempt_result"]["CONSUMER_RESULT"]
            expected_sources = [
                {"kind": "INPUT_RECORD", "sha256": binding_doc["input_record_sha256"]},
                {"kind": "RESULT_RECORD", "sha256": binding_doc["result_record_sha256"]},
                {"kind": "PROVIDER_STDOUT", "sha256": checked_chain["provider"]["sha256"]},
                {"kind": "CONSUMER_STDOUT", "sha256": checked_chain["consumer"]["sha256"]},
            ]
            if (artifact.get("schema_version") != "pg_i7.data-digest.v1"
                    or artifact.get("operation_id") != binding_doc["operation_id"]
                    or artifact.get("input", {}).get("path") != input_doc.get("input_path")
                    or artifact.get("input", {}).get("sha256") != _sha(raw_input)
                    or artifact.get("input", {}).get("byte_length") != len(raw_input)
                    or artifact.get("input", {}).get("schema") != input_doc.get("input_schema")
                    or artifact.get("input", {}).get("values") != input_doc.get("values")
                    or artifact.get("input", {}).get("identity_basis") != "EXACT_CLI_INPUT_BYTES"
                    or artifact.get("result", {}).get("sha256") != result_doc.get("result_sha256")
                    or artifact.get("result", {}).get("path") != result_doc.get("result_path")
                    or artifact.get("result", {}).get("status") != result_doc.get("status")
                    or artifact.get("result", {}).get("summary") != expected_summary
                    or artifact.get("result", {}).get("provider_stdout_sha256") != checked_chain["provider"]["sha256"]
                    or artifact.get("result", {}).get("provider_stdout_byte_length") != checked_chain["provider"]["byte_length"]
                    or artifact.get("result", {}).get("consumer_stdout_sha256") != checked_chain["consumer"]["sha256"]
                    or artifact.get("result", {}).get("consumer_stdout_byte_length") != checked_chain["consumer"]["byte_length"]
                    or artifact.get("provider_id") != binding_doc["provider_id"]
                    or artifact.get("sources") != expected_sources):
                raise EvidenceSidecarError("DATA_DIGEST semantic binding or verified summary mismatch")
        else:
            fixture = artifact.get("i5_fixture_exercise", {})
            if (artifact.get("schema_version") != "pg_i7.provenance.v1"
                    or artifact.get("operation_id") != binding_doc["operation_id"]
                    or artifact.get("actor_declared") != binding_doc.get("actor_declared")
                    or artifact.get("model_declared") != "UNKNOWN" or artifact.get("model_effective") != "UNKNOWN"
                    or artifact.get("provider_id") != binding_doc["provider_id"]
                    or artifact.get("inputs") != [{"sha256": input_doc.get("input_sha256"), "ref": "CLI_INPUT_BYTES"}]
                    or artifact.get("outputs") != [{"sha256": result_doc.get("result_sha256"), "ref": "CLI_RESULT_RECORD"}]
                    or artifact.get("confidence") != "SELF_REPORTED_ENGINEERING_ATTRIBUTION"
                    or artifact.get("i4_graph_binding") != "NOT_BOUND"
                    or artifact.get("verified_execution_chain", {}).get("request_sha256") != checked_chain["request"]["sha256"]
                    or artifact.get("verified_execution_chain", {}).get("provider_stdout_sha256") != checked_chain["provider"]["sha256"]
                    or artifact.get("verified_execution_chain", {}).get("consumer_stdout_sha256") != checked_chain["consumer"]["sha256"]
                    or fixture.get("status") != "PASS_SYNTHETIC_FIXTURE_EXERCISE"
                    or fixture.get("evidence_level") != "SYNTHETIC"
                    or fixture.get("i4_fingerprint") != _FIXTURE_SHA
                    or fixture.get("current_run_attribution") is not False
                    or fixture.get("fixture_i4_is_current_engineering_graph") is not False
                    or fixture.get("publisher") != "NONE" or fixture.get("operational_credit") != "NONE"
                    or artifact.get("current_i4_i5_integration") != expected_current_i5
                    or artifact.get("current_i4_i5_integration", {}).get("attribution") != "UNKNOWN"
                    or artifact.get("current_i4_i5_integration", {}).get("i5_append_attempted") is not False):
                raise EvidenceSidecarError("PROVENANCE semantic attribution or frozen I5 fixture boundary mismatch")
        checks.append({"artifact": name, "status": "PASS", "sha256": sha256_bytes(body), "byte_length": len(body)})
    return {"schema_version": "pg_i7.evidence-verification.v1", "status": "PASS", "checks": checks}


def build_corpus_graph(summary_dir: str | os.PathLike[str], output_dir: str | os.PathLike[str],
                       *, snapshot_id: str, scan_verification: Mapping[str, Any],
                       independent_verification: Mapping[str, Any] | None = None,
                       scan_dir: str | os.PathLike[str] | None = None,
                       supplemental_repair_dir: str | os.PathLike[str] | None = None,
                       test_api: bool = False,
                       test_scope_root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Bind compact, verified corpus observations in the frozen I4 graph API.

    This projection is deliberately aggregate: file references remain a separate
    documentary relation artifact, and no document relation becomes causality.
    """
    (canonical_json, generate_id, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     _, require_dag, SchemaRegistry, ProvenanceLedger, _) = _load_frozen_apis()
    summary = Path(summary_dir).resolve(strict=True)
    destination = Path(output_dir).resolve(strict=True)
    if not summary.is_dir() or not destination.is_dir() or summary == destination:
        raise EvidenceSidecarError("corpus summary and output directories must exist and differ")
    verify_counts = [scan_verification.get(name) for name in ("checked_count", "missing_count", "extra_count", "mismatch_count")]
    coherent = (scan_verification.get("expected_snapshot_id") == snapshot_id
                and all(isinstance(value, int) and value >= 0 for value in verify_counts)
                and scan_verification.get("inventory_matches") is
                    (scan_verification.get("snapshot_id") == snapshot_id))
    complete_verification = (scan_verification.get("status") == "VERIFIED"
                             and scan_verification.get("inventory_matches") is True
                             and all(scan_verification.get(name) == 0 for name in ("missing_count", "extra_count", "mismatch_count")))
    partial_verification = (scan_verification.get("status") == "INCOMPLETE_OR_MISMATCH"
                            and (scan_verification.get("inventory_matches") is False
                                 or any(scan_verification.get(name, 0) > 0 for name in ("missing_count", "extra_count", "mismatch_count"))))
    if not coherent or not (complete_verification or partial_verification):
        raise EvidenceSidecarError("corpus graph requires coherent same-snapshot verification with explicit status")
    names = ("ENGINEERING_CORPUS_DIGEST.json", "COVERAGE.json", "ENGINEERING_DOCUMENT_REFERENCES.jsonl",
             "READ_LEDGER.json")
    summary_bytes: dict[str, bytes] = {}
    for name in names:
        path = summary / name
        if not path.is_file() or path.is_symlink():
            raise EvidenceSidecarError("required summary artifact missing or redirected: " + name)
        summary_bytes[name] = path.read_bytes() if name != "ENGINEERING_DOCUMENT_REFERENCES.jsonl" else b""
    digest_doc = strict_json_loads(summary_bytes["ENGINEERING_CORPUS_DIGEST.json"])
    coverage_doc = strict_json_loads(summary_bytes["COVERAGE.json"])
    read_doc = strict_json_loads(summary_bytes["READ_LEDGER.json"])
    if any(doc.get("snapshot_id") != snapshot_id for doc in (digest_doc, coverage_doc, read_doc)):
        raise EvidenceSidecarError("summary artifacts do not share the expected snapshot")
    if (read_doc.get("ledger_sha256") != digest_doc.get("ledger_sha256")
            or digest_doc.get("document_reference_count") != coverage_doc.get("document_reference_count")):
        raise EvidenceSidecarError("summary ledger or documentary reference counts conflict")
    try:
        import summarize_corpus
        legacy_overlay_binding = summarize_corpus.verify_legacy_overlay_binding(
            scan_dir or summary, snapshot_id, digest_doc, coverage_doc, summary_dir=summary)
        supplemental_repair_binding = summarize_corpus.verify_supplemental_repair_binding(
            scan_dir or summary, summary, supplemental_repair_dir, snapshot_id, test_api=test_api,
            scope_root=test_scope_root if test_api else None)
    except (ImportError, ValueError) as exc:
        raise EvidenceSidecarError("corpus overlay or supplemental repair failed exact artifact authentication") from exc
    if (digest_doc.get("supplemental_repair") != supplemental_repair_binding
            or coverage_doc.get("supplemental_repair") != supplemental_repair_binding
            or read_doc.get("supplemental_repair") != supplemental_repair_binding):
        raise EvidenceSidecarError("supplemental repair binding is missing, unexpected, or inconsistent")
    references_path = summary / "ENGINEERING_DOCUMENT_REFERENCES.jsonl"
    h, ref_size, reference_rows = hashlib.sha256(), 0, 0
    pending = bytearray()
    with references_path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block); ref_size += len(block)
            pending.extend(block)
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                if not line:
                    continue
                ref_row = strict_json_loads(line.decode("utf-8"))
                if ref_row.get("snapshot_id") != snapshot_id:
                    raise EvidenceSidecarError("documentary reference row is from another snapshot")
                reference_rows += 1
    if pending:
        ref_row = strict_json_loads(pending.decode("utf-8"))
        if ref_row.get("snapshot_id") != snapshot_id:
            raise EvidenceSidecarError("documentary reference row is from another snapshot")
        reference_rows += 1
    if reference_rows != digest_doc.get("document_reference_count"):
        raise EvidenceSidecarError("documentary reference row count differs from the compact summary")
    reference_binding = {"path": "ENGINEERING_DOCUMENT_REFERENCES.jsonl",
                         "sha256": h.hexdigest(), "byte_length": ref_size,
                         "semantics": "DOCUMENTARY_RELATION_ONLY; NO_CAUSAL_EDGES"}
    independent_summary = _independent_verification_binding(independent_verification, snapshot_id, digest_doc)
    receipt = {"schema": "pg_i7.corpus-i4-source-receipt.v1", "snapshot_id": snapshot_id,
               "scan_verification": dict(scan_verification),
               "independent_verification": independent_summary,
               "corpus_digest": digest_doc,
               "legacy_reference_overlay_binding": legacy_overlay_binding,
               "supplemental_repair_binding": supplemental_repair_binding,
               "coverage_sha256": _sha(summary_bytes["COVERAGE.json"]),
               "read_ledger_sha256": _sha(summary_bytes["READ_LEDGER.json"]),
               "document_reference_artifact": reference_binding,
               "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN",
               "model_identity": "UNKNOWN", "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    source = {"CORPUS_DERIVATION_RECEIPT.json": canonical_json(receipt),
              "ENGINEERING_CORPUS_DIGEST.json": summary_bytes["ENGINEERING_CORPUS_DIGEST.json"],
              "COVERAGE.json": summary_bytes["COVERAGE.json"]}
    corpus_dir = destination / "i4_corpus_source_corpus"
    corpus_dir.mkdir(exist_ok=False)
    bindings = {name: {"corpus_path": name, "sha256": sha256_bytes(raw), "byte_length": len(raw)}
                for name, raw in source.items()}
    for name, raw in source.items():
        _write_new(corpus_dir / name, raw)
    actor_id = generate_id("ACTOR")
    ids = {name: generate_id(kind) for name, kind in (
        ("project_id", "PROJECT"), ("product_id", "PRODUCT"), ("lineage_id", "LINEAGE"),
        ("version_id", "VERSION"), ("session_id", "SESSION"), ("run_id", "RUN"),
        ("attempt_id", "ATTEMPT"), ("digest_event", "EVENT"), ("coverage_event", "EVENT"),
        ("receipt_event", "EVENT"))}
    specs = [("digest_event", "CORPUS_DIGEST_OBSERVED", "ENGINEERING_CORPUS_DIGEST.json"),
             ("coverage_event", "CORPUS_COVERAGE_OBSERVED", "COVERAGE.json"),
             ("receipt_event", "CORPUS_SCAN_RECEIPT_OBSERVED", "CORPUS_DERIVATION_RECEIPT.json")]
    occurred, schemas = _utc_now(), SchemaRegistry()
    events = []
    for sequence, (key, role, name) in enumerate(specs, 1):
        ids["event_id"] = ids[key]
        event = _make_event(generate_id, schemas, ids=ids, actor_id=actor_id, role=role,
                            sequence=sequence, occurred=occurred, payload_sha=bindings[name]["sha256"])
        event_raw = canonical_json(event)
        event_name = key + ".json"
        _write_new(corpus_dir / event_name, event_raw)
        event_binding = {"corpus_path": event_name, "sha256": sha256_bytes(event_raw),
                         "byte_length": len(event_raw)}
        events.append((event, name, event_binding))
    manifest = {"files": sorted([*bindings.values(), *[row[2] for row in events]], key=lambda row: row["corpus_path"])}
    manifest_raw = canonical_json(manifest)
    _write_new(corpus_dir / "manifest.json", manifest_raw)
    corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
    graph = CausalGraph(corpus)
    records = []
    views = []
    for event, source_name, event_binding in events:
        node = graph.append({"kind": "NODE", "record": event,
                             "source_bindings": [bindings[source_name], bindings["CORPUS_DERIVATION_RECEIPT.json"], event_binding],
                             "record_binding": {**event_binding, "pointer": ""}})
        raw = canonical_json(node); records.append(raw)
        _write_new(destination / "i4_corpus_graph_records" / f"record-{len(records)-1:03d}.json", raw)
        views.append({"id": event["event_id"], "type": "EVENT", "source": source_name,
                      "evidence_identity": bindings[source_name]["sha256"],
                      "relation": "OBSERVATION_ONLY", "actor_class": "TOOL_OBSERVER",
                      "actor_authenticity": "UNKNOWN", "causal_edges": []})
    require_dag(graph.nodes, graph.edges)
    graph_status = ("DERIVED_UNQUALIFIED_ENGINEERING_GRAPH" if complete_verification
                    else "DERIVED_UNQUALIFIED_PARTIAL_ENGINEERING_GRAPH")
    graph_doc = {"schema_version": "pg_i7.corpus-i4-graph.v1", "status": graph_status,
                 "snapshot_id": snapshot_id, "graph_root": graph.root(), "node_count": len(graph.nodes),
                 "edge_count": len(graph.edges), "nodes": views, "edges": [],
                 "documentary_reference_artifact": reference_binding,
                 "source_corpus_manifest_sha256": corpus.manifest_sha256,
                 "i4_interface": ["CausalGraph.append", "CausalGraph.rebuild", "require_dag"],
                 "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED", "i5_binding": "NOT_BOUND"}
    graph_raw = canonical_json(graph_doc)
    _write_new(destination / "CORPUS_I4_GRAPH.json", graph_raw)
    _write_new(destination / "CORPUS_I4_GRAPH.dot", _dot(graph_doc))
    rebuilt = CausalGraph.rebuild(corpus, records)
    require_dag(rebuilt.nodes, rebuilt.edges)
    if rebuilt.root() != graph.root() or len(rebuilt.edges) != 0:
        raise EvidenceSidecarError("corpus I4 graph rebuild mismatch")
    semantic_raw = canonical_json(rebuilt.semantic_view())
    current_i5 = current_i5_compatibility(semantic_raw)
    try:
        ProvenanceLedger(corpus, semantic_raw, {})
    except Exception as exc:
        current_i5["frozen_api_constructor"] = "REJECTED_CURRENT_I4_GRAPH"
        current_i5["frozen_api_error_type"] = type(exc).__name__
        current_i5["i5_append_attempted"] = False
    else:
        current_i5["frozen_api_constructor"] = "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED"
        current_i5["i5_append_attempted"] = False
    result = {"schema": "pg_i7.corpus-i4-i5-integration.v1", "status": current_i5["status"],
              "snapshot_id": snapshot_id, "i4_graph_status": graph_status,
              "verification_status": scan_verification["status"],
              "verification_snapshot_id": scan_verification["snapshot_id"],
              "verification_counts": {key: scan_verification[key] for key in
                                       ("checked_count", "missing_count", "extra_count", "mismatch_count")},
              "coverage_status": digest_doc.get("coverage_status"),
              "i4_graph_root": rebuilt.root(), "i4_nodes": len(rebuilt.nodes),
              "i4_edges": len(rebuilt.edges), "i4_semantic_sha256": _sha(semantic_raw),
              "i4_projection_sha256": _sha(graph_raw), "i4_rebuild": "PASS",
              "current_i4_i5_integration": current_i5, "attribution": "UNKNOWN",
              "supplemental_repair_binding": supplemental_repair_binding,
              "documentary_references_are_causal": False, "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    _write_new(destination / "CORPUS_I5_INTEGRATION.json", canonical_json(result))
    result["semantic_verification"] = verify_corpus_graph(destination, expected_snapshot_id=snapshot_id,
                                                            summary_dir=summary,
                                                            scan_dir=scan_dir,
                                                            supplemental_repair_dir=supplemental_repair_dir,
                                                            test_api=test_api,
                                                            test_scope_root=test_scope_root)
    return result


def _sha256_text(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _independent_verification_binding(value: Mapping[str, Any] | None, snapshot_id: str,
                                      digest_doc: Mapping[str, Any]) -> dict[str, Any] | None:
    """Keep independent audit evidence separate from producer scan counters."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise EvidenceSidecarError("independent verification receipt must be an object")
    schema = value.get("schema")
    receipt_sha = value.get("receipt_sha256")
    receipt_size = value.get("receipt_byte_length")
    if not _sha256_text(receipt_sha) or not isinstance(receipt_size, int) or receipt_size <= 0:
        raise EvidenceSidecarError("independent verification must bind exact receipt bytes")
    if schema == "pg_i7.root-independent-document-verification.v1":
        if value.get("status") != "PASS" or value.get("snapshot_id") != snapshot_id:
            raise EvidenceSidecarError("document verification receipt does not join the expected snapshot")
        fields = ("ledger_sha256", "documents", "unique_files_verified", "actual_bytes_read")
        if (not _sha256_text(value.get("ledger_sha256"))
                or any(not isinstance(value.get(field), int) or value[field] < 0 for field in fields[1:])):
            raise EvidenceSidecarError("document verification receipt has invalid scoped counts")
        return {"schema": schema, "status": value["status"], "snapshot_id": snapshot_id,
                "ledger_sha256": value["ledger_sha256"], "documents": value["documents"],
                "unique_files_verified": value["unique_files_verified"],
                "actual_bytes_read": value["actual_bytes_read"], "receipt_sha256": receipt_sha,
                "receipt_byte_length": receipt_size}
    if schema != "pg_i7.independent-corpus-audit.v1":
        raise EvidenceSidecarError("unsupported independent verification receipt schema")
    posterior = value.get("posterior_comparison")
    final = value.get("independent_final_metadata_recheck")
    count_fields = ("admission_disagreement", "both_hashed", "hash_or_size_mismatch",
                    "independent_entries_absent_from_producer_inventory", "independent_files_missing_from_producer",
                    "metadata_mismatch", "producer_cross_snapshot_rows", "producer_duplicate_path_ids",
                    "producer_files_missing_independently", "producer_inventory_byte_length",
                    "producer_inventory_duplicate_path_ids", "producer_inventory_entries_absent_independently",
                    "producer_inventory_inventoried_metadata_mismatch", "producer_inventory_rows",
                    "producer_inventory_unique_path_ids", "producer_ledger_byte_length", "producer_ledger_rows")
    count_maps = ("producer_inventory_status_counts", "producer_inventory_unique_kind_counts")
    if not isinstance(posterior, Mapping) or not isinstance(final, Mapping):
        raise EvidenceSidecarError("independent corpus audit lacks its exact comparison receipt")
    expected_policy = digest_doc.get("protection_policy_sha256")
    if (value.get("status") != "ENUMERATED_AND_REHASHED_WITH_EXPLICIT_EXCEPTIONS"
            or value.get("expected_producer_snapshot_id") != snapshot_id
            or posterior.get("producer_inventory_recomputed_snapshot_id") != snapshot_id
            or posterior.get("producer_inventory_snapshot_matches_expected") is not True
            or value.get("producer_scope_definition_sha256") != expected_policy
            or not _sha256_text(value.get("scope_sha256"))
            or not _sha256_text(value.get("independent_ledger_sha256"))
            or not _sha256_text(posterior.get("producer_inventory_sha256"))
            or posterior.get("producer_inventory_sha256") != digest_doc.get("inventory_sha256")
            or not _sha256_text(posterior.get("producer_ledger_sha256"))
            or posterior.get("producer_ledger_sha256") != digest_doc.get("ledger_sha256")
            or posterior.get("producer_inventory_stable_during_join") is not True
            or posterior.get("producer_ledger_stable_during_join") is not True
            or posterior.get("producer_cross_snapshot_rows") != 0
            or posterior.get("producer_duplicate_path_ids") != 0):
        raise EvidenceSidecarError("independent corpus audit is not joined to the exact producer snapshot and artifacts")
    for field in count_fields:
        if not isinstance(posterior.get(field), int) or posterior[field] < 0:
            raise EvidenceSidecarError("independent corpus audit comparison count is missing or invalid: " + field)
    if (posterior["producer_inventory_rows"] - posterior["producer_inventory_unique_path_ids"]
            != posterior["producer_inventory_duplicate_path_ids"]):
        raise EvidenceSidecarError("independent corpus audit raw inventory duplicate count is inconsistent")
    for field in count_maps:
        mapping = posterior.get(field)
        if not isinstance(mapping, Mapping) or any(not isinstance(n, int) or n < 0 for n in mapping.values()):
            raise EvidenceSidecarError("independent corpus audit comparison counts are invalid: " + field)
    independent_entries = value.get("independent_entries")
    if not isinstance(independent_entries, int) or independent_entries < 0:
        raise EvidenceSidecarError("independent corpus audit entry count is invalid")
    for field in ("status_counts", "kind_counts"):
        mapping = value.get(field)
        if not isinstance(mapping, Mapping) or any(not isinstance(n, int) or n < 0 for n in mapping.values()):
            raise EvidenceSidecarError("independent corpus audit counts are invalid: " + field)
        if sum(mapping.values()) != independent_entries:
            raise EvidenceSidecarError("independent corpus audit count total differs from entry count: " + field)
    byte_fields = ("independently_hashed_file_bytes", "observed_hash_read_bytes_including_failed_observations")
    if any(not isinstance(value.get(field), int) or value[field] < 0 for field in byte_fields):
        raise EvidenceSidecarError("independent corpus audit byte counters are invalid")
    if (value.get("source_execution") is not False or value.get("producer_imports") is not False
            or value.get("atomic_filesystem_snapshot_claim") is not False
            or value.get("local_only_database_not_for_export") is not True
            or not isinstance(value.get("resumed"), bool)):
        raise EvidenceSidecarError("independent corpus audit scope limitations are invalid")
    if (final.get("status") != "STABLE_OBSERVED_METADATA"
            or final.get("atomic_snapshot") is not False
            or final.get("final_entry_count") != independent_entries
            or any(final.get(field) != 0 for field in ("metadata_mismatches", "missing_after_hash_pass", "extra_after_hash_pass"))):
        raise EvidenceSidecarError("independent corpus audit final metadata recheck is inconsistent")
    return {"schema": schema, "status": value["status"],
            "expected_producer_snapshot_id": snapshot_id,
            "producer_scope_definition_sha256": expected_policy,
            "scope_sha256": value["scope_sha256"], "independent_ledger_sha256": value["independent_ledger_sha256"],
            "independent_entries": independent_entries, "status_counts": dict(value["status_counts"]),
            "kind_counts": dict(value["kind_counts"]),
            "source_execution": False, "producer_imports": False,
            "atomic_filesystem_snapshot_claim": False, "local_only_database_not_for_export": True,
            "resumed": value["resumed"],
            "independently_hashed_file_bytes": value["independently_hashed_file_bytes"],
            "observed_hash_read_bytes_including_failed_observations": value["observed_hash_read_bytes_including_failed_observations"],
            "posterior_comparison": dict(posterior),
            "independent_final_metadata_recheck": dict(final),
            "receipt_sha256": receipt_sha, "receipt_byte_length": receipt_size}


def verify_corpus_graph(output_dir: str | os.PathLike[str], *, expected_snapshot_id: str,
                        summary_dir: str | os.PathLike[str] | None = None,
                        scan_dir: str | os.PathLike[str] | None = None,
                        supplemental_repair_dir: str | os.PathLike[str] | None = None,
                        test_api: bool = False,
                        test_scope_root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Rebuild the compact I4 corpus graph and reject semantic receipt edits."""
    (canonical_json, _, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     _, require_dag, _, ProvenanceLedger, _) = _load_frozen_apis()
    base = Path(output_dir).resolve(strict=True)
    corpus_dir = base / "i4_corpus_source_corpus"
    manifest_raw = (corpus_dir / "manifest.json").read_bytes()
    manifest = strict_json_loads(manifest_raw)
    corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
    record_paths = sorted((base / "i4_corpus_graph_records").glob("record-*.json"))
    raw_records = [path.read_bytes() for path in record_paths]
    graph = CausalGraph.rebuild(corpus, raw_records)
    require_dag(graph.nodes, graph.edges)
    graph_doc = strict_json_loads((base / "CORPUS_I4_GRAPH.json").read_bytes())
    receipt = strict_json_loads((corpus_dir / "CORPUS_DERIVATION_RECEIPT.json").read_bytes())
    digest_doc = strict_json_loads(corpus.read("ENGINEERING_CORPUS_DIGEST.json"))
    coverage_doc = strict_json_loads(corpus.read("COVERAGE.json"))
    independent_summary = receipt.get("independent_verification")
    if _independent_verification_binding(independent_summary, expected_snapshot_id, digest_doc) != independent_summary:
        raise EvidenceSidecarError("independent verification binding differs from exact receipt and snapshot join")
    overlay_binding = digest_doc.get("legacy_reference_overlay")
    supplemental_binding = digest_doc.get("supplemental_repair")
    if (coverage_doc.get("snapshot_id") != expected_snapshot_id
            or coverage_doc.get("legacy_reference_overlay") != overlay_binding
            or receipt.get("legacy_reference_overlay_binding") != overlay_binding
            or coverage_doc.get("supplemental_repair") != supplemental_binding
            or receipt.get("supplemental_repair_binding") != supplemental_binding):
        raise EvidenceSidecarError("corpus graph legacy overlay commitment differs across digest, coverage, and source receipt")
    if overlay_binding is not None and summary_dir is None:
        raise EvidenceSidecarError("legacy overlay graph verification requires its bound summary source directory")
    if summary_dir is not None:
        try:
            import summarize_corpus
            verified_overlay = summarize_corpus.verify_legacy_overlay_binding(
                scan_dir or summary_dir, expected_snapshot_id, digest_doc, coverage_doc,
                summary_dir=summary_dir)
        except (ImportError, ValueError) as exc:
            raise EvidenceSidecarError("corpus graph legacy overlay bytes or old prefix no longer verify") from exc
        if verified_overlay != overlay_binding:
            raise EvidenceSidecarError("corpus graph overlay binding differs from current source artifacts")
        try:
            verified_supplemental = summarize_corpus.verify_supplemental_repair_binding(
                scan_dir or summary_dir, summary_dir, supplemental_repair_dir, expected_snapshot_id,
                test_api=test_api, scope_root=test_scope_root if test_api else None)
        except (ImportError, ValueError) as exc:
            raise EvidenceSidecarError("corpus graph supplemental repair bytes or primary row joins no longer verify") from exc
        if verified_supplemental != supplemental_binding:
            raise EvidenceSidecarError("corpus graph supplemental binding differs from current source artifacts")
    elif supplemental_binding is not None or supplemental_repair_dir is not None:
        raise EvidenceSidecarError("supplemental graph verification requires its bound summary and repair directories")
    scan_verification = receipt.get("scan_verification", {})
    verify_counts = [scan_verification.get(name) for name in ("checked_count", "missing_count", "extra_count", "mismatch_count")]
    coherent = (scan_verification.get("expected_snapshot_id") == expected_snapshot_id
                and all(isinstance(value, int) and value >= 0 for value in verify_counts)
                and scan_verification.get("inventory_matches") is
                    (scan_verification.get("snapshot_id") == expected_snapshot_id))
    complete_verification = (scan_verification.get("status") == "VERIFIED"
                             and scan_verification.get("inventory_matches") is True
                             and all(scan_verification.get(name) == 0 for name in ("missing_count", "extra_count", "mismatch_count")))
    partial_verification = (scan_verification.get("status") == "INCOMPLETE_OR_MISMATCH"
                            and (scan_verification.get("inventory_matches") is False
                                 or any(scan_verification.get(name, 0) > 0 for name in ("missing_count", "extra_count", "mismatch_count"))))
    if (not coherent or not (complete_verification or partial_verification)
            or digest_doc.get("snapshot_id") != expected_snapshot_id):
        raise EvidenceSidecarError("corpus source receipt lacks coherent exact-snapshot verification")
    roles = {"ENGINEERING_CORPUS_DIGEST.json": "CORPUS_DIGEST_OBSERVED",
             "COVERAGE.json": "CORPUS_COVERAGE_OBSERVED",
             "CORPUS_DERIVATION_RECEIPT.json": "CORPUS_SCAN_RECEIPT_OBSERVED"}
    views = []
    source_by_hash = {binding["sha256"]: binding["corpus_path"] for binding in manifest["files"]}
    for raw in raw_records:
        node = strict_json_loads(raw)
        event = node["record"]
        source_name = source_by_hash.get(event["payload_sha256"])
        if source_name not in roles or event.get("event_kind") != "ENGINEERING_" + roles[source_name]:
            raise EvidenceSidecarError("corpus graph record source or role differs")
        views.append({"id": event["event_id"], "type": "EVENT", "source": source_name,
                      "evidence_identity": event["payload_sha256"], "relation": "OBSERVATION_ONLY",
                      "actor_class": "TOOL_OBSERVER", "actor_authenticity": "UNKNOWN", "causal_edges": []})
    graph_status = ("DERIVED_UNQUALIFIED_ENGINEERING_GRAPH" if complete_verification
                    else "DERIVED_UNQUALIFIED_PARTIAL_ENGINEERING_GRAPH")
    if (graph_doc.get("schema_version") != "pg_i7.corpus-i4-graph.v1"
            or graph_doc.get("status") != graph_status
            or graph_doc.get("snapshot_id") != expected_snapshot_id
            or graph_doc.get("graph_root") != graph.root()
            or graph_doc.get("node_count") != len(graph.nodes) or graph_doc.get("edge_count") != 0
            or graph.edges or graph_doc.get("nodes") != views or graph_doc.get("edges") != []
            or graph_doc.get("source_corpus_manifest_sha256") != corpus.manifest_sha256
            or graph_doc.get("documentary_reference_artifact") != receipt.get("document_reference_artifact")
            or graph_doc.get("closure") != "NOT_CREATED" or graph_doc.get("signed_tip") != "NOT_CREATED"
            or graph_doc.get("i5_binding") != "NOT_BOUND"):
        raise EvidenceSidecarError("corpus I4 projection differs from exact rebuilt source graph")
    if (base / "CORPUS_I4_GRAPH.dot").read_bytes() != _dot(graph_doc):
        raise EvidenceSidecarError("corpus I4 DOT projection differs")
    semantic_raw = canonical_json(graph.semantic_view())
    expected_i5 = current_i5_compatibility(semantic_raw)
    try:
        ProvenanceLedger(corpus, semantic_raw, {})
    except Exception as exc:
        expected_i5["frozen_api_constructor"] = "REJECTED_CURRENT_I4_GRAPH"
        expected_i5["frozen_api_error_type"] = type(exc).__name__
        expected_i5["i5_append_attempted"] = False
    else:
        expected_i5["frozen_api_constructor"] = "ACCEPTED_CONSTRUCTOR_ONLY_APPEND_NOT_ATTEMPTED"
        expected_i5["i5_append_attempted"] = False
    result = strict_json_loads((base / "CORPUS_I5_INTEGRATION.json").read_bytes())
    expected_result = {"schema": "pg_i7.corpus-i4-i5-integration.v1", "status": expected_i5["status"],
                       "snapshot_id": expected_snapshot_id, "i4_graph_status": graph_status,
                       "verification_status": scan_verification["status"],
                       "verification_snapshot_id": scan_verification["snapshot_id"],
                       "verification_counts": {key: scan_verification[key] for key in
                                                ("checked_count", "missing_count", "extra_count", "mismatch_count")},
                       "coverage_status": digest_doc.get("coverage_status"),
                       "i4_graph_root": graph.root(),
                       "i4_nodes": len(graph.nodes), "i4_edges": 0, "i4_semantic_sha256": _sha(semantic_raw),
                       "i4_projection_sha256": _sha(canonical_json(graph_doc)), "i4_rebuild": "PASS",
                       "current_i4_i5_integration": expected_i5, "attribution": "UNKNOWN",
                       "supplemental_repair_binding": supplemental_binding,
                       "documentary_references_are_causal": False, "closure": "NOT_CREATED", "signed_tip": "NOT_CREATED"}
    if result != expected_result:
        raise EvidenceSidecarError("current corpus I4/I5 receipt differs from reconstructed exact graph")
    return {"status": "PASS", "snapshot_id": expected_snapshot_id,
            "i4_graph_root": graph.root(), "i4_nodes": len(graph.nodes), "i4_edges": 0,
            "i4_semantic_sha256": _sha(semantic_raw), "i5_status": expected_i5["status"],
            "supplemental_repair_binding": supplemental_binding,
            "attribution": "UNKNOWN", "forged_receipt_rejected_by_exact_reconstruction": True}


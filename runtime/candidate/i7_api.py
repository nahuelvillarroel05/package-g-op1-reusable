"""Import-safe facade for the bounded local I7 engineering composition.

Importing this module defines the API only. Workspace discovery and the CLI
motor are loaded lazily by a call, after an explicit workspace is supplied.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any


class APIError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _documents_policy(cli: Any):
    loader = getattr(cli, "_documents_policy_module", None)
    if not callable(loader):
        raise cli.I7Error("DOCUMENT_POLICY_UNAVAILABLE", "fixed CLI document-policy loader is unavailable")
    return loader()


def _cli(workspace_dir: str | os.PathLike[str]):
    raw_workspace = os.fspath(workspace_dir)
    main = sys.modules.get("__main__")
    if main is not None and callable(getattr(main, "_validate_workspace_root", None)):
        root = main._validate_workspace_root(raw_workspace)
        if Path(os.path.abspath(getattr(main, "WORKSPACE", ""))) == root:
            cli = main
        else:
            cli = None
    else:
        cli = None
    trusted = None
    if cli is None:
        trusted_path = Path(__file__).resolve().parent / "pg_i7.py"
        trusted_name = "_pg_i7_api_trusted_candidate"
        trusted = sys.modules.get(trusted_name)
        if trusted is None:
            spec = importlib.util.spec_from_file_location(trusted_name, trusted_path)
            if spec is None or spec.loader is None:
                raise APIError("TRUSTED_CLI_UNAVAILABLE", "fixed candidate CLI could not be loaded")
            trusted = importlib.util.module_from_spec(spec)
            sys.modules[trusted_name] = trusted
            spec.loader.exec_module(trusted)
        root = trusted._validate_workspace_root(raw_workspace)
    if cli is None:
        assert trusted is not None
        if not root.exists():
            raise APIError("WORKSPACE_NOT_INITIALIZED", "API calls require an existing workspace copied from the fixed candidate")
        trusted._validate_workspace_binding(root)
        path = root / "pg_i7.py"
        if not path.is_file() or path.is_symlink() or trusted._sha(path.read_bytes()) != trusted._sha((Path(__file__).resolve().parent / "pg_i7.py").read_bytes()):
            raise APIError("WORKSPACE_CLI_MISSING", "workspace does not contain a regular pg_i7.py")
        name = "_pg_i7_api_cli_" + str(abs(hash(str(root))))
        loaded = sys.modules.get(name)
        if loaded is None:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise APIError("WORKSPACE_CLI_UNLOADABLE", "workspace CLI could not be loaded")
            loaded = importlib.util.module_from_spec(spec)
            sys.modules[name] = loaded
            spec.loader.exec_module(loaded)
        cli = loaded
        named_cli = sys.modules.get("pg_i7")
        if named_cli is not None and Path(os.path.abspath(getattr(named_cli, "__file__", ""))) != path:
            raise APIError("IMPORT_COLLISION", "pg_i7 module name is bound to a different composition path")
        sys.modules.setdefault("pg_i7", cli)
    if Path(os.path.abspath(os.fspath(cli.WORKSPACE))) != root:
        raise APIError("WORKSPACE_BINDING_MISMATCH", "API workspace differs from the CLI's fixed workspace")
    cli._require_bound_workspace()
    return cli


def inspect(*, workspace_dir: str, data_digest: bool = False, causal_data: bool = False,
            provenance: bool = False, **unsupported: Any) -> dict[str, Any]:
    if unsupported or any(type(value) is not bool for value in (data_digest, causal_data, provenance)):
        raise APIError("API_ARGUMENT_ERROR", "inspect accepts boolean data_digest, causal_data, and provenance flags only")
    return _cli(workspace_dir).inspect(data_digest=data_digest, causal_data=causal_data, provenance=provenance)


def initialize_workspace(*, workspace_dir: str) -> dict[str, Any]:
    """Create a new focused workspace using the fixed candidate's existing copier."""
    trusted_path = Path(__file__).resolve().parent / "pg_i7.py"
    name = "_pg_i7_api_trusted_candidate"
    trusted = sys.modules.get(name)
    if trusted is None:
        spec = importlib.util.spec_from_file_location(name, trusted_path)
        if spec is None or spec.loader is None:
            raise APIError("TRUSTED_CLI_UNAVAILABLE", "fixed candidate CLI could not be loaded")
        trusted = importlib.util.module_from_spec(spec)
        sys.modules[name] = trusted
        spec.loader.exec_module(trusted)
    target = trusted._validate_workspace_root(workspace_dir)
    trusted._ensure_workspace(str(target), "run")
    trusted._validate_workspace_binding(target)
    return {"schema": "i7_api.workspace.v1", "status": "BOUND", "workspace_dir": str(target),
            "workspace_binding": str(target / trusted.WORKSPACE_BINDING_NAME)}


def run_provider(*, workspace_dir: str, provider_id: str, input: str,
                  output_dir: str | None = None, **options: Any) -> dict[str, Any]:
    bool_options = {"negative", "data_digest", "causal_data", "provenance", "strict_formal"}
    if any(type(options[key]) is not bool for key in bool_options if key in options):
        raise APIError("API_ARGUMENT_ERROR", "provider execution flags must be booleans")
    cli = _cli(workspace_dir)
    if provider_id == "safe.synthetic.totals.v1":
        allowed = {"negative", "data_digest", "causal_data", "provenance", "input_sha256",
                   "provenance_mode", "strict_formal"}
        if set(options) - allowed:
            raise APIError("API_ARGUMENT_ERROR", "unsupported synthetic provider arguments: " + ", ".join(sorted(set(options) - allowed)))
        if input == "<demo>":
            return cli.demo(output_dir=output_dir, provider_id=provider_id, **options)
        return cli.run(input=input, output_dir=output_dir, provider_id=provider_id, **options)
    if provider_id == "safe.documents.metadata.v1":
        if set(options) - {"input_sha256"}:
            raise cli.I7Error("PROVIDER_OPTION_UNSUPPORTED", "document metadata provider accepts only an optional input_sha256 pin")
        return _document_metadata_provider(cli, selection_manifest=input, output_dir=output_dir,
                                           input_sha256=options.get("input_sha256"))
    if provider_id == "safe.documents.metadata.v2":
        if set(options) - {"input_sha256"}:
            raise cli.I7Error("PROVIDER_OPTION_UNSUPPORTED", "document metadata v2 accepts only an optional input_sha256 pin")
        return _document_metadata_provider_v2(cli, selection_manifest=input, output_dir=output_dir,
                                              input_sha256=options.get("input_sha256"))
    raise cli.I7Error("PROVIDER_NOT_ALLOWLISTED", f"provider is not registered: {provider_id}")


def run_pipeline(*, workspace_dir: str, selection_manifest: str, output_dir: str | None = None,
                 data_digest: bool = True, causal_data: bool = True,
                 provenance: bool = False, provenance_mode: str = "prospective", **unsupported: Any) -> dict[str, Any]:
    if (unsupported or any(type(value) is not bool for value in (data_digest, causal_data, provenance))
            or not data_digest or not causal_data or provenance_mode != "prospective"):
        raise APIError("API_ARGUMENT_ERROR", "pipeline requires boolean data_digest=True and causal_data=True flags with provenance_mode='prospective'")
    cli = _cli(workspace_dir)
    cli._require_workspace_open()
    intent_id = cli._consume_producer_intent("pipeline-documents-to-totals")
    return _documents_to_totals(cli, selection_manifest=selection_manifest,
                                output_dir=output_dir or ("pipeline-" + cli.uuid.uuid4().hex),
                                flags={"data_digest": data_digest, "causal_data": causal_data,
                                       "provenance": provenance}, provenance_mode=provenance_mode,
                                pipeline_intent_id=intent_id)


def verify(*, workspace_dir: str, from_run: str, **options: Any) -> dict[str, Any]:
    allowed = {"input_sha256", "expected_operation_id"}
    if set(options) - allowed:
        raise APIError("API_ARGUMENT_ERROR", "unsupported verify arguments: " + ", ".join(sorted(set(options) - allowed)))
    return _cli(workspace_dir).verify(from_run=from_run, **options)


def query(*, workspace_dir: str, from_run: str, task_id: str | None = None,
          kind: str | None = None, identifier: str | None = None,
          limit: int = 50, expected_operation_id: str | None = None,
          include_superseded: bool = False,
          **unsupported: Any) -> dict[str, Any]:
    if unsupported or type(limit) is not int or not 1 <= limit <= 1000 or type(include_superseded) is not bool:
        raise APIError("API_ARGUMENT_ERROR", "query accepts task_id, kind, identifier, limit, and expected_operation_id")
    cli = _cli(workspace_dir)
    run_dir, run_record = cli._load_run(from_run, expected_operation_id)
    verification = cli.verify(from_run=str(run_dir), expected_operation_id=run_record["operation_id"])
    if verification.get("status") != "PASS":
        raise cli.I7Error("CONTEXT_QUERY_RUN_NOT_VERIFIED", "Context query requires a fully verified immutable run")
    bound_task = "cli-run:" + run_record["operation_id"]
    context_requested = (task_id is not None or kind is not None or identifier is not None
                         or limit != 50 or include_superseded)
    if run_record.get("provenance_mode") != "prospective":
        if context_requested:
            raise cli.I7Error("CONTEXT_QUERY_NOT_AVAILABLE",
                              "Context filters are unavailable for runs without prospective provenance")
        return cli.query(from_run=from_run, expected_operation_id=expected_operation_id)
    context = cli._prospective_adapter().verify(cli.WORKSPACE, run_dir,
                                                expected_run_id=run_record["operation_id"])
    try:
        records = cli._prospective_adapter().query(
            cli.WORKSPACE, run_dir, task_id=task_id, kind=kind, identifier=identifier,
            limit=limit, include_superseded=include_superseded,
            expected_run_id=run_record["operation_id"])
    except Exception as exc:
        raise cli.I7Error("CONTEXT_QUERY_UNAVAILABLE_READ_ONLY", str(exc)) from exc
    compact = cli.query(from_run=from_run, expected_operation_id=expected_operation_id)
    original_content_requested = (kind == "original_document_content"
                                  or identifier == "original_document_content")
    query_result_status = ("CONTENT_UNAVAILABLE" if original_content_requested else
                           "MATCHED_COMMITTED_RECORDS" if records else
                           "NO_MATCHING_COMMITTED_RECORDS")
    return {**compact, "context_query": {"schema": "i7_api.context-query.v1", "status": "PASS",
            "run_dir": str(run_dir),
            "operation_id": run_record["operation_id"], "task_id": bound_task,
            "graph_version": context.get("graph_version"), "graph_sha256": context.get("graph_sha256"),
            "provenance_sha256": context.get("provenance_sha256"), "records": records,
            "record_count": len(records), "read_only": True,
            "query_result_status": query_result_status,
            **({"original_document_content_status": "NOT_CAPTURED",
                "unavailable_reason": "ORIGINAL_CONTENT_NOT_CAPTURED"} if original_content_requested else {}),
            "provider_id_declared": run_record.get("provider_id"),
            "provider_and_process_identity": "UNKNOWN", "independent_custody": "NOT_PROVEN"}}


def recover(*, workspace_dir: str, from_run: str, **options: Any) -> dict[str, Any]:
    allowed = {"input_sha256", "expected_operation_id"}
    if set(options) - allowed:
        raise APIError("API_ARGUMENT_ERROR", "unsupported recovery arguments: " + ", ".join(sorted(set(options) - allowed)))
    cli = _cli(workspace_dir)
    path = cli._checked_absolute(from_run, base=cli.WORKSPACE, must_exist=True)
    if cli._beneath(path, cli.WORKSPACE / "runs") and path.is_dir() and (path / "attempt-000.json").is_file():
        attempt_files = sorted(path.glob("attempt-*.json"))
        checked_attempts = [cli._checked_absolute(item, base=path, must_exist=True) for item in attempt_files]
        rows = [cli._parse_json(item.read_bytes(), "pipeline attempt record") for item in checked_attempts]
        if not rows or rows[0].get("status") != "STARTED":
            raise cli.I7Error("PIPELINE_ATTEMPT_INVALID", "pipeline attempt start record is missing or invalid")
        for index, row in enumerate(rows):
            if row.get("attempt_number") != index:
                raise cli.I7Error("PIPELINE_ATTEMPT_SEQUENCE_INVALID", "append-only pipeline attempt sequence has a gap")
        last = rows[-1]
        if last.get("status") != "COMPLETED":
            return {"schema": "i7_api.pipeline-recovery.v1", "status": "INTERRUPTED_NOT_PROVEN",
                    "attempt_dir": str(path), "last_attempt": last,
                    "dispatch": "NOT_PERFORMED", "redispatch": "PROHIBITED",
                    "read_only": True, "authority_effect": "NONE"}
        run_dir = last.get("run_dir")
        if not isinstance(run_dir, str):
            raise cli.I7Error("PIPELINE_RECOVERY_BINDING_MISSING", "completed pipeline record lacks its run binding")
        recovered = cli.recover(from_run=run_dir, expected_operation_id=last.get("operation_id"))
        return {"schema": "i7_api.pipeline-recovery.v1", "status": recovered.get("status"),
                "attempt_dir": str(path), "last_attempt": last, "stage_b_recovery": recovered,
                "dispatch": "NOT_PERFORMED", "redispatch": "PROHIBITED", "read_only": True,
                "authority_effect": "NONE"}
    return cli.recover(from_run=from_run, **options)


def get_graph(*, workspace_dir: str, from_run: str, **options: Any) -> dict[str, Any]:
    allowed = {"graph_format", "expected_operation_id"}
    if set(options) - allowed:
        raise APIError("API_ARGUMENT_ERROR", "unsupported graph arguments: " + ", ".join(sorted(set(options) - allowed)))
    cli = _cli(workspace_dir)
    run_dir, record = cli._load_run(from_run, options.get("expected_operation_id"))
    verified = cli.verify(from_run=str(run_dir), expected_operation_id=record["operation_id"])
    if verified.get("status") != "PASS":
        raise cli.I7Error("GRAPH_RUN_NOT_VERIFIED", "graph query requires a fully verified immutable run")
    return cli.graph(from_run=str(run_dir), **options)


def get_provenance(*, workspace_dir: str, from_run: str, **options: Any) -> dict[str, Any]:
    if set(options) - {"expected_operation_id"}:
        raise APIError("API_ARGUMENT_ERROR", "unsupported provenance arguments: " + ", ".join(sorted(set(options) - {"expected_operation_id"})))
    cli = _cli(workspace_dir)
    run_dir, record = cli._load_run(from_run, options.get("expected_operation_id"))
    verified = cli.verify(from_run=str(run_dir), expected_operation_id=record["operation_id"])
    if verified.get("status") != "PASS":
        raise cli.I7Error("PROVENANCE_RUN_NOT_VERIFIED", "provenance query requires a fully verified immutable run")
    result = {"schema": "i7_api.provenance.v1", "operation_id": record["operation_id"],
              "run_dir": str(run_dir), "prospective_provenance": record.get("prospective_provenance")}
    if result["prospective_provenance"] is None:
        result["prospective_provenance"] = cli._prospective_adapter().verify(
            cli.WORKSPACE, run_dir, expected_run_id=record["operation_id"], include_observations=True)
    result["provider_id_declared"] = record.get("provider_id")
    result["provider_and_process_identity"] = "UNKNOWN"
    result["independent_custody"] = "NOT_PROVEN"
    return result


def inspect_document_selection(*, workspace_dir: str, policy_id: str) -> dict[str, Any]:
    if not isinstance(policy_id, str):
        raise APIError("API_ARGUMENT_ERROR", "policy_id must be a string")
    cli = _cli(workspace_dir)
    documents_policy = _documents_policy(cli)
    return documents_policy.inspect_document_selection(cli, policy_id)


def prepare_document_selection(*, workspace_dir: str, policy_id: str,
                               relative_paths: list[str] | tuple[str, ...], selection_id: str,
                               output_path: str) -> dict[str, Any]:
    if (not isinstance(policy_id, str) or type(relative_paths) not in {list, tuple}
            or any(not isinstance(item, str) for item in relative_paths)
            or not isinstance(selection_id, str) or not isinstance(output_path, str)):
        raise APIError("API_ARGUMENT_ERROR", "prepare requires policy_id, string relative_paths, selection_id, and output_path")
    cli = _cli(workspace_dir)
    documents_policy = _documents_policy(cli)
    return documents_policy.prepare_document_selection(cli, policy_id=policy_id,
                                                       relative_paths=relative_paths,
                                                       selection_id=selection_id,
                                                       output_path=output_path)


def validate_document_selection(*, workspace_dir: str, selection_manifest: str) -> dict[str, Any]:
    if not isinstance(selection_manifest, str):
        raise APIError("API_ARGUMENT_ERROR", "selection_manifest must be a string")
    cli = _cli(workspace_dir)
    documents_policy = _documents_policy(cli)
    return documents_policy.validate_document_selection(cli, selection_manifest)


def _document_metadata_provider(cli: Any, *, selection_manifest: str,
                                output_dir: str | None,
                                pipeline_intent_id: str | None = None,
                                input_sha256: str | None = None) -> dict[str, Any]:
    """Selection-bound provider that reads and records exactly the eight approved files."""
    cli._require_bound_workspace()
    supplied = cli._checked_absolute(selection_manifest, base=cli.FOCUSED_ROOT, must_exist=True)
    if not cli._same_path(supplied, cli.REAL_DOCUMENT_SELECTION):
        raise cli.I7Error("DOCUMENT_SELECTION_NOT_ALLOWLISTED", "provider requires the exact pinned eight-document manifest")
    selection_raw = supplied.read_bytes()
    if cli._sha(selection_raw) != cli.REAL_DOCUMENT_SELECTION_SHA256:
        raise cli.I7Error("DOCUMENT_SELECTION_NOT_ALLOWLISTED", "provider requires the exact pinned eight-document manifest")
    if input_sha256 is not None and input_sha256 != cli._sha(selection_raw):
        raise cli.I7Error("INPUT_PIN_MISMATCH", "selection manifest SHA-256 does not match --input-sha256")
    value = cli._parse_json(supplied.read_bytes(), "real document selection")
    rows = value.get("documents") if type(value) is dict else None
    if (value.get("schema") != "i7.focused.real-document-selection.v1" or type(rows) is not list
            or len(rows) != 8 or not cli._same_path(Path(value.get("source_root", "")), cli.ENGINEERING_ROOT)):
        raise cli.I7Error("DOCUMENT_SELECTION_INVALID", "provider accepts exactly the selected eight documents")
    if output_dir is None:
        output_dir = str(cli.WORKSPACE / "runs" / ("documents-" + cli.uuid.uuid4().hex))
    result = cli._engineering_documents(output_dir=output_dir, selection_manifest=str(supplied),
                                        flags={"data_digest": False, "causal_data": False, "provenance": False},
                                        _pipeline_intent_id=pipeline_intent_id)
    manifest_out = Path(result["output_dir"]) / "document-scan-manifest.jsonl"
    ledger_out = Path(result["output_dir"]) / "document-scan-ledger.jsonl"
    manifest_out_raw, ledger_out_raw = manifest_out.read_bytes(), ledger_out.read_bytes()
    return {"schema": "i7_api.document_metadata_provider.v1", "status": "PASS",
            "provider_id": "safe.documents.metadata.v1", "selection_manifest": str(supplied),
            "selection_manifest_sha256": cli._sha(selection_raw), "document_count": 8,
            "source_document_count": 8,
            "document_bytes": [row.get("bytes") for row in rows], "output_dir": result["output_dir"],
            "snapshot_id": result["snapshot_id"], "ledger_sha256": cli._sha(ledger_out_raw),
            "read_evidence": {"manifest_path": str(manifest_out), "manifest_sha256": cli._sha(manifest_out_raw),
                              "manifest_bytes": len(manifest_out_raw), "ledger_path": str(ledger_out),
                              "ledger_sha256": cli._sha(ledger_out_raw), "ledger_bytes": len(ledger_out_raw)},
            "read_only_source_access": True, "source_reads": 8,
            "actual_unique_source_bytes_read": result["actual_unique_document_bytes_read"],
            "documentary_references_are_causal": False}


def _document_metadata_provider_v2(cli: Any, *, selection_manifest: str,
                                   output_dir: str | None,
                                   pipeline_intent_id: str | None = None,
                                   input_sha256: str | None = None) -> dict[str, Any]:
    cli._require_bound_workspace()
    documents_policy = _documents_policy(cli)
    scanner = cli._engineering_api()
    value, rows, root, raw = documents_policy._manifest(cli, scanner, selection_manifest)
    if input_sha256 is not None and input_sha256 != cli._sha(raw):
        raise cli.I7Error("INPUT_PIN_MISMATCH", "selection manifest SHA-256 does not match --input-sha256")
    if output_dir is None:
        output_dir = str(cli.WORKSPACE / "runs" / ("documents-" + cli.uuid.uuid4().hex))
    result = cli._engineering_documents_v2(output_dir=output_dir, selection_manifest=selection_manifest,
                                           _pipeline_intent_id=pipeline_intent_id)
    manifest_out = Path(result["output_dir"]) / "document-scan-manifest.jsonl"
    ledger_out = Path(result["output_dir"]) / "document-scan-ledger.jsonl"
    manifest_raw, ledger_raw = manifest_out.read_bytes(), ledger_out.read_bytes()
    return {"schema": "i7_api.document_metadata_provider.v2", "status": "PASS",
            "provider_id": "safe.documents.metadata.v2", "selection_id": value["selection_id"],
            "selection_policy_id": value["policy_id"],
            "selection_commitment_sha256": value["selection_commitment_sha256"],
            "selection_manifest": str(Path(selection_manifest)), "selection_manifest_sha256": cli._sha(raw),
            "document_count": len(rows), "source_document_count": len(rows),
            "document_bytes": [row["bytes"] for row in rows], "output_dir": result["output_dir"],
            "snapshot_id": result["snapshot_id"], "ledger_sha256": cli._sha(ledger_raw),
            "snapshot_consistency": "PER_FILE_STABLE_READS_ONLY",
            "cross_document_snapshot_claim": "NOT_ASSERTED",
            "read_evidence": {"manifest_path": str(manifest_out), "manifest_sha256": cli._sha(manifest_raw),
                              "manifest_bytes": len(manifest_raw), "ledger_path": str(ledger_out),
                              "ledger_sha256": cli._sha(ledger_raw), "ledger_bytes": len(ledger_raw)},
            "read_only_source_access": True, "source_reads": len(rows),
            "actual_unique_source_bytes_read": result["actual_unique_document_bytes_read"],
            "documentary_references_are_causal": False, "authority_effect": "NONE"}


def _documents_to_totals(cli: Any, *, selection_manifest: str, output_dir: str,
                         flags: dict[str, bool], provenance_mode: str,
                         pipeline_intent_id: str | None = None) -> dict[str, Any]:
    cli._require_workspace_open()
    prefix = Path(output_dir)
    if prefix.is_absolute() or prefix.drive or ".." in prefix.parts or len(prefix.parts) != 1 or not prefix.name.startswith("pipeline-"):
        raise cli.I7Error("PIPELINE_OUTPUT_INVALID", "pipeline output must be a fresh pipeline-* run name")
    attempt_dir = cli._new_output_dir(cli.WORKSPACE / "runs" / (prefix.name + "-attempt"),
                                      "PIPELINE-" + cli.uuid.uuid4().hex, explicit=True)
    _append_pipeline_attempt(cli, attempt_dir, {"stage_a": "NOT_STARTED", "transfer": "NOT_STARTED",
                                                "stage_b": "NOT_EXECUTED", "i4": "NOT_EXECUTED",
                                                "i5_next": "NOT_EXECUTED", "context_query": "NOT_EXECUTED"},
                             "STARTED")
    try:
        result = _documents_to_totals_body(cli, selection_manifest=selection_manifest,
                                           output_dir=output_dir, flags=flags,
                                           provenance_mode=provenance_mode,
                                           pipeline_intent_id=pipeline_intent_id)
    except Exception as exc:
        runs = cli.WORKSPACE / "runs"
        scan_dir = runs / (prefix.name + "-A")
        stage_a_done = (scan_dir / "document-scan-manifest.jsonl").is_file()
        b_dir = runs / (prefix.name + "-B")
        b_started = b_dir.exists()
        _append_pipeline_attempt(cli, attempt_dir,
                                 {"stage_a": "PASS" if stage_a_done else "NOT_PROVEN",
                                  "transfer": ("PASS" if (attempt_dir / "transfer.json").is_file()
                                               else ("NOT_PROVEN" if stage_a_done else "NOT_EXECUTED")),
                                  "stage_b": "AMBIGUOUS_NO_REDISPATCH" if b_started else "NOT_EXECUTED",
                                  "i4": "NOT_PROVEN" if b_started else "NOT_EXECUTED",
                                  "i5_next": "NOT_PROVEN" if b_started else "NOT_EXECUTED",
                                  "context_query": "NOT_EXECUTED"}, "FAILED",
                                 failure={"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
        raise
    _append_pipeline_attempt(cli, attempt_dir,
                             {"stage_a": "PASS", "transfer": "PASS", "stage_b": "PASS",
                              "i4": "PASS_PROSPECTIVE_ENGINEERING_ONLY",
                              "i5_next": "PASS_PROSPECTIVE_ENGINEERING_ONLY",
                              "context_query": "AVAILABLE_READ_ONLY"}, "COMPLETED",
                             operation_id=result["stage_b"]["id"],
                             run_dir=result["stage_b"]["run_dir"],
                             result_sha256=result["stage_b"]["result"].get("run", {}).get("run_record_sha256"))
    result["pipeline_attempt_dir"] = str(attempt_dir)
    result["recovery_policy"] = "VERIFY_EXISTING_ARTIFACTS_ONLY_NO_REDISPATCH"
    return result


def _append_pipeline_attempt(cli: Any, attempt_dir: Path, stages: dict[str, str], status: str,
                             **details: Any) -> None:
    existing = sorted(attempt_dir.glob("attempt-*.json"))
    path = attempt_dir / f"attempt-{len(existing):03d}.json"
    cli._write_new(path, {"schema": "i7.pipeline-attempt.v1", "status": status,
                          "attempt_number": len(existing), "stages": stages,
                          "dispatch_policy": "NO_RETRY_NO_REDISPATCH", **details})


def _documents_to_totals_body(cli: Any, *, selection_manifest: str, output_dir: str,
                         flags: dict[str, bool], provenance_mode: str,
                         pipeline_intent_id: str | None = None) -> dict[str, Any]:
    """Produce exact document metadata A, bind it into totals input B, and run once."""
    if provenance_mode != "prospective":
        raise cli.I7Error("PIPELINE_PROVENANCE_MODE", "documents-to-totals requires prospective provenance mode")
    cli._require_workspace_open()
    cli._assert_pipeline_intent(pipeline_intent_id)
    documents_policy = _documents_policy(cli)
    scanner = cli._engineering_api()
    selection = cli._checked_absolute(selection_manifest, base=cli.FOCUSED_ROOT, must_exist=True)
    selection_raw = documents_policy._bounded_read(cli, scanner, selection, documents_policy.MAX_SELECTION_BYTES)
    selection_obj = cli._parse_json(selection_raw, "document selection")
    selection_schema = selection_obj.get("schema") if type(selection_obj) is dict else None
    if selection_schema == "i7.focused.real-document-selection.v1":
        if (not cli._same_path(selection, cli.REAL_DOCUMENT_SELECTION)
                or cli._sha(selection_raw) != cli.REAL_DOCUMENT_SELECTION_SHA256):
            raise cli.I7Error("DOCUMENT_SELECTION_NOT_ALLOWLISTED", "v1 pipeline requires the exact pinned eight-document selection")
        selected = selection_obj.get("documents")
        provider_id = "safe.documents.metadata.v1"
        selection_commitment = None
    elif selection_schema == documents_policy.SCHEMA:
        selection_obj, selected, _, checked_raw = documents_policy._manifest(cli, scanner, str(selection))
        if checked_raw != selection_raw:
            raise cli.I7Error("DOCUMENT_SELECTION_CHANGED", "v2 selection manifest changed during validation")
        provider_id = "safe.documents.metadata.v2"
        selection_commitment = selection_obj["selection_commitment_sha256"]
    else:
        raise cli.I7Error("DOCUMENT_SELECTION_INVALID", "pipeline selection schema is not a supported v1 or v2 contract")
    if type(selected) is not list or not 1 <= len(selected) <= 64:
        raise cli.I7Error("DOCUMENT_SELECTION_INVALID", "pipeline requires between 1 and 64 selected documents")
    expected_document_count = len(selected)
    run_parent = cli._lexical_path("runs", must_exist=False, base=cli.WORKSPACE)
    if not output_dir or ".." in Path(output_dir).parts:
        raise cli.I7Error("PIPELINE_OUTPUT_INVALID", "pipeline output must name a fresh workspace run prefix")
    prefix = Path(output_dir)
    if prefix.is_absolute() or prefix.drive or len(prefix.parts) != 1 or not prefix.name.startswith("pipeline-"):
        raise cli.I7Error("PIPELINE_OUTPUT_INVALID", "pipeline output must be a fresh pipeline-* run name")
    cli._checked_absolute(run_parent, base=cli.WORKSPACE, must_exist=False)
    stage_a_dir = run_parent / (prefix.name + "-A")
    stage_b_dir = run_parent / (prefix.name + "-B")
    if provider_id == "safe.documents.metadata.v1":
        stage_a = _document_metadata_provider(cli, selection_manifest=str(selection),
                                              output_dir=str(stage_a_dir),
                                              pipeline_intent_id=pipeline_intent_id)
    else:
        stage_a = _document_metadata_provider_v2(cli, selection_manifest=str(selection),
                                                 output_dir=str(stage_a_dir),
                                                 pipeline_intent_id=pipeline_intent_id)
    scan_dir = cli._checked_absolute(stage_a["output_dir"], base=cli.WORKSPACE, must_exist=True)
    manifest_path = cli._checked_absolute(scan_dir / "document-scan-manifest.jsonl", base=scan_dir, must_exist=True)
    ledger_path = cli._checked_absolute(scan_dir / "document-scan-ledger.jsonl", base=scan_dir, must_exist=True)
    manifest_raw, ledger_raw = manifest_path.read_bytes(), ledger_path.read_bytes()
    manifest_doc = cli._parse_json(manifest_raw.rstrip(b"\r\n"), "document scan manifest")
    ledger_rows = [cli._parse_json(line, "document scan ledger row") for line in ledger_raw.splitlines()]
    if (manifest_doc.get("snapshot_id") != stage_a.get("snapshot_id")
            or len(ledger_rows) != expected_document_count
            or manifest_doc.get("document_count") != expected_document_count
            or manifest_doc.get("coverage_status") != "COMPLETE"):
        raise cli.I7Error("DOCUMENT_METADATA_OUTPUT_INVALID", "A output is not the exact complete selected-document scan")
    selection_after = documents_policy._bounded_read(cli, scanner, selection, documents_policy.MAX_SELECTION_BYTES)
    if selection_after != selection_raw or cli._sha(selection_after) != stage_a.get("selection_manifest_sha256"):
        raise cli.I7Error("DOCUMENT_SELECTION_CHANGED", "selection manifest changed after metadata scan")
    by_id = {row.get("path_id"): row for row in ledger_rows}
    if set(by_id) != {row.get("path_id") for row in selected}:
        raise cli.I7Error("DOCUMENT_METADATA_SELECTION_MISMATCH", "A ledger identities differ from the pinned selection")
    ordered = []
    for row in selected:
        found = by_id[row["path_id"]]
        if (found.get("size") != row["bytes"] or found.get("sha256") != row["sha256"]
                or found.get("status") != "HASHED"):
            raise cli.I7Error("DOCUMENT_METADATA_COMMITMENT_MISMATCH", "A ledger size or hash differs from selection")
        item = {"path_id": row["path_id"], "sha256": found["sha256"], "bytes": found["size"]}
        if "file_identity" in row:
            item["file_identity"] = row["file_identity"]
        ordered.append(item)
    values = [row["bytes"] for row in ordered]
    if (len(values) > cli.MAX_VALUES or any(type(value) is not int or value < cli.MIN_VALUE or value > cli.MAX_VALUE
                                             for value in values)):
        raise cli.I7Error("DOCUMENT_TOTAL_NOT_INT32", "selected document byte counts must fit the unchanged 64-value int32 engine contract")
    b_raw = cli._json_bytes({"schema": cli.INPUT_SCHEMA, "values": values})
    if len(b_raw) > cli.MAX_INPUT_BYTES:
        raise cli.I7Error("INPUT_TOO_LARGE", "derived totals input exceeds the existing bounded engine input limit")
    inputs_dir = cli._checked_absolute(cli.INPUTS_ROOT, base=cli.WORKSPACE, must_exist=False)
    if not inputs_dir.exists():
        parent_id = cli._object_id(cli.WORKSPACE)
        cli._write_probe(cli.WORKSPACE)
        try:
            inputs_dir.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise cli.I7Error("INPUT_STAGE_COLLISION", "workspace inputs directory appeared during exclusive creation") from exc
        if cli._object_id(cli.WORKSPACE) != parent_id:
            raise cli.I7Error("INPUT_STAGE_PARENT_CHANGED", "workspace parent changed during inputs directory creation")
        inputs_dir = cli._checked_absolute(inputs_dir, base=cli.WORKSPACE, must_exist=True)
    if cli._is_reparse(inputs_dir) or not cli._beneath(inputs_dir, cli.WORKSPACE):
        raise cli.I7Error("INPUT_STAGE_SCOPE", "derived input directory is redirected or outside workspace")
    b_path = inputs_dir / (cli._sha(b_raw) + ".json")
    try:
        cli._write_bytes_new(b_path, b_raw)
    except FileExistsError as exc:
        raise cli.I7Error("REPLAY_REJECTED", "derived input already exists in this workspace") from exc
    if cli._sha(b_path.read_bytes()) != cli._sha(b_raw):
        raise cli.I7Error("INPUT_STAGE_PIN_MISMATCH", "derived B input did not read back exactly")
    transfer_id = "TRANSFER-" + cli.uuid.uuid4().hex
    transfer = {"schema": "i7.pipeline-transfer.v1", "transfer_id": transfer_id,
                "stage_a_id": stage_a["snapshot_id"], "stage_a_status": stage_a["status"],
                "stage_a_manifest_sha256": cli._sha(manifest_raw), "stage_a_manifest_bytes": len(manifest_raw),
                "stage_a_manifest_base64": cli.base64.b64encode(manifest_raw).decode("ascii"),
                "stage_a_ledger_sha256": cli._sha(ledger_raw), "stage_a_ledger_bytes": len(ledger_raw),
                "stage_a_ledger_base64": cli.base64.b64encode(ledger_raw).decode("ascii"),
                "stage_a_output_dir": str(scan_dir),
                "selection_manifest_path": str(selection),
                "selection_manifest_base64": cli.base64.b64encode(selection_raw).decode("ascii"),
                "selection_sha256": cli._sha(selection_raw), "selection_schema": selection_schema,
                "selection_commitment_sha256": selection_commitment,
                "metadata_provider_id": provider_id, "document_count": expected_document_count,
                "documents": ordered, "documentary_references_are_causal": False,
                "stage_b_input_sha256": cli._sha(b_raw), "stage_b_input_bytes": len(b_raw),
                "stage_b_values": values}
    attempt_evidence = run_parent / (prefix.name + "-attempt")
    cli._write_new(attempt_evidence / "transfer.json", transfer)
    try:
        stage_b = cli._execute(operation="run", input_value=str(b_path), output_dir=str(stage_b_dir),
                               provider_id=cli.PROVIDER_ID, negative=False, flags=flags,
                               input_sha256=cli._sha(b_raw), provenance_mode="prospective",
                               pipeline_transfer=transfer, _pipeline_intent_id=pipeline_intent_id)
    except Exception as exc:
        failure = {"schema": "i7.pipeline-attempt.v1", "status": "FAILED", "stage_a": stage_a,
                   "transfer_id": transfer_id, "stage_b": {"status": "NOT_PROVEN", "dispatched": "UNKNOWN"},
                   "failure": {"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)},
                   "dependency_status": "NOT_EXECUTED_OR_AMBIGUOUS; NEW WORKSPACE REQUIRED"}
        failure_path = scan_dir / "pipeline-attempt-failure.json"
        if not failure_path.exists():
            cli._write_new(failure_path, failure)
        raise
    result = {"schema": "i7.pipeline-documents-to-totals.v1" if provider_id == "safe.documents.metadata.v1" else "i7.pipeline-documents-to-totals.v2",
              "status": stage_b["status"], "provider_id": cli.PROVIDER_ID,
              "metadata_provider_id": provider_id,
              "selection_schema": selection_schema, "selection_commitment_sha256": selection_commitment,
              "stage_a": {"id": stage_a["snapshot_id"], "status": stage_a["status"],
                          "output_dir": stage_a["output_dir"], "document_count": expected_document_count,
                          "source_document_count": stage_a["source_document_count"],
                          "actual_unique_source_bytes_read": stage_a["actual_unique_source_bytes_read"],
                          "manifest_sha256": transfer["stage_a_manifest_sha256"],
                          "ledger_sha256": transfer["stage_a_ledger_sha256"]},
              "transfer": {"id": transfer_id, "status": "VERIFIED_EXACT", "input_sha256": cli._sha(b_raw),
                           "input_bytes": len(b_raw), "values": values, "sum": sum(values)},
              "stage_b": {"id": stage_b["operation_id"], "status": stage_b["status"],
                          "run_dir": stage_b["run_dir"], "result": stage_b},
              "causal_data": stage_b.get("run", {}).get("evidence_artifacts", {}).get("i4", {}),
              "i4_graph": {"path": stage_b.get("run", {}).get("evidence_artifacts", {}).get("artifacts", {}).get("causal_graph", {}).get("path"),
                           "sha256": stage_b.get("run", {}).get("evidence_artifacts", {}).get("artifacts", {}).get("causal_graph", {}).get("sha256")},
              "i5_next": {"status": stage_b.get("prospective_provenance", {}).get("i5_next_status"),
                          "graph_version": stage_b.get("prospective_provenance", {}).get("graph_version"),
                          "graph_sha256": stage_b.get("prospective_provenance", {}).get("graph_sha256"),
                          "provenance_sha256": stage_b.get("prospective_provenance", {}).get("provenance_sha256"),
                          "i4_semantic_sha256": stage_b.get("prospective_provenance", {}).get("i4_semantic_sha256")},
              "provenance": stage_b.get("prospective_provenance", {}),
              "documentary_references_are_causal": False, "authority_effect": "NONE"}
    pipeline_path = Path(stage_b["run_dir"]) / "PIPELINE_EXECUTION.json"
    cli._write_new(pipeline_path, result)
    result["pipeline_record"] = {"path": str(pipeline_path), "sha256": cli._sha(pipeline_path.read_bytes()),
                                 "bytes": pipeline_path.stat().st_size}
    return result


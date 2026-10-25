"""Prospective OP1 NEXT provenance bridge using the byte-pinned Context Engine.

The adapter is Engineering-only. It preserves exact source bytes and leaves model,
process, actor authenticity, custody, and operational authority UNKNOWN/NOT_PROVEN.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import uuid
from typing import Any

CONTEXT_ENGINE_SHA256 = "1fdbf50fe56e82ec86e96dff3039a0bf5d8cfbddc217d9f2d928b7a62bd62568"

class ProspectiveError(ValueError):
    pass

def _require_cli_workspace(workspace: Path, *, mutating: bool) -> Any:
    cli = sys.modules.get("__main__")
    if cli is None or not callable(getattr(cli, "_require_bound_workspace", None)):
        cli = sys.modules.get("pg_i7")
    if cli is None or not callable(getattr(cli, "_require_bound_workspace", None)):
        raise ProspectiveError("prospective adapter requires the pinned CLI workspace guard")
    cli._require_bound_workspace()
    bound_workspace = cli._checked_absolute(cli.WORKSPACE, base=cli.WORKSPACE, must_exist=True)
    checked_workspace = cli._checked_absolute(workspace, base=bound_workspace, must_exist=True)
    if checked_workspace != bound_workspace:
        raise ProspectiveError("prospective adapter workspace differs from the active bound CLI")
    if mutating:
        cli._require_workspace_open(checked_workspace)
    return cli

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _json(raw: bytes) -> Any:
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ProspectiveError("duplicate JSON key")
            out[key] = value
        return out
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ProspectiveError("nonfinite JSON")))

def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(parent.resolve(strict=True))
        return True
    except (ValueError, OSError):
        return False

def _safe_file(path: Path, root: Path) -> Path:
    raw_path = Path(os.fspath(path))
    if ".." in raw_path.parts:
        raise ProspectiveError("parent traversal rejected in prospective evidence path")
    lexical = Path(os.path.abspath(os.fspath(raw_path)))
    root = root.resolve(strict=True)
    if not lexical.is_relative_to(root) or not lexical.exists():
        raise ProspectiveError("source path escaped the bound workspace")
    for item in (lexical, *lexical.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ProspectiveError("reparse point in prospective evidence path")
    path = lexical.resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or not os.path.samefile(lexical, path):
        raise ProspectiveError("prospective evidence object changed during path resolution")
    if int(getattr(path.stat(), "st_nlink", 1)) != 1:
        raise ProspectiveError("hard-linked prospective source rejected")
    return path

def _safe_store_tree(store: Path) -> None:
    lexical = Path(os.path.abspath(os.fspath(store)))
    for path in (lexical, *lexical.parents):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ProspectiveError("reparse point in prospective Context Engine path")
    root = lexical.resolve(strict=True)
    if not root.is_dir():
        raise ProspectiveError("prospective Context Engine store is not a directory")
    for path in root.rglob("*"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ProspectiveError("reparse point in prospective Context Engine store")
        if path.is_file() and int(getattr(path.stat(), "st_nlink", 1)) != 1:
            raise ProspectiveError("hard-linked Context Engine store file rejected")

def _engine_api(workspace: Path):
    source = _safe_file(workspace / "context_engine.py", workspace)
    raw = source.read_bytes()
    if _sha(raw) != CONTEXT_ENGINE_SHA256:
        raise ProspectiveError("copied Context Engine source pin mismatch")
    name = "_pg_i7_context_engine_" + CONTEXT_ENGINE_SHA256[:12]
    loaded = sys.modules.get(name)
    if loaded is not None:
        if Path(getattr(loaded, "__file__", "")).resolve() != source:
            raise ProspectiveError("Context Engine import collision")
        return loaded
    spec = importlib.util.spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise ProspectiveError("Context Engine import specification unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def _i4_semantic(workspace: Path, output: Path, *, documents: bool) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    sidecar = _safe_file(workspace / "evidence_sidecar.py", workspace)
    loaded = sys.modules.get("evidence_sidecar")
    if loaded is None or Path(getattr(loaded, "__file__", "")).resolve() != sidecar:
        raise ProspectiveError("pinned evidence sidecar must be loaded before NEXT I4 reconstruction")
    (canonical_json, _, sha256_bytes, strict_json_loads, CausalGraph, SourceCorpus,
     i4_pointer, require_dag, *_rest) = loaded._load_frozen_apis()
    if documents:
        corpus_dir = output / "i4_document_source_corpus"
        records_dir = output / "i4_document_graph_records"
        graph_path = output / "REAL_DOCUMENT_I4_GRAPH.json"
        binding_path = output / "REAL_DOCUMENT_I5_INTEGRATION.json"
    else:
        corpus_dir = output / "i4_source_corpus"
        records_dir = output / "i4_graph_records"
        graph_path = output / "CAUSAL_GRAPH.json"
        binding_path = output / "PROVENANCE.json"
    manifest_path = _safe_file(corpus_dir / "manifest.json", output)
    manifest_raw = manifest_path.read_bytes()
    manifest = strict_json_loads(manifest_raw)
    manifest_files = manifest.get("files") if type(manifest) is dict else None
    if type(manifest_files) is not list:
        raise ProspectiveError("I4 source corpus manifest is malformed")
    for row in manifest_files:
        if type(row) is not dict:
            raise ProspectiveError("I4 source corpus member row is malformed")
        relative = row.get("corpus_path")
        if (not isinstance(relative, str) or not relative or "\\" in relative
                or Path(relative).is_absolute() or Path(relative).drive
                or any(part in {"", ".", ".."} for part in relative.split("/"))):
            raise ProspectiveError("I4 source corpus member path is unsafe")
        member = _safe_file(corpus_dir.joinpath(*relative.split("/")), output)
        body = member.read_bytes()
        if len(body) != row.get("byte_length") or _sha(body) != row.get("sha256"):
            raise ProspectiveError("I4 source corpus member commitment mismatch")
    corpus = SourceCorpus(corpus_dir, manifest, sha256_bytes(manifest_raw), manifest_bytes=manifest_raw)
    record_paths = sorted(p for p in records_dir.glob("record-*.json") if p.is_file())
    if not record_paths:
        raise ProspectiveError("I4 graph records are missing")
    for path in record_paths:
        _safe_file(path, output)
    records = [path.read_bytes() for path in record_paths]
    graph = CausalGraph.rebuild(corpus, records)
    require_dag(graph.nodes, graph.edges)
    semantic_raw = canonical_json(graph.semantic_view())
    graph_doc = _json(_safe_file(graph_path, output).read_bytes())
    binding = _json(_safe_file(binding_path, output).read_bytes()) if binding_path.is_file() else {}
    if graph_doc.get("graph_root") != graph.root():
        raise ProspectiveError("rebuilt current I4 graph root differs from the CLI graph projection")
    if documents:
        # Documentary graph projections have role-specific nodes and no causal
        # edges. Reuse their existing frozen reconstruction verifier instead
        # of applying the synthetic CLI projection contract.
        snapshot_id = graph_doc.get("snapshot_id")
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ProspectiveError("document graph snapshot identity is missing")
        verifier = getattr(loaded, "verify_document_graph", None)
        if not callable(verifier):
            raise ProspectiveError("pinned documentary graph verifier is unavailable")
        document_result = verifier(output, expected_snapshot_id=snapshot_id)
        if (document_result.get("status") != "PASS"
                or document_result.get("i4_semantic_sha256") != _sha(semantic_raw)):
            raise ProspectiveError("rebuilt documentary I4 graph projection differs from the CLI artifact")
    elif loaded._projection(graph, graph_doc, i4_pointer) is not True:
        raise ProspectiveError("rebuilt current I4 graph projection differs from the CLI artifact")
    expected = (binding.get("i4_semantic_sha256") if documents else
                binding.get("current_i4_i5_integration", {}).get("i4_semantic_sha256"))
    if expected is not None and _sha(semantic_raw) != expected:
        raise ProspectiveError("rebuilt current I4 semantic bytes differ from the CLI artifact binding")
    return semantic_raw, graph_doc, binding

def _write_exact(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ProspectiveError("prospective exact-byte source copy mismatch")

def _source_specs(output: Path, *, documents: bool) -> list[tuple[str, Path]]:
    if documents:
        paths = [("REAL_DOCUMENT_I4_GRAPH.json", output / "REAL_DOCUMENT_I4_GRAPH.json"),
                 ("REAL_DOCUMENT_I5_INTEGRATION.json", output / "REAL_DOCUMENT_I5_INTEGRATION.json"),
                 ("PROVENANCE.json", output / "PROVENANCE.json"),
                 ("i4-document-corpus-manifest.json", output / "i4_document_source_corpus" / "manifest.json"),
                 ("document-scan-manifest-input.json", output / "document-scan-manifest-input.json")]
        for path in sorted((output / "i4_document_graph_records").glob("record-*.json")):
            paths.append(("i4-document-record-" + path.name, path))
        receipt = output / "independent-receipt-input.json"
        if receipt.is_file():
            paths.append(("independent-receipt.json", receipt))
        return paths
    paths = []
    for name in ("run.json", "run.index.json", "result.json", "CAUSAL_GRAPH.json",
                 "I7_EVIDENCE_BINDING.json", "DATA_DIGEST.json"):
        path = output / name
        if path.is_file():
            paths.append((name, path))
    for path in sorted((output / "i4_source_corpus").iterdir()):
        if not path.is_file() or path.suffix.casefold() != ".json":
            continue
        paths.append(("i4-source-" + path.name, path))
    return paths

def _build(output: Path, workspace: Path, *, task_id: str, run_id: str,
           documents: bool, scan_dir: Path | None = None,
           receipt_path: Path | None = None) -> dict[str, Any]:
    cli = _require_cli_workspace(workspace, mutating=True)
    output = cli._checked_absolute(output, base=workspace, must_exist=True)
    if not _inside(output, workspace / "runs"):
        raise ProspectiveError("prospective output is outside bound workspace runs")
    if documents:
        if scan_dir is not None:
            scan_dir = cli._checked_absolute(scan_dir, base=workspace, must_exist=True)
            if not _inside(scan_dir, workspace / "runs") or not scan_dir.is_dir():
                raise ProspectiveError("document scan path is outside bound workspace runs")
        if receipt_path is not None:
            receipt_path = cli._checked_absolute(receipt_path, base=workspace, must_exist=True)
            if not receipt_path.is_file():
                raise ProspectiveError("independent receipt path is not a file")
    output = output.resolve(strict=True)
    workspace = workspace.resolve(strict=True)
    if not _inside(output, workspace / "runs"):
        raise ProspectiveError("prospective output is outside bound workspace runs")
    store = output / "context-next-store"
    if store.exists() or store.is_symlink():
        raise ProspectiveError("prospective Context Engine store must be fresh")
    semantic_raw, graph_doc, sidecar_binding = _i4_semantic(workspace, output, documents=documents)
    engine_module = _engine_api(workspace)
    engine = engine_module.Engine(store)
    materials = store / "source-materials"
    materials.mkdir(exist_ok=False)
    input_paths = _source_specs(output, documents=documents)
    if documents and receipt_path is not None and not any(label == "independent-receipt.json" for label, _ in input_paths):
        input_paths.append(("independent-receipt.json", receipt_path))
    source_rows = {}
    for label, original in input_paths:
        source = _safe_file(original, workspace)
        raw = source.read_bytes()
        try:
            _json(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ProspectiveError) as exc:
            raise ProspectiveError("Context Engine source must be one strict JSON artifact: " + label) from exc
        filename = f"{len(source_rows):04d}-{_sha(label.encode())[:12]}.json"
        material_path = materials / filename
        _write_exact(material_path, raw)
        source_id = "cli-artifact-" + _sha((label + _sha(raw)).encode())[:48]
        row = engine.admit_source(material_path, _sha(raw), scope="ENGINEERING_RESULT", source_id=source_id)
        source_rows[label] = {"source_id": source_id, "original_path": str(source),
                              "sha256": row["sha256"], "bytes": row["byte_length"]}
    semantic_path = materials / "current-i4-semantic.json"
    _write_exact(semantic_path, semantic_raw)
    semantic_id = "i4-semantic-" + _sha(semantic_raw)
    engine.admit_source(semantic_path, _sha(semantic_raw), scope="ENGINEERING_RESULT", source_id=semantic_id)
    graph_label = "REAL_DOCUMENT_I4_GRAPH.json" if documents else "CAUSAL_GRAPH.json"
    graph_source_id = source_rows[graph_label]["source_id"]
    observations = []
    run_source = source_rows.get("run.json")
    if not documents and run_source is not None:
        observations.append({"id": "operation-identity-" + _sha((task_id + run_id).encode()),
                             "kind": "operation_identity", "task_id": task_id,
                             "run_id": run_id, "session_id": "UNKNOWN", "artifact_id": run_id,
                             "text": "Operation ID bound to the committed CLI run record; actor, process, and provider identity remain UNKNOWN.",
                             "evidence_binding": {"source_id": run_source["source_id"], "pointer": "/operation_id"}})
    graph_nodes = graph_doc.get("nodes", [])
    if type(graph_nodes) is not list:
        raise ProspectiveError("I4 graph node list is malformed")
    for index, node in enumerate(graph_nodes):
        if type(node) is not dict:
            raise ProspectiveError("I4 graph node is malformed")
        identity = node.get("id") or node.get("identity") or f"i4-node-{index:04d}"
        if not isinstance(identity, str) or not identity:
            raise ProspectiveError("I4 graph node identity is malformed")
        observations.append({"id": identity, "event_id": node.get("event_id", identity),
                            "kind": "document_observation" if documents else "cli_event",
                            "task_id": task_id, "run_id": run_id, "session_id": "UNKNOWN",
                            "artifact_id": node.get("source", node.get("identity", "UNKNOWN")),
                            "text": "Exact I4 node projection bound to current semantic bytes; actor/model/process remain UNKNOWN.",
                            "evidence_binding": {"source_id": graph_source_id, "pointer": f"/nodes/{index}"}})
    # The semantic bytes are a separate identity anchor, not a causal edge to the CLI result.
    observations.append({"id": "current-i4-semantic-" + _sha(semantic_raw),
                         "kind": "i4_semantic_graph_identity", "task_id": task_id,
                         "run_id": "UNKNOWN", "session_id": "UNKNOWN",
                         "artifact_id": "sha256:" + _sha(semantic_raw),
                         "text": "Current generated I4 semantic graph bytes rebuilt and hash-matched; no frozen fixture substitution.",
                         "evidence_binding": {"source_id": semantic_id, "pointer": ""}})
    for label, row in source_rows.items():
        if label == graph_label:
            continue
        # Bind each original CLI/document artifact as an independent observation in this same graph version.
        observations.append({"id": "artifact-" + _sha(label.encode())[:12] + row["sha256"][:32], "kind": "cli_artifact",
                             "task_id": task_id, "run_id": run_id, "session_id": "UNKNOWN",
                             "artifact_id": row["original_path"],
                             "text": "Exact local artifact bytes admitted from the bound output; declaration does not establish actor or authority.",
                             "evidence_binding": {"source_id": row["source_id"], "pointer": ""}})
    # Pipeline identity references are registered at execution time against the
    # already admitted evidence-binding artifact. Engine.query remains the sole
    # query implementation; these documentary rows do not create causal edges.
    evidence_row = source_rows.get("I7_EVIDENCE_BINDING.json")
    if evidence_row is not None:
        evidence_value = _json(Path(evidence_row["original_path"]).read_bytes())
        input_record = evidence_value.get("input_record") if type(evidence_value) is dict else None
        transfer = input_record.get("pipeline_transfer") if type(input_record) is dict else None
        if type(transfer) is dict and transfer.get("selection_schema") == "pg_i7.documents.selection.v2":
            provider_id = transfer.get("metadata_provider_id")
            commitment = transfer.get("selection_commitment_sha256")
            docs = transfer.get("documents")
            if (provider_id != "safe.documents.metadata.v2"
                    or not isinstance(commitment, str) or not re.fullmatch(r"[0-9a-f]{64}", commitment)
                    or type(docs) is not list or not 1 <= len(docs) <= 64):
                raise ProspectiveError("committed v2 document identity vector is malformed")
            binding_source = evidence_row["source_id"]
            observations.append({"id": "document-provider-" + _sha((task_id + provider_id).encode()),
                                 "kind": "document_provider_identity", "task_id": task_id,
                                 "run_id": run_id, "session_id": "UNKNOWN", "artifact_id": provider_id,
                                 "text": "Declared metadata provider ID bound to the committed pipeline transfer; execution identity remains UNKNOWN.",
                                 "evidence_binding": {"source_id": binding_source,
                                                      "pointer": "/input_record/pipeline_transfer/metadata_provider_id"}})
            observations.append({"id": "document-selection-" + commitment,
                                 "kind": "document_selection_identity", "task_id": task_id,
                                 "run_id": run_id, "session_id": "UNKNOWN", "artifact_id": commitment,
                                 "event_id": "selection-" + commitment,
                                 "text": "Selection commitment recorded as documentary evidence; it does not assert an atomic cross-document snapshot.",
                                 "evidence_binding": {"source_id": binding_source,
                                                      "pointer": "/input_record/pipeline_transfer/selection_commitment_sha256"}})
            for index, document in enumerate(docs):
                path_id = document.get("path_id") if type(document) is dict else None
                if not isinstance(path_id, str) or not re.fullmatch(r"[0-9a-f]{64}", path_id):
                    raise ProspectiveError("committed v2 document path identity is malformed")
                observations.append({"id": "represented-document-" + path_id,
                                     "kind": "represented_document_identity", "task_id": task_id,
                                     "run_id": run_id, "session_id": "UNKNOWN", "artifact_id": path_id,
                                     "text": "Represented document identity from the verified metadata transfer; source content was not reconstructed here.",
                                     "evidence_binding": {"source_id": binding_source,
                                                          "pointer": f"/input_record/pipeline_transfer/documents/{index}/path_id"}})
    binding_body = {"schema": "i7.prospective.context-engine.binding.v1", "task_id": task_id,
                    "run_id": run_id, "i4_semantic_sha256": _sha(semantic_raw),
                    "documentary_references_are_causal": False if documents else None,
                    "source_artifacts": {label: {"path": row["original_path"], "sha256": row["sha256"], "bytes": row["bytes"]}
                                         for label, row in source_rows.items()},
                    "provider_identity": "UNKNOWN", "process_identity": "UNKNOWN",
                    "actor_identity": "UNKNOWN", "custody": "NOT_PROVEN"}
    binding_raw = json.dumps(binding_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    binding_path = materials / "prospective-binding.json"
    _write_exact(binding_path, binding_raw)
    binding_id = "next-binding-" + _sha(binding_raw)
    engine.admit_source(binding_path, _sha(binding_raw), scope="ENGINEERING_RESULT", source_id=binding_id)
    observations.append({"id": binding_id, "kind": "prospective_binding", "task_id": task_id,
                         "run_id": run_id, "session_id": "UNKNOWN",
                         "text": "Exact output artifact hashes and current I4 semantic identity bound to this NEXT graph version.",
                         "evidence_binding": {"source_id": binding_id, "pointer": ""}})
    edges = []
    for index, edge in enumerate(graph_doc.get("edges", [])):
        if type(edge) is not dict:
            raise ProspectiveError("I4 graph edge is malformed")
        source_id, target_id = edge.get("source_id"), edge.get("target_id")
        if source_id in {item["id"] for item in graph_nodes} and target_id in {item["id"] for item in graph_nodes}:
            edges.append({"id": str(edge.get("id") or f"i4-edge-{index:04d}"), "from": source_id,
                          "to": target_id, "relationship": "DERIVED_ASSOCIATION",
                          "evidence_bindings": [{"source_id": graph_source_id, "pointer": f"/edges/{index}"}]})
    latest = engine.latest()
    manifest = engine.ingest(observations, edges,
                             expected_parent=(latest["graph_sha256"] if latest else None),
                             provenance={"declared_actor_identity": "UNKNOWN", "provider_identity": "UNKNOWN",
                                         "process_identity": "UNKNOWN", "tool_identity": "UNKNOWN",
                                         "timestamp": "UNKNOWN", "invocation_evidence": "UNKNOWN"})
    checked = engine.verify()
    if checked.get("status") != "PASS":
        raise ProspectiveError("new Context Engine graph did not verify")
    version_dir = store / "versions" / f"{manifest['version']:08d}-{manifest['graph_sha256']}"
    provenance = _json((version_dir / "provenance.json").read_bytes())
    if any(row.get("provider_identity") != "UNKNOWN" or row.get("process_identity") != "UNKNOWN"
           or row.get("independent_custody") != "NOT_PROVEN" for row in provenance.get("records", [])):
        raise ProspectiveError("Context Engine provenance fabricated provider, process, or custody")
    if documents and graph_doc.get("edge_count") != 0:
        raise ProspectiveError("documentary references may not be promoted into causal edges")
    return {"status": "PASS_PROSPECTIVE_ENGINEERING_ONLY", "store": str(store),
            "task_id": task_id, "run_id": run_id, "i4_semantic_sha256": _sha(semantic_raw),
            "graph_version": manifest["version"], "graph_sha256": manifest["graph_sha256"],
            "provenance_sha256": manifest["provenance_sha256"], "observations": len(observations),
            "derived_edges": len(edges), "documentary_references_are_causal": False if documents else None,
            "i5_next_status": "ENGINEERING_ONLY; NOT FORMAL I5 ACCEPTANCE",
            "identity": "UNKNOWN", "independent_custody": "NOT_PROVEN",
            "original_external_source_reads": 0,
            "engine_source_admission_reads": engine.metrics.get("SOURCE_READS", 0),
            "source_artifact_hashes": {key: row["sha256"] for key, row in source_rows.items()}}

def build_for_run(workspace: Path, run_dir: Path) -> dict[str, Any]:
    cli = _require_cli_workspace(workspace, mutating=True)
    run_dir = cli._checked_absolute(run_dir, base=workspace, must_exist=True)
    if not _inside(run_dir, workspace / "runs") or not run_dir.is_dir():
        raise ProspectiveError("prospective run is outside bound workspace runs")
    record = _json(_safe_file(run_dir / "run.json", workspace).read_bytes())
    operation_id = record.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        raise ProspectiveError("CLI run identity is missing")
    return _build(run_dir, workspace, task_id="cli-run:" + operation_id, run_id=operation_id,
                  documents=False)

def build_for_documents(workspace: Path, output_dir: Path, scan_dir: Path,
                        receipt_path: Path) -> dict[str, Any]:
    cli = _require_cli_workspace(workspace, mutating=True)
    output_dir = cli._checked_absolute(output_dir, base=workspace, must_exist=True)
    if not _inside(output_dir, workspace / "runs") or not output_dir.is_dir():
        raise ProspectiveError("document output is outside bound workspace runs")
    scan_dir = cli._checked_absolute(scan_dir, base=workspace, must_exist=True)
    if not _inside(scan_dir, workspace / "runs") or not scan_dir.is_dir():
        raise ProspectiveError("document scan path is outside bound workspace runs")
    receipt_path = cli._checked_absolute(receipt_path, base=workspace, must_exist=True)
    if not receipt_path.is_file():
        raise ProspectiveError("independent receipt path is not a file")
    graph = _json(_safe_file(output_dir / "REAL_DOCUMENT_I4_GRAPH.json", workspace).read_bytes())
    snapshot = graph.get("snapshot_id")
    if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise ProspectiveError("document snapshot identity is missing")
    return _build(output_dir, workspace, task_id="document-snapshot:" + snapshot,
                  run_id=output_dir.name, documents=True, scan_dir=scan_dir.resolve(strict=True),
                  receipt_path=receipt_path.resolve(strict=True))

def verify(workspace: Path, output_dir: Path, *, expected_run_id: str | None = None,
           documents: bool = False, include_observations: bool = False) -> dict[str, Any]:
    cli = _require_cli_workspace(workspace, mutating=False)
    output_dir = cli._checked_absolute(output_dir, base=workspace, must_exist=True)
    if not _inside(output_dir, workspace / "runs") or not output_dir.is_dir():
        raise ProspectiveError("verified output is outside bound workspace runs")
    output_dir = output_dir.resolve(strict=True)
    store = output_dir / "context-next-store"
    if not store.is_dir() or store.is_symlink() or not _inside(store, output_dir):
        raise ProspectiveError("prospective store is missing or outside the verified output")
    _safe_store_tree(store)
    engine_module = _engine_api(workspace)
    engine = engine_module.Engine.__new__(engine_module.Engine)
    engine.root = store.resolve(strict=True)
    engine.metrics = {"REPEATED_SOURCE_READS": 0, "SOURCE_READS": 0, "RECONSTRUCTION_REQUIRED": False}
    engine._raw_cache = {}
    engine._parsed_cache = {}
    engine._index_stat = None
    engine._graph = None
    engine._manifest = None
    checked = engine.verify()
    if checked.get("status") != "PASS" or engine._manifest is None:
        raise ProspectiveError("read-only Context Engine verification failed")
    rows = engine._graph.get("observations", []) if engine._graph else []
    for source in engine._sources().values():
        source_path = Path(source.get("path", ""))
        if (not source_path.is_absolute() or not source_path.resolve(strict=True).is_relative_to(store.resolve(strict=True))):
            raise ProspectiveError("Context Engine source descriptor escaped its exact output store")
    semantic_raw, graph_doc, _ = _i4_semantic(workspace, output_dir, documents=documents)
    semantic_rows = [row for row in rows if row.get("kind") == "i4_semantic_graph_identity"]
    if len(semantic_rows) != 1:
        raise ProspectiveError("prospective graph lacks one exact current-I4 semantic identity anchor")
    if semantic_rows[0].get("artifact_id") != "sha256:" + _sha(semantic_raw):
        raise ProspectiveError("prospective I4 semantic identity differs from rebuilt current graph")
    binding_rows = [row for row in rows if row.get("kind") == "prospective_binding"]
    if len(binding_rows) != 1:
        raise ProspectiveError("prospective graph lacks its unique source/output binding")
    binding_id = binding_rows[0]["evidence_binding"]["source_id"]
    binding_raw = engine.read_source(binding_id)
    binding = _json(binding_raw)
    if binding.get("task_id") != binding_rows[0].get("task_id") or binding.get("run_id") != binding_rows[0].get("run_id"):
        raise ProspectiveError("prospective binding identity differs from its graph observation")
    if binding.get("i4_semantic_sha256") != _sha(semantic_raw):
        raise ProspectiveError("prospective binding semantic identity differs from rebuilt current graph")
    expected_artifacts = {}
    for label, original in _source_specs(output_dir, documents=documents):
        source = _safe_file(original, output_dir)
        raw = source.read_bytes()
        expected_artifacts[label] = {"path": str(source), "sha256": _sha(raw), "bytes": len(raw)}
    if binding.get("source_artifacts") != expected_artifacts:
        raise ProspectiveError("prospective output artifact identities differ from the committed binding")
    if expected_run_id is not None and not any(row.get("run_id") == expected_run_id for row in rows):
        raise ProspectiveError("prospective graph run identity differs from the original CLI operation")
    result = {"status": "PASS", "store": str(store), "graph_version": engine._manifest["version"],
              "graph_sha256": engine._manifest["graph_sha256"],
              "provenance_sha256": engine._manifest["provenance_sha256"],
              "observations": len(rows), "read_only": True,
              "provider_and_process_identity": "UNKNOWN", "independent_custody": "NOT_PROVEN"}
    if include_observations:
        result["records"] = rows
    return result


def query(workspace: Path, output_dir: Path, *, task_id: str | None = None,
          kind: str | None = None, identifier: str | None = None, limit: int = 50,
          include_superseded: bool = False, expected_run_id: str | None = None) -> list[dict[str, Any]]:
    """Use the pinned Engine.query semantics while refusing index reconstruction."""
    cli = _require_cli_workspace(workspace, mutating=False)
    checked = verify(workspace, output_dir, expected_run_id=expected_run_id,
                     include_observations=True)
    store = Path(checked["store"])
    _safe_store_tree(store)
    engine_module = _engine_api(workspace)
    base_engine = engine_module.Engine
    import sqlite3
    from types import SimpleNamespace
    index_path = _safe_file(store / "index.sqlite", store)
    index_uri = index_path.as_uri() + "?mode=ro"

    def readonly_connect(database, *args, **kwargs):
        try:
            requested = Path(database).resolve(strict=True)
        except (TypeError, OSError):
            requested = None
        if requested != index_path.resolve(strict=True) or args or kwargs:
            raise ProspectiveError("Context Engine read-only query attempted an unbound SQLite connection")
        return sqlite3.connect(index_uri, uri=True)

    class ReadOnlyEngine(base_engine):
        def _ensure_index(self):
            if not index_path.is_file():
                raise ProspectiveError("Context Engine query index is missing; read-only query will not rebuild it")
            try:
                with engine_module.sqlite3.connect(index_path) as db:
                    actual = db.execute("SELECT * FROM observations ORDER BY id").fetchall()
            except sqlite3.Error as exc:
                raise ProspectiveError("Context Engine query index is unreadable; read-only query will not rebuild it") from exc
            if actual != sorted(self._index_rows()):
                raise ProspectiveError("Context Engine query index differs from verified committed graph")
            self._index_stat = self._index_signature()

    engine = ReadOnlyEngine.__new__(ReadOnlyEngine)
    engine.root = store
    engine.metrics = {"REPEATED_SOURCE_READS": 0, "SOURCE_READS": 0, "RECONSTRUCTION_REQUIRED": False}
    engine._raw_cache = {}
    engine._parsed_cache = {}
    engine._index_stat = None
    engine._graph = None
    engine._manifest = None
    query_identifier = identifier
    query_task = task_id
    if identifier in {checked.get("graph_sha256"), checked.get("provenance_sha256")}:
        # Those digest identities are computed over the complete committed
        # version and cannot be embedded in that version without a cycle. After
        # verify() has matched the supplied digest to the current manifest,
        # resolve it to that run's already indexed observations using the
        # existing Engine.query implementation.
        bindings = [row for row in checked.get("records", [])
                    if row.get("kind") == "prospective_binding"]
        if len(bindings) != 1:
            raise ProspectiveError("verified version digest has no unique current run binding")
        current_task = bindings[0].get("task_id")
        if not isinstance(current_task, str) or not current_task:
            raise ProspectiveError("verified version digest has no bound task identity")
        if query_task is not None and query_task != current_task:
            return []
        query_task = current_task
        query_identifier = None
    original_sqlite = engine_module.sqlite3
    engine_module.sqlite3 = SimpleNamespace(connect=readonly_connect, Error=sqlite3.Error)
    try:
        return engine.query(task_id=query_task, kind=kind, identifier=query_identifier,
                            limit=limit, include_superseded=include_superseded)
    finally:
        engine_module.sqlite3 = original_sqlite


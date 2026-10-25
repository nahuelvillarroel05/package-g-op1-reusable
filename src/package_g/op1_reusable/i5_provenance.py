"""Source-bound I5 attribution over the unchanged I0/I1 and I4 contracts.

Frozen cores remain unchanged. Rich attributes are digest-bound ARTIFACT companions.
Attribution edges never enter the I4 causal graph or grant operational authority.
"""
from __future__ import annotations

from copy import deepcopy, copy
from threading import RLock
from typing import Any, Callable

from .identity import canonical_json, sha256_bytes, validate_id, strict_json_loads
from .registry import IdentityRegistry
from .schema_registry import SchemaRegistry
from .i4_graph import SourceCorpus, pointer
from importlib import resources

_design = resources.files(__package__).joinpath("frozen_i5", "OP1_MODEL_SUBAGENT_PROVENANCE_IMPLEMENTATION.json").read_bytes()
if sha256_bytes(_design) != "5391f9de0ef9151b073c7ed7219680150dfb2e6091fc5eb4cd2f906b3fcd3815":
    raise RuntimeError("frozen I5 implementation design differs")

I4_FINGERPRINT = "4a574976eaa7443505eaa4850ff9c000e5f1077fb636920a701d4da1e9b9a1b5"
PROVENANCE_SCHEMA_HASH = "e0359b233eeb7e2bd80e5fc0c0db1e1dd872e40bf6e8d41aabd69f46c22bf9fd"
CORE_TYPES = frozenset({"TASK", "DELEGATION", "REPORT", "REVIEW", "TOOL_INVOCATION"})
LEVELS = frozenset({"SELF_REPORTED", "OWNER_DECLARED", "CONFIGURED_IDENTITY",
                    "EXECUTION_RECEIPT", "HISTORICAL_ARTIFACT", "SYNTHETIC"})
STATUSES = frozenset({"CREATED", "ASSIGNED", "RUNNING", "SUCCESS", "FAILURE",
                      "BLOCKED", "TIMEOUT", "NO_OUTPUT", "UNKNOWN", "SUPERSEDED",
                      "COMMITTED", "ACCEPTED", "REJECTED", "PARTIAL"})
META_FIELDS = frozenset({
    "semantic_key", "claims", "evidence_level", "exact_attribution",
    "task_id", "parent_task_id", "requester_actor_id", "assignee_actor_id",
    "objective", "phase", "status", "input_refs", "output_refs", "role",
    "assignment_id", "supersedes_task_id", "delegation_id", "constraints",
    "scope", "operation_id", "session_id", "run_id", "i4_entity_id",
    "source_refs", "rationale", "side_effect_class", "order",
    "declared_timestamp", "output_absence_binding", "review_status",
    "historical_artifact_id", "drafted_by_actor_id", "decided_by_actor_id",
    "expected_assignment_id", "config_binding", "execution_binding",
})
DESCRIPTOR_FIELDS = {
    "ACTOR": {"actor_kind", "subject"},
    "MODEL": {"provider", "family", "designation", "version", "observed_identity",
              "declared_identity", "runtime_config_sha256"},
    "TOOL": {"name", "version", "runtime_config_sha256"},
}
class ProvenanceError(ValueError):
    """Admission fails without changing committed provenance."""
    def __init__(self, reason: str, outcome: str = "REJECT_PROVENANCE"):
        super().__init__(reason)
        self.outcome = outcome

class ProvenanceLedger:
    """A serializable append-only attribution view with exact-source admission.

    The corpus manifest fixes each source's evidence level. The caller must
    authenticate that corpus; a matching digest establishes byte identity, not
    trust in every statement contained in those bytes. SELF_REPORTED is retained
    as SELF_REPORTED, never independently VERIFIED.
    """
    def __init__(self, corpus: SourceCorpus, i4_semantic_bytes: bytes,
                 i4_contexts: dict[str, dict[str, str]], *,
                 publisher: Callable[[bytes], Any] | None = None,
                 registry: IdentityRegistry | None = None):
        if sha256_bytes(i4_semantic_bytes) != I4_FINGERPRINT:
            raise ProvenanceError("frozen I4 semantic graph differs")
        graph = strict_json_loads(i4_semantic_bytes)
        self._i4_ids = frozenset(row["identity"] for row in graph["nodes"])
        self._i4_nodes={row["identity"]:row for row in graph["nodes"]}
        self._i4_contexts = deepcopy(i4_contexts)
        if set(self._i4_contexts) - self._i4_ids:
            raise ProvenanceError("I4 context references absent node")
        for entity, context in self._i4_contexts.items():
            binding=context.get("source_binding")
            if not binding:
                raise ProvenanceError("I4 context lacks exact source binding")
            corpus.binding(binding)
            node=pointer(strict_json_loads(corpus.read(binding["corpus_path"])),binding.get("pointer",""))
            observed=node.get("record",{})
            subject=node.get("derivation",{}).get("subject",{})
            if observed.get("identity",{}).get("entity_id") != entity:
                raise ProvenanceError("I4 context entity differs from bound source")
            if sha256_bytes(canonical_json(subject))!=self._i4_nodes[entity]["represented_fact_sha256"]:
                raise ProvenanceError("context record does not match frozen I4 represented fact")
            supporting=context.get("supporting_source_binding")
            if not supporting or supporting["sha256"] not in self._i4_nodes[entity]["source_evidence_hashes"]:
                raise ProvenanceError("context source is not bound by frozen I4 node")
            corpus.binding(supporting)
            if {x["sha256"] for x in node.get("source_bindings",[])}!=set(self._i4_nodes[entity]["source_evidence_hashes"]):
                raise ProvenanceError("I4 node sources differ")
            for b in subject.get("bindings",[]):
                corpus.binding(b)
                source_raw=corpus.read(b["corpus_path"])
                actual=sha256_bytes(source_raw) if b.get("byte_digest") else pointer(strict_json_loads(source_raw),b["pointer"])
                if actual!=b["value"]:
                    raise ProvenanceError("represented historical context fact differs")
            for field in ("session_id","run_id"):
                if observed.get(field) != context.get(field) or subject.get("historical_scope",{}).get(field)!=context.get(field):
                    raise ProvenanceError("I4 context differs from exact historical source")
        self._i4_bytes = i4_semantic_bytes
        self.corpus = corpus
        self.registry = registry or IdentityRegistry()
        self.schemas = self.registry.schemas
        self.core_schema = self.schemas.find_document("OP1_ACTOR_MODEL_TOOL_PROVENANCE_SCHEMA.json")
        if self.core_schema.sha256 != PROVENANCE_SCHEMA_HASH:
            raise ProvenanceError("frozen provenance schema differs")
        self.publisher = publisher
        self._records: list[bytes] = []
        self._by_id: dict[str, dict] = {}
        self._keys: set[tuple[str, str]] = set()
        self._assignment: dict[str, str] = {}
        self._assignees: dict[str, str] = {}
        self._assignment_history: dict[str, set[str]] = {}
        self._source_cache = {}
        self._parsed_cache = {}
        self._superseded_tasks: set[str] = set()
        self._lock = RLock()
        self._quarantined = False

    @property
    def records(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self._records)

    @property
    def i4_fingerprint(self) -> str:
        return sha256_bytes(self._i4_bytes)

    def lookup(self, entity_id: str, kind: str | None = None) -> dict:
        validate_id(entity_id, kind)
        if entity_id not in self._by_id:
            try:
                existing = self.registry.lookup(entity_id, kind)
            except ValueError as exc:
                raise ProvenanceError("missing prior committed identity") from exc
            value = strict_json_loads(existing.record_bytes)
            if existing.entity_type in DESCRIPTOR_FIELDS:
                raise ProvenanceError("registered identity requires explicit digest-bound descriptor enrollment")
            return {"record": value if "identity" in value else {"identity":value},
                    "metadata":{},"descriptor":{}}
        row = deepcopy(self._by_id[entity_id])
        if kind and row["record"]["identity"]["entity_type"] != kind:
            raise ProvenanceError("wrong committed identity type")
        return row

    def _source(self, binding: dict) -> bytes:
        name=binding["corpus_path"]
        if name not in self._source_cache:
            self._source_cache[name]=self.corpus.read(name)
        raw=self._source_cache[name]
        rows=self.corpus._files
        if rows[name].get("evidence_level") not in LEVELS:
            raise ProvenanceError("source lacks fixed evidence level")
        if sha256_bytes(raw) != binding["sha256"] or ("byte_length" in binding and len(raw)!=binding["byte_length"]):
            raise ProvenanceError("forged exact source binding")
        return raw

    def _source_value(self,binding):
        name=binding["corpus_path"]
        self._source(binding)
        if name not in self._parsed_cache:
            self._parsed_cache[name]=strict_json_loads(self._source_cache[name])
        return pointer(self._parsed_cache[name],binding.get("pointer",""))

    def _validate_sources(self, candidate: dict) -> tuple[dict, bytes | None]:
        fields = {"record", "metadata", "descriptor", "companion_id",
                  "record_binding", "support", "content_binding"}
        if set(candidate) != fields:
            raise ProvenanceError("unexpected or missing provenance bundle field")
        base = {k: candidate[k] for k in ("record", "metadata", "descriptor", "companion_id")}
        binding = candidate["record_binding"]
        source = self._source(binding)
        if self._source_value(binding) != base:
            raise ProvenanceError("authored record differs from exact committed source")
        metadata = candidate["metadata"]
        if set(metadata) - META_FIELDS or not isinstance(metadata.get("semantic_key"), str) or not metadata["semantic_key"]:
            raise ProvenanceError("invalid companion metadata")
        if metadata.get("evidence_level") not in LEVELS:
            raise ProvenanceError("unknown confidence level")
        if not isinstance(metadata.get("claims"), list):
            raise ProvenanceError("explicit semantic claim inventory required")
        support = candidate["support"]
        if not isinstance(support, list) or not support:
            raise ProvenanceError("unsupported provenance")
        supported = set()
        for claim in support:
            if set(claim) != {"target_pointer", "source_binding"}:
                raise ProvenanceError("invalid assertion support")
            sb = claim["source_binding"]
            raw = self._source(sb)
            target = claim["target_pointer"]
            if target in supported:
                raise ProvenanceError("duplicate semantic claim binding")
            if pointer(base, target) != self._source_value(sb):
                raise ProvenanceError("semantic assertion absent from source")
            source_level = self.corpus._files[sb["corpus_path"]]["evidence_level"]
            if metadata["evidence_level"] != "SELF_REPORTED" and source_level == "SELF_REPORTED":
                raise ProvenanceError("self-report cannot establish independent provenance")
            if metadata["evidence_level"] == "EXECUTION_RECEIPT" and source_level != "EXECUTION_RECEIPT":
                raise ProvenanceError("execution attribution lacks execution receipt")
            if source_level == "SYNTHETIC" and metadata["evidence_level"] != "SYNTHETIC":
                raise ProvenanceError("synthetic evidence cannot establish real provenance")
            if metadata["evidence_level"] in {"OWNER_DECLARED","CONFIGURED_IDENTITY","HISTORICAL_ARTIFACT"} and source_level != metadata["evidence_level"]:
                raise ProvenanceError("source confidence classification does not support requested attribution")
            supported.add(target)
        if set(metadata["claims"]) != supported:
            raise ProvenanceError("incomplete or undeclared semantic support")
        descriptor = candidate["descriptor"]
        kind = candidate["record"]["identity"]["entity_type"]
        required_claims = {"/descriptor/"+key for key, value in descriptor.items() if value != "UNKNOWN"}
        required_claims |= {"/record/"+key for key in candidate["record"] if key != "identity"}
        required_claims |= {"/metadata/"+key for key in metadata if key not in
                           {"semantic_key","claims","evidence_level","exact_attribution","declared_timestamp"}}
        if not required_claims <= supported:
            raise ProvenanceError("meaningful attribution missing explicit support")
        def referenced(value):
            if isinstance(value,dict):
                if "corpus_path" in value and "sha256" in value:
                    self._source(value)
                    if "pointer" in value:self._source_value(value)
                for item in value.values():referenced(item)
            elif isinstance(value,list):
                for item in value:referenced(item)
        referenced(metadata)
        content = self._source(candidate["content_binding"]) if candidate["content_binding"] else None
        return base, content

    def _actor(self, entity_id: str, model_id: str | None = None, kind: str | None = None) -> dict:
        actor = self.lookup(entity_id, "ACTOR")["descriptor"]
        if kind and actor["actor_kind"] != kind:
            raise ProvenanceError("human/model actor type confusion")
        if actor["actor_kind"] == "HUMAN":
            if model_id is not None:
                raise ProvenanceError("HUMAN forbids MODEL-only fields")
        else:
            if model_id != actor.get("model_id"):
                raise ProvenanceError("MODEL requires its exact registered MODEL_ID")
            self.lookup(model_id, "MODEL")
        return actor

    def _context(self, metadata: dict, task: dict | None = None, identity: dict | None = None) -> None:
        for field, kind in (("session_id", "SESSION"), ("run_id", "RUN")):
            if field in metadata:
                validate_id(metadata[field], kind)
        if ("session_id" in metadata) != ("run_id" in metadata):
            raise ProvenanceError("Session/RUN requires exact paired context")
        if task:
            for field in ("session_id", "run_id"):
                if metadata.get(field) != task["metadata"].get(field):
                    raise ProvenanceError("cross-Session or cross-RUN task binding")
        if identity:
            for field in ("session_id","run_id"):
                if field in identity and field in metadata and identity[field]!=metadata[field]:
                    raise ProvenanceError("envelope contradicts provenance context")
        if "i4_entity_id" in metadata:
            entity=metadata["i4_entity_id"]
            if entity not in self._i4_ids or entity not in self._i4_contexts:
                raise ProvenanceError("unresolved I4 binding")
            for field in ("session_id","run_id"):
                if metadata.get(field)!=self._i4_contexts[entity].get(field):
                    raise ProvenanceError("wrong Session/RUN I4 provenance binding")
        if "run_id" in metadata:
            pair=(metadata["session_id"],metadata["run_id"])
            if any((x["session_id"],x["run_id"])==pair for x in self._i4_contexts.values()):
                return
            run=self.lookup(metadata["run_id"],"RUN")["record"]["identity"]
            session=self.lookup(metadata["session_id"],"SESSION")["record"]["identity"]
            if run.get("session_id")!=metadata["session_id"]:
                raise ProvenanceError("unregistered or cross-Session RUN")
            for field in ("project_id","product_id","lineage_id","version_id"):
                if run.get(field)!=session.get(field):
                    raise ProvenanceError("context hierarchy mismatch")

    def _exact_capability(self, model_or_tool):
        row=self.lookup(model_or_tool)
        d,m=row["descriptor"],row["metadata"]
        if d.get("version","UNKNOWN")=="UNKNOWN" or d.get("observed_identity","UNKNOWN")=="UNKNOWN" and row["record"]["identity"]["entity_type"]=="MODEL":
            return False
        return m.get("exact_attribution") is True and m["evidence_level"]=="EXECUTION_RECEIPT"

    def _validate_semantics(self, base: dict, content: bytes | None) -> None:
        r, m, d = base["record"], base["metadata"], base["descriptor"]
        identity = r["identity"]
        kind, entity = identity["entity_type"], identity["entity_id"]
        validate_id(entity, kind)
        validate_id(base["companion_id"], "ARTIFACT")
        if entity in self._by_id or base["companion_id"] in self._by_id or entity == base["companion_id"]:
            raise ProvenanceError("immutable identity collision", "REJECT_COLLISION")
        if (kind, m["semantic_key"]) in self._keys:
            raise ProvenanceError("semantic identity collision", "REJECT_COLLISION")
        if m.get("status", r.get("status", identity["status"])) not in STATUSES:
            raise ProvenanceError("unrecognized provenance status")
        if "status" in m and "status" in r and m["status"]!=r["status"]:
            raise ProvenanceError("companion status contradicts frozen core")
        self._context(m, identity=identity)
        if identity.get("caused_by_ids"):
            raise ProvenanceError("I5 attribution cannot introduce I4 causal edges")
        if m.get("decided_by_actor_id"):
            self._actor(m["decided_by_actor_id"],None,"HUMAN")
        if m.get("drafted_by_actor_id"):
            self.lookup(m["drafted_by_actor_id"],"ACTOR")
        if kind in DESCRIPTOR_FIELDS:
            expected = DESCRIPTOR_FIELDS[kind] | ({"model_id"} if kind == "ACTOR" and d.get("actor_kind") == "MODEL" else set())
            if not isinstance(d, dict) or set(d) != expected:
                raise ProvenanceError("identity descriptor fields invalid")
            if any(not isinstance(v,str) or not v for v in d.values()):
                raise ProvenanceError("descriptor requires explicit nonempty strings or UNKNOWN")
            if sha256_bytes(canonical_json(d)) != identity.get("content_sha256"):
                raise ProvenanceError("descriptor content digest differs")
            if content is not None:
                raise ProvenanceError("registration descriptor uses its exact canonical payload")
            if kind == "ACTOR":
                if d["actor_kind"] not in {"HUMAN", "MODEL"}:
                    raise ProvenanceError("actor/person class invalid")
                if d["actor_kind"] == "HUMAN":
                    if "model_id" in d:
                        raise ProvenanceError("HUMAN has MODEL-only field")
                else:
                    self.lookup(d["model_id"], "MODEL")
            else:
                for field in ("version", "runtime_config_sha256"):
                    if not isinstance(d[field], str) or not d[field]:
                        raise ProvenanceError("missing version/config state")
                if d["runtime_config_sha256"] != "UNKNOWN":
                    from .identity import validate_sha256
                    validate_sha256(d["runtime_config_sha256"])
                if d["runtime_config_sha256"] != "UNKNOWN":
                    config=m.get("config_binding")
                    if not config or sha256_bytes(self._source(config)) != d["runtime_config_sha256"]:
                        raise ProvenanceError("configuration digest lacks exact configuration bytes")
                if m.get("exact_attribution") and (d["version"] == "UNKNOWN" or (kind == "MODEL" and d["observed_identity"] == "UNKNOWN")):
                    raise ProvenanceError("UNKNOWN version/backend blocks exact attribution")
            if m.get("exact_attribution") and m["evidence_level"]!="EXECUTION_RECEIPT":
                raise ProvenanceError("declared identity is not independent backend attestation")
            return
        if d:
            raise ProvenanceError("only ACTOR/MODEL/TOOL have registration descriptor")
        if kind not in CORE_TYPES | {"OPERATION", "DECISION", "EVIDENCE", "ARTIFACT", "PROJECT", "PRODUCT", "LINEAGE", "VERSION", "FREEZE", "SESSION", "RUN", "FINDING", "ERROR"}:
            raise ProvenanceError("unsupported I5 record type; no authority/dataset APIs")
        if m.get("exact_attribution"):
            actor_refs={identity["actor_id"]} | {value for key,value in r.items() if key.endswith("actor_id")} | {m[key] for key in ("assignee_actor_id","requester_actor_id","drafted_by_actor_id","decided_by_actor_id") if m.get(key)}
            for ref in actor_refs:
                actor=self.lookup(ref,"ACTOR")["descriptor"]
                if actor["actor_kind"]=="MODEL" and not self._exact_capability(actor["model_id"]):
                    raise ProvenanceError("record exact attribution exceeds actor model evidence")
            for key in ("model_id","reviewer_model_id","tool_id"):
                if key in r and not self._exact_capability(r[key]):
                    raise ProvenanceError("record exact attribution exceeds registered identity evidence")
        if kind in CORE_TYPES:
            if identity["schema_id"] != self.core_schema.schema_id or identity["schema_version"] != self.core_schema.version:
                raise ProvenanceError("wrong frozen provenance schema binding")
            validation = self.schemas.validate(self.core_schema.schema_id, self.core_schema.version, r)
            if not validation.valid:
                raise ProvenanceError("frozen provenance core rejected")
            if r.get(kind.lower()+"_id") != entity:
                raise ProvenanceError("leading ID differs from frozen envelope")
        if kind in {"PROJECT","PRODUCT","LINEAGE","VERSION","FREEZE","SESSION","RUN"}:
            if m.get("role") != "CONTEXT_ID_ONLY":
                raise ProvenanceError("context identity registration grants no state or authority")
        elif kind in {"ARTIFACT","EVIDENCE","FINDING","ERROR"}:
            if kind == "ARTIFACT" and m.get("role")=="TASK_ASSIGNMENT_REVISION":
                task=self.lookup(m["task_id"],"TASK")
                self._context(m,task)
                self.lookup(m["assignee_actor_id"],"ACTOR")
                if m["task_id"] in self._superseded_tasks or m["expected_assignment_id"]!=self._assignment[m["task_id"]] or m["assignment_id"] in self._assignment_history[m["task_id"]]:
                    raise ProvenanceError("stale/colliding or reused assignment revision")
                if identity["actor_id"]!=task["record"]["actor_id"]:
                    raise ProvenanceError("unpermitted task reassignment")
            else:
                if kind != "EVIDENCE" and m.get("role") not in {"SOURCE_ENROLLMENT","FROZEN_CONTEXT_REFERENCE"}:
                    raise ProvenanceError("bounded generic source enrollment required")
                if content is None or not m.get("source_refs"):
                    raise ProvenanceError("generic source requires exact digest-bound bytes")
                if identity.get("content_sha256")!=sha256_bytes(content):
                    raise ProvenanceError("generic source bytes differ")
                if kind in {"FINDING","ERROR"} and set(r)=={"identity"}:
                    raise ProvenanceError("finding/error requires frozen content-specific schema")
        elif kind == "OPERATION":
            self._actor(identity["actor_id"], self.lookup(identity["actor_id"], "ACTOR")["descriptor"].get("model_id"))
        elif kind == "TASK":
            self._actor(r["actor_id"], self.lookup(r["actor_id"], "ACTOR")["descriptor"].get("model_id"))
            operation = self.lookup(r["operation_id"], "OPERATION")
            self._context(m, operation)
            for field in ("requester_actor_id", "assignee_actor_id"):
                self.lookup(m[field], "ACTOR")
            if not isinstance(m["objective"],str) or not m["objective"] or not isinstance(m["phase"],str) or not m["phase"]:
                raise ProvenanceError("task objective/phase invalid")
            for field in ("input_refs", "output_refs"):
                if not isinstance(m[field], list):
                    raise ProvenanceError("task references required")
            if m.get("parent_task_id"):
                self._context(m,self.lookup(m["parent_task_id"], "TASK"))
            if m.get("supersedes_task_id"):
                if m["supersedes_task_id"] in self._superseded_tasks:
                    raise ProvenanceError("task predecessor already superseded")
                previous = self.lookup(m["supersedes_task_id"], "TASK")
                self._context(m, previous)
            if not isinstance(m.get("assignment_id"), str) or not m["assignment_id"]:
                raise ProvenanceError("explicit assignment token required")
            if r["status"]=="NO_OUTPUT":
                proof=m.get("output_absence_binding")
                if not proof or m["output_refs"]:
                    raise ProvenanceError("task NO_OUTPUT requires positive absence proof")
                level=self.corpus._files[proof["corpus_path"]]["evidence_level"]
                if level not in {"EXECUTION_RECEIPT","SYNTHETIC"} or level=="SYNTHETIC" and m["evidence_level"]!="SYNTHETIC":
                    raise ProvenanceError("task absence proof evidence level invalid")
                if self._source_value(proof)!={"output_state":"NO_OUTPUT","contract":"NO_OUTPUT_PROVEN","task_id":entity,"assignment_id":m["assignment_id"]}:
                    raise ProvenanceError("task UNKNOWN cannot become NO_OUTPUT")
        elif kind == "DELEGATION":
            task = self.lookup(r["task_id"], "TASK")
            self._context(m, task)
            self.lookup(r["delegator_actor_id"], "ACTOR")
            if r["task_id"] in self._superseded_tasks or r["delegator_actor_id"]!=task["record"]["actor_id"]:
                raise ProvenanceError("unpermitted delegator or superseded task")
            if not r["scope"] or not set(r["scope"])<=set(task["metadata"].get("scope",[])):
                raise ProvenanceError("delegation exceeds explicit task scope")
            self._actor(r["delegate_actor_id"], r["model_id"], "MODEL")
            if r["delegate_actor_id"] != self._assignees[r["task_id"]]:
                raise ProvenanceError("fake delegation/assignee mismatch")
            if m.get("assignment_id") != self._assignment[r["task_id"]]:
                raise ProvenanceError("delegation stale assignment")
            if not isinstance(m["constraints"], list) or not m["constraints"]:
                raise ProvenanceError("bounded delegation constraints required")
        elif kind in {"REPORT", "TOOL_INVOCATION"}:
            task_id = r.get("task_id", m.get("task_id"))
            task = self.lookup(task_id, "TASK")
            self._context(m, task)
            if task_id in self._superseded_tasks or m.get("assignment_id") != self._assignment[task_id]:
                raise ProvenanceError("stale report/invocation after task supersession")
            actor = self.lookup(r["actor_id"], "ACTOR")["descriptor"]
            model_id = r.get("model_id", actor.get("model_id"))
            self._actor(r["actor_id"], model_id, r.get("producer_kind"))
            if r["actor_id"] != self._assignees[task_id]:
                raise ProvenanceError("output from unassigned actor")
            if m.get("delegation_id"):
                delegated = self.lookup(m["delegation_id"], "DELEGATION")
                delegation = delegated["record"]
                if delegation["task_id"] != task_id or delegation["delegate_actor_id"] != r["actor_id"] or delegated["metadata"]["assignment_id"] != m["assignment_id"]:
                    raise ProvenanceError("output delegation mismatch")
            if m.get("exact_attribution") and actor["actor_kind"]=="MODEL" and not self._exact_capability(model_id):
                raise ProvenanceError("output exact attribution exceeds registered model evidence")
            if kind == "REPORT":
                if content is None or sha256_bytes(content) != r["content_sha256"] or identity.get("content_sha256") != r["content_sha256"]:
                    raise ProvenanceError("raw report must exist before parse/admission")
                if r["status"] not in {"COMMITTED", "UNKNOWN"}:
                    raise ProvenanceError("report acceptance must derive from separate REVIEW")
            else:
                tool=self.lookup(r["tool_id"], "TOOL")
                if m.get("exact_attribution") and not self._exact_capability(r["tool_id"]):
                    raise ProvenanceError("exact tool attribution exceeds registered evidence")
                self.lookup(r["operation_id"], "OPERATION")
                if r["operation_id"] != task["record"]["operation_id"]:
                    raise ProvenanceError("tool operation differs from calling task")
                if not m.get("input_refs") or not m.get("side_effect_class") or not isinstance(m.get("order"), int):
                    raise ProvenanceError("invocation input/order/side-effect evidence missing")
                refs = [self._source(b) for b in m["input_refs"]]
                if not any(sha256_bytes(raw) == r["input_sha256"] for raw in refs):
                    raise ProvenanceError("invocation exact input missing")
                execution=m.get("execution_binding")
                if execution:
                    receipt=self._source_value(execution)
                    if self.corpus._files[execution["corpus_path"]]["evidence_level"]!="EXECUTION_RECEIPT":
                        raise ProvenanceError("tool execution requires independent receipt")
                    if receipt.get("tool_name")!=tool["descriptor"]["name"] or receipt.get("input_sha256")!=r["input_sha256"] or receipt.get("output_state")!=r["output_state"] or receipt.get("output_sha256")!=r.get("output_sha256") or receipt.get("status")!=r["status"]:
                        raise ProvenanceError("invocation contradicts bound execution receipt")
                    if not receipt.get("source_call_id"):
                        raise ProvenanceError("receipt lacks exact call binding")
                    if actor["actor_kind"]=="MODEL":
                        if receipt.get("calling_model_designation")!=self.lookup(model_id,"MODEL")["descriptor"]["designation"]:
                            raise ProvenanceError("receipt calling model differs")
                    elif receipt.get("calling_actor_kind")!="HUMAN" or receipt.get("calling_model_designation") not in {None,"UNKNOWN"}:
                        raise ProvenanceError("human tool receipt cannot claim model caller")
                    if receipt.get("tool_config_sha256","UNKNOWN")!=tool["descriptor"]["runtime_config_sha256"]:
                        raise ProvenanceError("tool receipt configuration differs")
                    for prior in self._records:
                        prior=strict_json_loads(prior)
                        eb=prior["metadata"].get("execution_binding")
                        if eb and self._source_value(eb).get("source_call_id")==receipt["source_call_id"]:
                            raise ProvenanceError("execution receipt already attributed to another invocation")
                elif m["evidence_level"]=="EXECUTION_RECEIPT":
                    raise ProvenanceError("claimed execution lacks bound invocation receipt")
                state = r["output_state"]
                if r["status"]=="NO_OUTPUT" and state!="NO_OUTPUT":
                    raise ProvenanceError("NO_OUTPUT status contradicts ambiguous or present output")
                if state == "PRESENT":
                    if content is None or sha256_bytes(content) != r["output_sha256"]:
                        raise ProvenanceError("tool PRESENT requires exact output evidence")
                else:
                    if content is not None:
                        raise ProvenanceError("no output digest for NO_OUTPUT/UNKNOWN")
                    if state == "NO_OUTPUT":
                        proof = m.get("output_absence_binding")
                        if not proof or self.corpus._files[proof["corpus_path"]]["evidence_level"] not in {"EXECUTION_RECEIPT", "SYNTHETIC"}:
                            raise ProvenanceError("NO_OUTPUT requires positive independent proof")
                        absent = self._source_value(proof)
                        if self.corpus._files[proof["corpus_path"]]["evidence_level"]=="SYNTHETIC" and m["evidence_level"]!="SYNTHETIC":
                            raise ProvenanceError("synthetic absence proof cannot establish real NO_OUTPUT")
                        if absent != {"output_state":"NO_OUTPUT","contract":"NO_OUTPUT_PROVEN",
                                      "tool_invocation_id":entity,"tool_id":r["tool_id"],"input_sha256":r["input_sha256"]}:
                            raise ProvenanceError("UNKNOWN cannot become NO_OUTPUT")
        elif kind == "DECISION":
            self.lookup(r["decider_actor_id"], "ACTOR")
            for ref in r["subject_ids"]:
                self.lookup(ref["entity_id"], ref["entity_type"])
            for ref in r["evidence_ids"]:
                evidence=self.lookup(ref,"EVIDENCE")
                self._context(m,evidence) if evidence["metadata"].get("run_id") else None
            for ref in r["resolves_finding_ids"]:
                self.lookup(ref,"FINDING")
            if r["resolves_finding_ids"]:
                raise ProvenanceError("I5 review does not resolve I4 causal findings")
            if m.get("decided_by_actor_id"):
                self._actor(m["decided_by_actor_id"], None, "HUMAN")
                if r["decider_actor_id"] != m["decided_by_actor_id"]:
                    raise ProvenanceError("owner decision attributed to draft producer")
            if m.get("drafted_by_actor_id"):
                self.lookup(m["drafted_by_actor_id"], "ACTOR")
        elif kind == "REVIEW":
            report = self.lookup(r["report_id"], "REPORT")
            self._context(m, report)
            self._actor(r["reviewer_actor_id"], r.get("reviewer_model_id"), r["reviewer_kind"])
            decision_row = self.lookup(r["decision_id"], "DECISION")
            self._context(m,decision_row)
            decision=decision_row["record"]
            if decision["outcome"]!=r["outcome"] or decision["rationale"]!=m["rationale"]:
                raise ProvenanceError("review contradicts bound decision")
            if not any(
                self.lookup(x,"EVIDENCE")["record"]["identity"].get("content_sha256")==report["record"]["content_sha256"]
                and self.lookup(x,"EVIDENCE").get("content_binding")==report["content_binding"]
                and report["content_binding"] in self.lookup(x,"EVIDENCE")["metadata"].get("source_refs",[])
                for x in decision["evidence_ids"]
            ):
                raise ProvenanceError("review lacks exact committed report evidence")
            if m.get("exact_attribution") and (r.get("reviewer_model_id") is None or not self._exact_capability(r["reviewer_model_id"])):
                raise ProvenanceError("review exact attribution exceeds registered evidence")
            if decision["decider_actor_id"] != r["reviewer_actor_id"] or not any(x["entity_id"] == r["report_id"] for x in decision["subject_ids"]):
                raise ProvenanceError("review decision/producer distinction missing")
            if not m["rationale"]:
                raise ProvenanceError("review rationale required")

    def append(self, candidate: dict) -> dict:
        with self._lock:
            if self._quarantined:
                raise ProvenanceError("publication uncertainty; stop and reconstruct from I1")
            self._source_cache={}; self._parsed_cache={}
            candidate = deepcopy(candidate)
            base, raw_content = self._validate_sources(candidate)
            self._validate_semantics(base, raw_content)
            r, m, d = base["record"], base["metadata"], base["descriptor"]
            identity = r["identity"]
            # Stage both registrations against the full unchanged I0 admission rules.
            # Only containers are copied; immutable records and schema validators are shared.
            staged=copy(self.registry)
            for name,value in vars(self.registry).items():
                if isinstance(value,(dict,list,set)):
                    setattr(staged,name,value.copy())
            core=None if set(r)=={"identity"} else r
            payload=canonical_json(d) if d else raw_content
            companion={"entity_id":base["companion_id"],"entity_type":"ARTIFACT",
                       "schema_id":self.registry._identity_schema.schema_id,
                       "schema_version":self.registry._identity_schema.version,
                       "actor_id":identity["actor_id"],"created_at_utc":identity["created_at_utc"],
                       "status":"COMMITTED","content_sha256":sha256_bytes(canonical_json(base))}
            try:
                if identity["entity_id"] in staged._records:
                    # Enroll provenance around an existing I0 identity without
                    # allocating a second identity or rewriting its receipt.
                    exact_record=canonical_json(core if core is not None else identity)
                    staged.retry_lookup(identity["entity_id"],sha256_bytes(exact_record),identity["entity_type"])
                    staged._validate(identity,core,payload)
                else:
                    staged.register(identity,logical_key=m["semantic_key"],record=core,content_bytes=payload)
                staged.register(companion,logical_key="I5 companion "+identity["entity_id"],content_bytes=canonical_json(base))
            except ValueError as exc:
                raise ProvenanceError(str(exc),"REJECT_RECORD") from exc
            committed=canonical_json(candidate)
            if self.publisher:
                try:
                    self.publisher(committed)
                except Exception:
                    self._quarantined=True
                    raise
            # No further admission/allocation can fail after durable publication.
            self.registry.__dict__.update(staged.__dict__)
            self._records.append(committed)
            self._by_id[identity["entity_id"]] = candidate
            self._by_id[base["companion_id"]] = {"record":{"identity":companion},"metadata":{},"descriptor":{}}
            self._keys.add((identity["entity_type"], m["semantic_key"]))
            if identity["entity_type"] == "TASK":
                self._assignment[identity["entity_id"]] = m["assignment_id"]
                self._assignees[identity["entity_id"]] = m["assignee_actor_id"]
                self._assignment_history[identity["entity_id"]]={m["assignment_id"]}
                if m.get("supersedes_task_id"):
                    self._superseded_tasks.add(m["supersedes_task_id"])
            if identity["entity_type"] == "ARTIFACT" and m.get("role")=="TASK_ASSIGNMENT_REVISION":
                self._assignment[m["task_id"]] = m["assignment_id"]
                self._assignees[m["task_id"]] = m["assignee_actor_id"]
                self._assignment_history[m["task_id"]].add(m["assignment_id"])
            return deepcopy(base)

    def report_outcome(self, report_id: str) -> str:
        self.lookup(report_id, "REPORT")
        reviews = [strict_json_loads(raw)["record"] for raw in self.records
                   if strict_json_loads(raw)["record"]["identity"]["entity_type"] == "REVIEW"
                   and strict_json_loads(raw)["record"]["report_id"] == report_id]
        return reviews[-1]["outcome"] if reviews else "UNKNOWN"

    def semantic_view(self) -> dict:
        rows=[]
        for raw in self.records:
            c=strict_json_loads(raw)
            record=deepcopy(c["record"])
            record["identity"].pop("created_at_utc",None)
            record.pop("reviewed_at_utc",None)
            record.pop("decided_at_utc",None)
            metadata=deepcopy(c["metadata"])
            metadata.pop("declared_timestamp",None)
            # Corpus locators are transport; exact source hashes are semantics.
            def semantic(value):
                if isinstance(value,list):return [semantic(x) for x in value]
                if isinstance(value,dict):
                    return {k:semantic(v) for k,v in value.items() if k not in {"corpus_path","original_path"}}
                return value
            rows.append(semantic({"record":record,"metadata":metadata,"descriptor":c["descriptor"],
                                  "support":[{"target_pointer":b["target_pointer"],
                                              "source_pointer":b["source_binding"].get("pointer",""),
                                              "source_sha256":b["source_binding"]["sha256"] if b["source_binding"]["corpus_path"]!=c["record_binding"]["corpus_path"] else "AUTHORED_RECORD_SEMANTICS_ABOVE",
                                              "source_level":self.corpus._files[b["source_binding"]["corpus_path"]]["evidence_level"]} for b in c["support"]],
                                  "content_sha256":c["content_binding"]["sha256"] if c["content_binding"] else None}))
        return {"i4_semantic_graph_fingerprint":self.i4_fingerprint,
                "provenance_records":sorted(rows,key=lambda x:x["record"]["identity"]["entity_id"]),
                "review_precedence":[strict_json_loads(raw)["record"]["review_id"] for raw in self.records if strict_json_loads(raw)["record"]["identity"]["entity_type"]=="REVIEW"],
                "report_outcomes":{x:self.report_outcome(x) for x,r in sorted(self._by_id.items()) if r["record"]["identity"]["entity_type"]=="REPORT"},
                "current_assignments":dict(sorted(self._assignment.items())),
                "causal_edges_added":0,"execution_authority_granted":False}

    @property
    def semantic_fingerprint(self) -> str:
        return sha256_bytes(canonical_json(self.semantic_view()))

    @classmethod
    def rebuild(cls, corpus, i4_bytes, i4_contexts, records, **kwargs):
        publisher=kwargs.pop("publisher",None)
        ledger=cls(corpus,i4_bytes,i4_contexts,**kwargs)
        for raw in records:ledger.append(strict_json_loads(raw))
        ledger.publisher=publisher
        return ledger

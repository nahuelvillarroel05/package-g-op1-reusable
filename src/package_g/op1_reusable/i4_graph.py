"""Offline append-only causal graph over immutable source bytes; no runtime execution."""
from __future__ import annotations
from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any, Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import canonical_json, sha256_bytes, strict_json_loads, validate_id
from .schema_registry import SchemaRegistry

HASHES = {"OP1_CAUSAL_GRAPH_CONTRACT.json":"212347222febaf09471ac827176dfb97d0f9b6d271b7e3195ffb19a8ec2ad892",
          "OP1_CAUSAL_GRAPH_IMPLEMENTATION.json":"92250ad91000b7242ea863acbd44451e11c7beda367ef8f1d06940d47507fda9"}
CONTRACTS = {}
for name, digest in HASHES.items():
    raw = resources.files(__package__).joinpath("frozen_i4", name).read_bytes()
    if sha256_bytes(raw) != digest:
        raise RuntimeError("frozen I4 contract hash mismatch")
    CONTRACTS[name] = strict_json_loads(raw)
EDGES = frozenset(CONTRACTS["OP1_CAUSAL_GRAPH_IMPLEMENTATION.json"]["edge_types"])
CAUSAL = frozenset(CONTRACTS["OP1_CAUSAL_GRAPH_CONTRACT.json"]["edge_semantics"]["causal_back_edges"])
TYPES = {"event_id":"EVENT", "produced_artifact_ids":"ARTIFACT", "produced_finding_ids":"FINDING",
         "resolved_finding_ids":"FINDING", "triggered_decision_ids":"DECISION", "evidence_ids":"EVIDENCE"}
RUN_MACHINE = strict_json_loads(resources.files(__package__).joinpath("frozen_i2","OP1_RUN_STATE_MACHINE.json").read_bytes())
TERMINAL_OUTCOMES=frozenset(RUN_MACHINE["terminal_states"])
SCHEMAS = {kind:f"OP1_{kind}_SCHEMA.json" for kind in ("EVENT","EVIDENCE","FINDING","ERROR","DECISION")}

class GraphError(ValueError):
    def __init__(self, reason, outcome="REJECT_GRAPH"):
        super().__init__(reason)
        self.outcome = outcome

def pointer(value, path):
    if path == "":
        return value
    if not isinstance(path,str) or not path.startswith("/"):
        raise GraphError("invalid source pointer")
    try:
        for part in path[1:].split("/"):
            key=part.replace("~1","/").replace("~0","~")
            value=value[int(key)] if isinstance(value,list) else value[key]
        return value
    except (KeyError,IndexError,TypeError,ValueError) as exc:
        raise GraphError("unresolved source pointer") from exc

class SourceCorpus:
    def __init__(self, root:Path, manifest:Mapping[str,Any], digest:str, *, manifest_bytes:bytes|None=None):
        self.root=Path(root).resolve()
        self._manifest=deepcopy(dict(manifest))
        if manifest_bytes is not None and strict_json_loads(manifest_bytes)!=self._manifest:
            raise GraphError("manifest object differs from exact frozen bytes")
        self.manifest_sha256=digest
        if sha256_bytes(manifest_bytes if manifest_bytes is not None else canonical_json(self._manifest)) != digest:
            raise GraphError("corpus manifest commitment differs")
        self._files={}
        seen=set()
        for row in self._manifest["files"]:
            name=row["corpus_path"]
            if name.casefold() in seen:
                raise GraphError("duplicate corpus member")
            seen.add(name.casefold())
            self._files[name]=deepcopy(row)
            self.read(name)
    @property
    def manifest(self):return deepcopy(self._manifest)
    @property
    def files(self):return deepcopy(self._files)
    @classmethod
    def from_path(cls,root:Path,digest:str):
        raw=(Path(root)/"SOURCE_CORPUS_MANIFEST.json").read_bytes()
        return cls(root,strict_json_loads(raw),digest,manifest_bytes=raw)
    def read(self,name):
        if name not in self._files:
            raise GraphError("source not admitted")
        path=self.root/name
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise GraphError("source path escape")
        raw=path.read_bytes()
        row=self._files[name]
        if len(raw)!=row["byte_length"] or sha256_bytes(raw)!=row["sha256"]:
            raise GraphError("source byte mutation")
        return raw
    def binding(self,b):
        raw=self.read(b["corpus_path"])
        if sha256_bytes(raw)!=b["sha256"]:
            raise GraphError("forged source digest")
        for key,kind in (("evidence_ids","EVIDENCE"),("event_ids","EVENT")):
            for entity in b.get(key,[]):
                validate_id(entity,kind)
                if entity.encode() not in raw:
                    raise GraphError("source ID absent from exact bytes")
        if "pointer" in b:
            pointer(strict_json_loads(raw),b["pointer"])
    def raw_binding(self,b):
        if "corpus_path" in b:
            self.binding(b)
            row=self._files[b["corpus_path"]]
        else:
            if self._manifest.get("accepted_source",{}).get("all_part_membership_rehash_crc")!="PASS":
                raise GraphError("external RAW lacks accepted byte-verification binding")
            matches=[r for r in self._manifest.get("omitted_large_bindings",[]) if r["original_package_member"]==b.get("original_package_member")]
            commitments={(r["sha256"],r["byte_length"]) for r in matches}
            if not matches or commitments!={(b["sha256"],b["byte_length"])}:
                raise GraphError("external RAW binding absent/ambiguous")
            row=matches[0] # Repeated identical inventory aliases are one commitment.
        if row["sha256"]!=b["sha256"] or row["byte_length"]!=b["byte_length"]:
            raise GraphError("RAW source commitment differs")

def require_dag(nodes,edges):
    # Kahn's algorithm covers long histories without Python recursion limits.
    adjacent={entity:set() for entity in nodes}
    degree={entity:0 for entity in nodes}
    for edge in edges:
        if edge["edge_type"] in CAUSAL or edge["edge_type"]=="supersedes_id":
            source,target=edge["source_id"],edge["target_id"]
            if source not in nodes or target not in nodes:raise GraphError("dangling causal reference")
            if target not in adjacent[source]:
                adjacent[source].add(target)
                degree[target]+=1
    ready=[entity for entity in nodes if degree[entity]==0]
    count=0
    while ready:
        entity=ready.pop()
        count+=1
        for parent in adjacent[entity]:
            degree[parent]-=1
            if degree[parent]==0:ready.append(parent)
    if count!=len(nodes):raise GraphError("causal cycle")

class CausalGraph:
    """Only new records; durable sink executes before graph state advances."""
    def __init__(self,corpus:SourceCorpus,*,sink=None,trusted_checkpoint_public_key=None,closure_policies=None,causal_rules=None,source_index=None):
        self.corpus=corpus
        self.sink=sink
        self.trusted_checkpoint_public_key=trusted_checkpoint_public_key
        self._closure_policies=deepcopy(dict(closure_policies or {}))
        self._causal_rules=deepcopy(dict(causal_rules or {}))
        self.source_index=source_index
        if source_index is not None:
            from .i4_source import SourceIndex
            if not isinstance(source_index,SourceIndex) or source_index.corpus is not corpus:
                raise GraphError("closure source registry must be the verified bound source index")
        self.schemas=SchemaRegistry()
        self._records=[]
        self._nodes={}
        self._edges=[]
        self._closures=[]
    @property
    def closure_policies(self):return deepcopy(self._closure_policies)
    @property
    def causal_rules(self):return deepcopy(self._causal_rules)
    @property
    def records(self): return tuple(self._records)
    @property
    def nodes(self): return deepcopy(self._nodes)
    @property
    def edges(self): return deepcopy(self._semantic_edges())
    def root(self): return sha256_bytes(canonical_json([sha256_bytes(r) for r in self._records]))
    @staticmethod
    def envelope(node): return node["record"].get("identity",node["record"])
    def resolve(self,entity,kind=None):
        try: validate_id(entity,kind)
        except ValueError as exc: raise GraphError("malformed or wrong typed ID") from exc
        if entity not in self._nodes: raise GraphError("nonexistent/forged/future parent")
        node=self._nodes[entity]
        if kind and self.envelope(node)["entity_type"]!=kind: raise GraphError("wrong entity type")
        return node
    def sources(self,value):
        if not value.get("source_bindings"): raise GraphError("missing source closure")
        for b in value["source_bindings"]: self.corpus.binding(b)
    @staticmethod
    def references(node):
        """Exact schema fields, without renaming subject/resolution annotations."""
        record=node["record"];env=CausalGraph.envelope(node)
        refs=[]
        for field in EDGES:
            if field=="event_id" and env["entity_type"]=="EVENT":continue # EVENT.event_id is its own identity, not a causal reference.
            values=record.get(field,[])
            if field in {"parent_ids","caused_by_ids"}:
                values=values+env.get(field,[])
            if field=="supersedes_id" and field in env:values=env[field]
            if isinstance(values,(str,dict)):values=[values]
            for ref in values:
                refs.append((field,ref.get("entity_id") if isinstance(ref,dict) else ref))
        return sorted(set(refs))
    def _semantic_edges(self):
        combined={}
        for entity,node in self._nodes.items():
            for relation,target in self.references(node):
                key=(relation,entity,target)
                combined[key]={"edge_type":relation,"source_id":entity,"target_id":target,
                               "source_bindings":deepcopy(node["source_bindings"]),"origin":"EXACT_SCHEMA_REFERENCE"}
        for edge in self._edges:
            key=(edge["edge_type"],edge["source_id"],edge["target_id"])
            if key not in combined:combined[key]=deepcopy(edge)
            else:
                known={b["sha256"] for b in combined[key]["source_bindings"]}
                combined[key]["source_bindings"].extend(deepcopy(b) for b in edge["source_bindings"] if b["sha256"] not in known)
        return [combined[k] for k in sorted(combined)]
    def schema_links(self):
        links=[]
        for entity,node in sorted(self._nodes.items()):
            for field in ("subject_ids","resolves_finding_ids","source_evidence_ids"):
                for ref in node["record"].get(field,[]):
                    target=ref["entity_id"] if isinstance(ref,dict) else ref
                    links.append({"field":field,"source_id":entity,"target_id":target,
                                  "source_evidence_hashes":sorted({b["sha256"] for b in node["source_bindings"]})})
        return sorted(links,key=lambda x:(x["field"],x["source_id"],x["target_id"]))
    def node(self,value):
        record=value["record"]
        env=self.envelope(value)
        entity,kind=env["entity_id"],env["entity_type"]
        validate_id(entity,kind)
        if entity in self._nodes: raise GraphError("immutable identity collision")
        if not env.get("actor_id"): raise GraphError("missing actor attribution","REJECT_RECORD")
        validate_id(env["actor_id"],"ACTOR")
        entry=self.schemas.find_document(SCHEMAS.get(kind,"OP1_IDENTITY_ENVELOPE_SCHEMA.json"))
        checked=record if kind in SCHEMAS else env
        result=self.schemas.validate(entry.schema_id,entry.version,checked)
        if not result.valid: raise GraphError("frozen schema rejected: "+"; ".join(result.errors),"REJECT_RECORD")
        if kind in SCHEMAS and (env["schema_id"]!=entry.schema_id or env["schema_version"]!=entry.version):
            raise GraphError("schema identity mismatch","REJECT_RECORD")
        if kind in {"EVENT","EVIDENCE"} and any(record.get(k)!=env.get(k) for k in ("run_id",)):
            raise GraphError("record/envelope scope mismatch","REJECT_RECORD")
        if kind=="EVENT" and record["session_id"]!=env["session_id"]:
            raise GraphError("event/envelope session mismatch","REJECT_RECORD")
        if kind in {"EVENT","EVIDENCE"} and record.get("actor_id")!=env["actor_id"]:
            raise GraphError("actor linkage mismatch","REJECT_RECORD")
        if kind=="DECISION" and record["decider_actor_id"]!=env["actor_id"]:
            raise GraphError("decision actor linkage mismatch","REJECT_RECORD")
        self.sources(value)
        # An admitted historical record must match exact source JSON. A derived
        # reification records each observed field separately and retains sources.
        if "record_binding" in value:
            binding=value["record_binding"]
            if not any(b["corpus_path"]==binding["corpus_path"] and b["sha256"]==binding["sha256"] for b in value["source_bindings"]):
                raise GraphError("source record commitment not included in node support")
            self.corpus.binding(binding)
            original=pointer(strict_json_loads(self.corpus.read(binding["corpus_path"])),binding.get("pointer",""))
            if original!=record:raise GraphError("record differs from immutable source")
        elif "derivation" in value:
            observations=value["derivation"].get("observations",[])
            if not observations:raise GraphError("derived interpretation has no observations")
            for observed in observations:
                if observed["corpus_path"] not in {b["corpus_path"] for b in value["source_bindings"]}:
                    raise GraphError("derived observation source unbound")
                actual=pointer(strict_json_loads(self.corpus.read(observed["corpus_path"])),observed["pointer"])
                if actual!=observed["value"]:raise GraphError("derived observation differs from source")
        else:raise GraphError("node requires exact source record or explicit sourced derivation")
        if kind=="EVIDENCE" and "receipt_payload" in value.get("derivation",{}):
            receipt=value["derivation"]["receipt_payload"]
            raw=canonical_json(receipt)
            if (record["derivation_class"]!="DERIVED_IMMUTABLE" or record["evidence_class"]!="I4_SOURCE_INTERPRETATION_RECEIPT" or
                record["sha256"]!=sha256_bytes(raw) or record["byte_length"]!=len(raw) or env.get("content_sha256")!=record["sha256"]):
                raise GraphError("current derived receipt payload/class differs")
            if receipt.get("original_source_bindings")!=value["source_bindings"] or receipt.get("current_observation_event_id")!=record["event_id"]:
                raise GraphError("derived receipt does not preserve exact original source attribution")
        for field in ("parent_ids","caused_by_ids"):
            for ref in record.get(field,[])+env.get(field,[]):
                parent=self.resolve(ref["entity_id"],ref["entity_type"])
                self.boundary({"repair_decision_id":value.get("repair_decision_id")},value,parent)
        if kind=="EVENT":
            for field,target in TYPES.items():
                if field!="event_id":
                    for ref in record.get(field,[]): self.resolve(ref,target)
        if kind in {"EVIDENCE","ERROR"}:
            cause=self.resolve(record["event_id"],"EVENT")
            self.boundary({"repair_decision_id":value.get("repair_decision_id")},value,cause)
        if kind in {"ERROR","FINDING","DECISION"}:
            for ref in record["evidence_ids"]: self.resolve(ref,"EVIDENCE")
        if kind in {"FINDING","DECISION"}:
            for ref in record["subject_ids"]: self.resolve(ref["entity_id"],ref["entity_type"])
        if kind=="EVIDENCE":
            for ref in record.get("source_evidence_ids",[]):self.resolve(ref,"EVIDENCE")
        if kind=="DECISION":
            for ref in record["resolves_finding_ids"]: self.resolve(ref,"FINDING")
            if "repair_permission" in value:
                bound=value.get("repair_permission_binding")
                if not bound:raise GraphError("repair permission requires exact source binding")
                self.corpus.binding(bound)
                permitted=pointer(strict_json_loads(self.corpus.read(bound["corpus_path"])),bound.get("pointer",""))
                if permitted!=value["repair_permission"]:raise GraphError("repair boundary differs from source decision")
        if "supersedes_id" in env:
            ref=env["supersedes_id"]
            previous=self.resolve(ref["entity_id"],ref["entity_type"])
            if kind!=ref["entity_type"] or kind not in {"ARTIFACT","FINDING","ERROR","DECISION","REPORT","REVIEW"}:
                raise GraphError("frozen I0 supersession type restriction")
            from .identity import HIERARCHY_TYPES
            if any(env.get(k)!=self.envelope(previous).get(k) for k in HIERARCHY_TYPES):
                raise GraphError("supersession cannot cross frozen identity scope")
        if "derivation" in value:
            for relation,target_id in self.references(value):
                if relation in CAUSAL:
                    target=self.resolve(target_id)
                    support=value["derivation"].get("causal_basis",{}).get(relation+":"+target_id)
                    if not support:raise GraphError("derived causal reference requires explicit source support")
                    self.validate_basis({**value,"edge_type":relation,"target_id":target_id,"basis":support},value,target)
        nodes={**self._nodes,entity:value}
        intrinsic=[{"edge_type":r,"source_id":entity,"target_id":t} for r,t in self.references(value)]
        require_dag(nodes,self._semantic_edges()+intrinsic)
    def boundary(self,value,source,target):
        left,right=self.envelope(source),self.envelope(target)
        if any(left.get(k) and right.get(k) and left[k]!=right[k] for k in ("project_id","product_id","lineage_id","version_id")):
            raise GraphError("unauthorized lineage/hierarchy boundary")
        crossed=[k for k in ("session_id","run_id") if left.get(k) and right.get(k) and left[k]!=right[k]]
        if not crossed:return
        if not value.get("repair_decision_id"):raise GraphError("unauthorized RUN/SESSION causal boundary: missing committed repair DECISION")
        decision=self.resolve(value["repair_decision_id"],"DECISION")
        if decision["sequence"]>=source["sequence"]:raise GraphError("repair decision not prior committed")
        expected={k:[right[k],left[k]] for k in crossed}
        if decision.get("repair_permission")!=expected or decision["record"]["outcome"]!="REPAIR_AUTHORIZED":
            raise GraphError("decision does not permit exact repair boundary")
        subjects={r["entity_id"] for r in decision["record"]["subject_ids"]}
        if not all(set(pair)<=subjects for pair in expected.values()):raise GraphError("repair permission subjects differ")
    def validate_subject(self,node,subject):
        if node.get("derivation",{}).get("subject")!=subject:
            raise GraphError("derived endpoint meaning differs from independently fixed rule")
        if not subject.get("represented_fact") or not subject.get("bindings"):
            raise GraphError("derived endpoint lacks unambiguous source fact binding")
        env=self.envelope(node)
        if any(env.get(k)!=v for k,v in subject.get("historical_scope",{}).items() if k in {"run_id","session_id"}):
            raise GraphError("derived historical scope differs from endpoint record")
        paths={b["corpus_path"] for b in node["source_bindings"]}
        for binding in subject["bindings"]:
            if binding["corpus_path"] not in paths:raise GraphError("derived endpoint source unbound")
            self.corpus.binding(binding)
            raw=self.corpus.read(binding["corpus_path"])
            actual=sha256_bytes(raw) if binding.get("byte_digest") else pointer(strict_json_loads(raw),binding["pointer"])
            if actual!=binding["value"]:raise GraphError("derived endpoint source fact differs")
    def validate_interpretation(self,value,source,target):
        key=value["edge_type"]+":"+self.envelope(source)["entity_id"]+":"+self.envelope(target)["entity_id"]
        rule=self._causal_rules.get(key)
        if not rule or value["basis"].get("interpretation_rule_sha256")!=sha256_bytes(canonical_json(rule)):
            raise GraphError("unregistered or changed derived relationship rule")
        if rule["edge_type"]!=value["edge_type"] or rule["source_id"]!=self.envelope(source)["entity_id"] or rule["target_id"]!=self.envelope(target)["entity_id"]:
            raise GraphError("derived rule endpoints differ")
        self.validate_subject(source,rule["source_subject"])
        self.validate_subject(target,rule["target_subject"])
        left,right=rule["source_subject"].get("historical_scope",{}),rule["target_subject"].get("historical_scope",{})
        if any(left.get(k) and right.get(k) and left[k]!=right[k] for k in ("run_id","session_id")):
            self.boundary(value,{"record":{"identity":left},"sequence":source["sequence"]},{"record":{"identity":right},"sequence":target["sequence"]})
        if rule.get("proof_kind")=="CURRENT_COMMIT_PROTOCOL":
            if source["derivation"].get("record_purpose")!="CURRENT_RECONSTRUCTION" or target["derivation"].get("record_purpose")!="CURRENT_RECONSTRUCTION":
                raise GraphError("current commitment proof cannot impersonate historical causation")
            if value["basis"].get("committed_target_record_sha256")!=sha256_bytes(canonical_json(target["record"])):
                raise GraphError("current causal source commitment differs")
            if value["basis"]["kind"]=="EXPLICIT_DECISION" and self.envelope(target)["entity_type"]!="DECISION":
                raise GraphError("current decision source has wrong type")
        elif rule.get("proof_kind")=="SOURCE_ASSERTION":
            if not rule.get("assertions") or not rule.get("relationship_meaning"):
                raise GraphError("hash-only relationship cannot assert causation")
            paths={b["corpus_path"] for b in source["source_bindings"]}
            for binding in rule["assertions"]:
                if binding["corpus_path"] not in paths:raise GraphError("source causal assertion unbound")
                self.corpus.binding(binding)
                actual=pointer(strict_json_loads(self.corpus.read(binding["corpus_path"])),binding["pointer"])
                if actual!=binding["value"]:raise GraphError("source causal assertion differs")
        else:raise GraphError("unsupported derived causal proof")

    def validate_basis(self,value,source,target):
        relation=value["edge_type"]
        basis=value.get("basis",{})
        if relation in CAUSAL:
            if basis.get("kind") not in {"EXPLICIT_REFERENCE","CLAIM_AUTHORITY_BINDING","DISPATCH_OPERATION_BINDING","EXPLICIT_DECISION","FROZEN_RULE"}:
                raise GraphError("temporal adjacency is insufficient for causation")
            if "interpretation_rule_sha256" in basis:
                self.validate_interpretation(value,source,target)
                return
            path=basis.get("corpus_path")
            if path not in {b["corpus_path"] for b in value["source_bindings"]}:raise GraphError("unbound causal support")
            observed=pointer(strict_json_loads(self.corpus.read(path)),basis.get("pointer",""))
            if observed!=basis.get("value"):raise GraphError("source reference differs")
            if basis["kind"]=="FROZEN_RULE":
                rule=pointer(CONTRACTS["OP1_CAUSAL_GRAPH_CONTRACT.json"],basis.get("rule_pointer"))
                if basis.get("rule_text")!=rule:raise GraphError("causal rule not frozen")
                # Frozen rule may only validate the exact field it defines.
                refs=source["record"].get(relation,[])
                refs=[refs] if isinstance(refs,str) else refs
                ids=[r.get("entity_id") if isinstance(r,dict) else r for r in refs]
                if value["target_id"] not in ids:raise GraphError("frozen rule cannot invent absent reference")
            else:
                bound=basis.get("binding_value")
                # Hashes identify bytes; unbound native aliases do not identify
                # a causal endpoint. Match the committed typed ID exactly.
                pending=[observed]
                found=False
                while pending:
                    part=pending.pop()
                    if isinstance(part,str) and part==bound:found=True
                    elif isinstance(part,dict):pending.extend(part.values())
                    elif isinstance(part,list):pending.extend(part)
                if bound!=value["target_id"] or not isinstance(bound,str) or not found:
                    raise GraphError("explicit source reference does not bind typed target")
    def edge(self,value):
        relation=value.get("edge_type")
        if relation not in EDGES:raise GraphError("undefined frozen relationship")
        source,target=self.resolve(value["source_id"]),self.resolve(value["target_id"])
        if source is target:raise GraphError("self cycle")
        if source["sequence"]<=target["sequence"]:raise GraphError("forward parent commitment")
        if relation in TYPES:self.resolve(value["target_id"],TYPES[relation])
        if relation in TYPES and relation!="event_id" and self.envelope(source)["entity_type"]=="EVENT" and source["record"].get("event_role") not in {"PUBLICATION","RESOLUTION","TERMINAL"}:
            raise GraphError("publication order violation")
        self.sources(value)
        self.boundary(value,source,target)
        self.validate_basis(value,source,target)
        # Every canonical edge must be an exact field reference in its source.
        # Basis verifies external support; it cannot invent a graph relationship.
        if (relation,value["target_id"]) not in self.references(source):
            raise GraphError("relationship absent from exact source schema field")
        require_dag(self._nodes,self._semantic_edges()+[value])
        key=(relation,value["source_id"],value["target_id"])
        if any(key==(e["edge_type"],e["source_id"],e["target_id"]) for e in self._edges):
            raise GraphError("immutable duplicate edge")
    def checkpoint_payload(self,terminal,manifest,outcome):
        return {"graph_root":self.root(),"sequence":len(self._records),"terminal_event_id":terminal,
                "graph_frontier":sorted(self._nodes),"expected_manifest_sha256":sha256_bytes(canonical_json(manifest)),
                "outcome":outcome,"closure_policy_sha256":sha256_bytes(canonical_json(self._closure_policies.get(terminal))),
                "terminal_scope":deepcopy(self._closure_policies.get(terminal,{}).get("terminal_scope")),
                "classification_binding_sha256":sha256_bytes(canonical_json(self._closure_policies.get(terminal,{}).get("classification_binding"))),
                "causal_rules_sha256":sha256_bytes(canonical_json(self._causal_rules)),
                "source_corpus_manifest_sha256":self.corpus.manifest_sha256}
    def closure(self,value,public_key):
        validate_id(value["terminal_event_id"],"EVENT")
        if value["terminal_event_id"] not in self._nodes:
            raise GraphError("missing terminal graph commitment","INCOMPLETE_EVIDENCE")
        terminal=self.resolve(value["terminal_event_id"],"EVENT")
        if terminal["record"]["event_role"]!="TERMINAL":raise GraphError("missing terminal commitment","INCOMPLETE_EVIDENCE")
        if not value.get("expected_manifest") or not value.get("required_evidence_classes"):
            raise GraphError("missing terminal evidence manifest/classes","INCOMPLETE_EVIDENCE")
        policy=self._closure_policies.get(value["terminal_event_id"])
        if not policy:raise GraphError("missing externally registered closure policy","INCOMPLETE_EVIDENCE")
        if (sorted(value["required_evidence_classes"])!=sorted(policy["required_evidence_classes"]) or
            sha256_bytes(canonical_json(value["expected_manifest"]))!=policy["expected_manifest_sha256"]):
            raise GraphError("candidate cannot weaken registered closure manifest/classes","INCOMPLETE_EVIDENCE")
        evidence_ids=[b.get("source_evidence_id") for b in value["expected_manifest"]]
        if len(set(evidence_ids))!=len(evidence_ids):raise GraphError("duplicate terminal evidence commitment","INCOMPLETE_EVIDENCE")
        scope=policy.get("terminal_scope")
        classification=value.get("classification_binding")
        if not scope or scope!=value.get("terminal_scope") or not classification or classification!=policy.get("classification_binding"):
            raise GraphError("closure scope/classification must match externally registered source policy","INCOMPLETE_EVIDENCE")
        if scope.get("run_id")!=self.envelope(terminal).get("run_id"):
            raise GraphError("closure scope differs from terminal subject RUN","INCOMPLETE_EVIDENCE")
        self.corpus.binding(classification)
        if not any(b["corpus_path"]==classification["corpus_path"] and b["sha256"]==classification["sha256"] for b in value["source_bindings"]):
            raise GraphError("terminal classification source absent from certificate support","INCOMPLETE_EVIDENCE")
        observed=pointer(strict_json_loads(self.corpus.read(classification["corpus_path"])),classification["pointer"])
        if scope.get("scope_kind")=="RUN":
            if value["outcome"] not in TERMINAL_OUTCOMES:
                raise GraphError("RUN terminal outcome not frozen","INCOMPLETE_EVIDENCE")
            mapped=RUN_MACHINE["user_shorthand_mapping"].get(observed,observed)
        elif scope.get("scope_kind")=="RECOVERY_COMPONENT":
            # The frozen causal design has no universal outcome enum. This
            # describes an evidence-bound recovery result, never a second RUN
            # transition or a newly invented ATTEMPT state machine.
            label_binding=policy.get("component_label_binding")
            if not label_binding:raise GraphError("recovery component lacks source label binding","INCOMPLETE_EVIDENCE")
            self.corpus.binding(label_binding)
            label=pointer(strict_json_loads(self.corpus.read(label_binding["corpus_path"])),label_binding["pointer"])
            if label!=scope.get("historical_component_label"):
                raise GraphError("recovery component label differs from source","INCOMPLETE_EVIDENCE")
            mapped=observed
        else:raise GraphError("unregistered terminal classification scope","INCOMPLETE_EVIDENCE")
        if not isinstance(mapped,str) or mapped!=value["outcome"]:
            raise GraphError("closure classification differs from source","INCOMPLETE_EVIDENCE")
        classes=set()
        for b in value["expected_manifest"]:
            try:
                if policy.get("evidence_registry")=="VERIFIED_SOURCE_COMMITMENTS":
                    if self.source_index is None:raise GraphError("verified source evidence registry absent")
                    source=self.source_index.committed_evidence(b["source_evidence_id"])
                    evidence=source["record"]
                    if source["record_binding"]!=b.get("evidence_record_binding"):
                        raise GraphError("source evidence identity commitment differs")
                else:evidence=self.resolve(b["source_evidence_id"],"EVIDENCE")["record"]
                self.corpus.raw_binding(b)
            except (KeyError,GraphError) as exc:
                raise GraphError("required evidence commitment missing","INCOMPLETE_EVIDENCE") from exc
            if (evidence["sha256"]!=b["sha256"] or evidence["byte_length"]!=b["byte_length"] or
                evidence["evidence_class"]!=b["evidence_class"]):
                raise GraphError("evidence class/hash differs from committed source","INCOMPLETE_EVIDENCE")
            classes.add(evidence["evidence_class"])
        if not set(value["required_evidence_classes"])<=classes:
            raise GraphError("valid hash does not replace missing evidence class","INCOMPLETE_EVIDENCE")
        self.sources(value)
        payload=self.checkpoint_payload(value["terminal_event_id"],value["expected_manifest"],value["outcome"])
        cp=value.get("checkpoint",{})
        if not self.trusted_checkpoint_public_key or public_key!=self.trusted_checkpoint_public_key or cp.get("payload")!=payload:
            raise GraphError("missing/stale external graph checkpoint","INCOMPLETE_EVIDENCE")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(cp["signature_hex"]),canonical_json(payload))
        except (ValueError,KeyError,TypeError,InvalidSignature) as exc:
            raise GraphError("invalid owner checkpoint","INCOMPLETE_EVIDENCE") from exc
        if any(c["terminal_event_id"]==value["terminal_event_id"] for c in self._closures):raise GraphError("closure collision")
    def tip_payload(self):
        closures=[{"terminal_event_id":c["terminal_event_id"],"closure_sha256":sha256_bytes(canonical_json(c))} for c in self._closures]
        return {"sequence":len(self._records),"graph_root":self.root(),
                "terminal_closure_sha256":sha256_bytes(canonical_json(sorted(closures,key=lambda c:c["terminal_event_id"])))}
    def verify_tip(self,checkpoint,public_key):
        if not self.trusted_checkpoint_public_key or public_key!=self.trusted_checkpoint_public_key or checkpoint.get("payload")!=self.tip_payload():
            raise GraphError("external graph tip detects truncation/rollback","INCOMPLETE_EVIDENCE")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(checkpoint["signature_hex"]),canonical_json(checkpoint["payload"]))
        except (ValueError,KeyError,TypeError,InvalidSignature) as exc:
            raise GraphError("invalid external graph tip signature","INCOMPLETE_EVIDENCE") from exc
    def validate_proposal(self,records):
        """Preflight a candidate batch without publishing or mutating any prefix."""
        values=[deepcopy(dict(v)) for v in records]
        nodes=deepcopy(self._nodes)
        edges=self._semantic_edges()
        for value in values:
            if value.get("kind")=="NODE":
                entity=self.envelope(value)["entity_id"]
                nodes[entity]=value
                edges.extend({"edge_type":r,"source_id":entity,"target_id":t} for r,t in self.references(value))
            elif value.get("kind")=="EDGE":edges.append(value)
        require_dag(nodes,edges)
        staged=self.rebuild(self.corpus,self.records,checkpoint_public_key=self.trusted_checkpoint_public_key,closure_policies=self._closure_policies,causal_rules=self._causal_rules,source_index=self.source_index)
        for value in values:staged.append(value,checkpoint_public_key=self.trusted_checkpoint_public_key)
        return staged.fingerprint()
    def append(self,value,*,checkpoint_public_key=None):
        candidate=deepcopy(dict(value))
        candidate["sequence"]=len(self._records)+1
        candidate["previous_graph_sha256"]=self.root()
        kind=candidate.get("kind")
        try:
            if kind=="NODE":self.node(candidate)
            elif kind=="EDGE":self.edge(candidate)
            elif kind=="CLOSURE":self.closure(candidate,checkpoint_public_key)
            else:raise GraphError("unsupported graph record")
        except GraphError:raise
        except (KeyError,TypeError,ValueError,IndexError) as exc:
            raise GraphError("malformed graph record: "+str(exc),"REJECT_RECORD") from exc
        raw=canonical_json(candidate)
        if self.sink:self.sink(deepcopy(candidate))
        self._records.append(raw)
        if kind=="NODE":self._nodes[self.envelope(candidate)["entity_id"]]=candidate
        elif kind=="EDGE":self._edges.append(candidate)
        else:self._closures.append(candidate)
        return deepcopy(candidate)
    def semantic_view(self):
        nodes=[{"identity":entity,"type":self.envelope(node)["entity_type"],"source_evidence_hashes":sorted({b["sha256"] for b in node["source_bindings"]})} for entity,node in sorted(self._nodes.items())]
        edges=[{"edge_type":e["edge_type"],"source_id":e["source_id"],"target_id":e["target_id"],"source_evidence_hashes":sorted({b["sha256"] for b in e["source_bindings"]})} for e in sorted(self._semantic_edges(),key=lambda e:(e["edge_type"],e["source_id"],e["target_id"]))]
        closures=sorted([{"terminal_event_id":c["terminal_event_id"],"classification":c["outcome"],"terminal_scope":c["terminal_scope"],"classification_binding_sha256":sha256_bytes(canonical_json(c["classification_binding"])),"expected_manifest_sha256":sha256_bytes(canonical_json(c["expected_manifest"]))} for c in self._closures],key=lambda c:c["terminal_event_id"])
        for item in nodes:
            subject=self._nodes[item["identity"]].get("derivation",{}).get("subject")
            if subject:item["represented_fact_sha256"]=sha256_bytes(canonical_json(subject))
        for item in edges:
            rule=self._causal_rules.get(item["edge_type"]+":"+item["source_id"]+":"+item["target_id"])
            if rule:
                item["interpretation_rule_sha256"]=sha256_bytes(canonical_json(rule))
                item["relationship_meaning"]=rule["relationship_meaning"]
        return {"nodes":nodes,"edges":edges,"schema_links":self.schema_links(),"closures":closures}
    def terminal_completeness(self):
        terminals={i for i,n in self._nodes.items() if n["record"].get("event_role")=="TERMINAL"}
        closed={c["terminal_event_id"] for c in self._closures}
        return {"classification":"PASS" if terminals and terminals==closed else "INCOMPLETE_EVIDENCE",
                "terminal_events":sorted(terminals),"missing_closures":sorted(terminals-closed)}
    def fingerprint(self):return sha256_bytes(canonical_json(self.semantic_view()))
    @classmethod
    def rebuild(cls,corpus,records,*,checkpoint_public_key=None,trusted_tip=None,closure_policies=None,causal_rules=None,source_index=None):
        graph=cls(corpus,trusted_checkpoint_public_key=checkpoint_public_key,closure_policies=closure_policies,causal_rules=causal_rules,source_index=source_index)
        for raw in records:
            candidate=graph.append(strict_json_loads(raw),checkpoint_public_key=checkpoint_public_key)
            if canonical_json(candidate)!=raw:raise GraphError("record reorder or commitment mismatch")
        if trusted_tip is not None:graph.verify_tip(trusted_tip,checkpoint_public_key)
        return graph


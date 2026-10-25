"""Verified frozen I1 source index; declarations are not automatically admitted causes."""
from __future__ import annotations
from copy import deepcopy
from collections import Counter
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .identity import canonical_json,sha256_bytes,strict_json_loads
from .i4_graph import CausalGraph,GraphError,require_dag,SCHEMAS,TYPES
from .schema_registry import SchemaRegistry

class SourceIndex:
    def __init__(self,corpus):
        self.corpus=corpus;self.objects={};self.commitments={};self.header=None
        manifests=[]
        for path,row in corpus.files.items():
            raw=corpus.read(path)
            try:record=strict_json_loads(raw)
            except (ValueError,UnicodeError):continue
            if not isinstance(record,dict):continue
            kind=record.get("identity",{}).get("entity_type")
            binding={"corpus_path":path,"sha256":row["sha256"],"byte_length":row["byte_length"]}
            if kind in {"EVENT","EVIDENCE"}:
                entity=record["identity"]["entity_id"]
                if entity in self.objects and self.objects[entity]["record"]!=record:
                    raise GraphError("conflicting immutable source identity")
                self.objects.setdefault(entity,{"kind":"NODE","record":record,"record_binding":binding,"source_bindings":[binding]})
            if "writer_signature_hex" in record and "object_id" in record and "sequence" in record:
                manifests.append((record,binding))
            if row.get("original_package_member","").endswith("/store_header.json"):
                if self.header and self.header!=record:raise GraphError("conflicting source store headers")
                self.header=record
        if not self.header:raise GraphError("source writer header absent")
        key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.header["writer_public_key_hex"]))
        previous=None
        schemas=SchemaRegistry()
        authenticated_actor=self.header["identity"]["actor_id"]
        for sequence,(manifest,binding) in enumerate(sorted(manifests,key=lambda x:x[0]["sequence"]),1):
            if manifest["sequence"]!=sequence or manifest["previous_manifest_sha256"]!=previous:
                raise GraphError("source commitment reorder/truncation")
            if manifest["store_id"]!=self.header["store_id"]:raise GraphError("source store identity mismatch")
            unsigned=deepcopy(manifest);signature=bytes.fromhex(unsigned.pop("writer_signature_hex"))
            try:key.verify(signature,canonical_json(unsigned))
            except InvalidSignature as exc:raise GraphError("source writer signature invalid") from exc
            entity=manifest["object_id"]
            if entity in self.commitments:raise GraphError("source identity committed twice")
            node=self.objects.get(entity)
            if not node:raise GraphError("source committed typed record missing")
            record=node["record"];env=CausalGraph.envelope(node)
            entry=schemas.find_document(SCHEMAS[env["entity_type"]])
            checked=schemas.validate(entry.schema_id,entry.version,record)
            if not checked.valid:raise GraphError("source frozen schema rejected: "+"; ".join(checked.errors))
            if (env["schema_id"]!=entry.schema_id or env["schema_version"]!=entry.version or
                record["actor_id"]!=env["actor_id"] or manifest["actor_id"]!=authenticated_actor or env["actor_id"]!=authenticated_actor):
                raise GraphError("source authenticated actor/schema linkage differs")
            for field in ("project_id","product_id","lineage_id","version_id","session_id","run_id"):
                if env.get(field)!=manifest["scope"].get(field):raise GraphError("source signed scope differs from record")
            if record["attempt_id"]!=manifest["scope"]["attempt_id"]:raise GraphError("source signed attempt differs")
            if env["entity_type"]=="EVENT" and record["committed_sequence"]!=sequence:raise GraphError("source event sequence differs")
            if env["entity_type"]=="EVIDENCE" and any(record[a]!=manifest[b] for a,b in (("sha256","object_sha256"),("byte_length","object_byte_length"),("evidence_class","evidence_class"))):
                raise GraphError("source evidence payload/class differs from signed commitment")
            record_binding=node["record_binding"]
            if record_binding["sha256"]!=manifest["record_sha256"] or record_binding["byte_length"]!=manifest["record_byte_length"]:
                raise GraphError("source record differs from signed commitment")
            self.commitments[entity]={"sequence":sequence,"manifest":manifest,"source_binding":binding}
            previous=binding["sha256"]
        if len(self.objects)!=len(self.commitments):raise GraphError("uncommitted source object")
        self.root=previous
        # Keep verified byte locators independently of mutable diagnostic views.
        self._evidence_locators={entity:(deepcopy(node["record_binding"]),
                                 deepcopy(self.commitments[entity]["source_binding"]))
                                 for entity,node in self.objects.items()
                                 if CausalGraph.envelope(node)["entity_type"]=="EVIDENCE"}
    def committed_evidence(self,entity):
        """RAW custody proof; does not admit its historical causal subgraph."""
        from .identity import validate_id
        validate_id(entity,"EVIDENCE")
        if entity not in self._evidence_locators:raise GraphError("source evidence commitment absent")
        record_binding,manifest_binding=self._evidence_locators[entity]
        record=strict_json_loads(self.corpus.read(record_binding["corpus_path"]))
        manifest=strict_json_loads(self.corpus.read(manifest_binding["corpus_path"]))
        if (record["evidence_id"]!=entity or manifest["object_id"]!=entity or
            record_binding["sha256"]!=manifest["record_sha256"] or
            any(record[a]!=manifest[b] for a,b in (("sha256","object_sha256"),("byte_length","object_byte_length"),("evidence_class","evidence_class")))):
            raise GraphError("source evidence record/class differs from signed commitment")
        return {"record":record,"record_binding":deepcopy(record_binding),
                "source_commitment_binding":deepcopy(manifest_binding),"sequence":manifest["sequence"]}
    def analysis(self):
        edges=[];boundaries=[];invalid=[]
        for entity,node in self.objects.items():
            env=CausalGraph.envelope(node)
            for relation,target in CausalGraph.references(node):
                edge={"edge_type":relation,"source_id":entity,"target_id":target}
                edges.append(edge)
                if target not in self.objects or self.commitments[target]["sequence"]>=self.commitments[entity]["sequence"] or (relation in TYPES and CausalGraph.envelope(self.objects[target])["entity_type"]!=TYPES[relation]):
                    invalid.append(edge);continue
                other=CausalGraph.envelope(self.objects[target])
                crossed=[k for k in ("session_id","run_id") if env.get(k) and other.get(k) and env[k]!=other[k]]
                if crossed and relation in {"parent_ids","caused_by_ids","event_id"}:
                    boundaries.append({**edge,"boundaries":crossed,"source_binding":node["record_binding"],
                                       "target_binding":self.objects[target]["record_binding"],"source_commitment":self.commitments[entity],
                                       "target_commitment":self.commitments[target],"status":"SOURCE_DECLARED_UNADMITTED_NO_IDENTIFIED_PERMISSION"})
        require_dag(self.objects,edges)
        adjacency={i:set() for i in self.objects}
        for e in edges:
            if e["target_id"] in adjacency:
                adjacency[e["source_id"]].add(e["target_id"]);adjacency[e["target_id"]].add(e["source_id"])
        unseen=set(adjacency);components=[]
        while unseen:
            pending=[min(unseen)];size=0
            while pending:
                current=pending.pop()
                if current not in unseen:continue
                unseen.remove(current);size+=1;pending.extend(adjacency[current]&unseen)
            components.append(size)
        return {"source_record_integrity":"PASS","writer_signatures_verified":len(self.commitments),"signed_manifest_root_sha256":self.root,
                "source_declared_dag":"PASS","source_node_types":dict(Counter(CausalGraph.envelope(n)["entity_type"] for n in self.objects.values())),
                "source_declared_edge_types":dict(Counter(e["edge_type"] for e in edges)),"dangling_or_forward_references":invalid,
                "cross_boundary_references":boundaries,"connected_component_sizes":sorted(components),
                "causal_admission":"BLOCKED" if boundaries or invalid else "NOT_YET_EVALUATED",
                "truth_boundary":"Signed source references are preserved declarations, not permission or proof of physical causation."}
    def admit_until_rejection(self,graph):
        for entity in sorted(self.objects,key=lambda e:self.commitments[e]["sequence"]):
            candidate=deepcopy(self.objects[entity])
            try:graph.append(candidate)
            except GraphError as exc:
                return {"result":exc.outcome,"reason":str(exc),"source_candidate":candidate,
                        "source_commitment":self.commitments[entity],"committed_graph_prefix_records":len(graph.records),
                        "committed_graph_prefix_sha256":graph.root(),"semantic_prefix_fingerprint":graph.fingerprint(),
                        "complete_graph":False,"terminal_closure":"INCOMPLETE_EVIDENCE"}
        return {"result":"PASS","committed_graph_prefix_records":len(graph.records),"complete_graph":True}

"""I4 graph publication through unchanged I1 ACTION/EVIDENCE/PUBLICATION APIs."""
from __future__ import annotations
from .append_only import utc_now
from .identity import canonical_json,generate_id,sha256_bytes
from .evidence_store import EvidenceStore
from .storage_paths import Scope

def event(store,scope,actor,role,*,evidence_ids=()):
    entity=generate_id("EVENT")
    schema=store.schemas.find_document("OP1_EVENT_SCHEMA.json")
    identity={"entity_id":entity,"entity_type":"EVENT","schema_id":schema.schema_id,"schema_version":schema.version,
              "actor_id":actor,"created_at_utc":utc_now(),"status":"COMMITTED",
              **{k:getattr(scope,k) for k in ("project_id","product_id","lineage_id","version_id","session_id","run_id")}}
    return {"identity":identity,"event_id":entity,"event_kind":"I4_GRAPH_"+role,"event_role":role,
            "session_id":scope.session_id,"run_id":scope.run_id,"attempt_id":scope.attempt_id,"actor_id":actor,
            "occurred_at_utc":utc_now(),"committed_sequence":1,"parent_ids":[],"caused_by_ids":[],
            "payload_sha256":sha256_bytes(b""),"produced_artifact_ids":[],"produced_finding_ids":[],
            "resolved_finding_ids":[],"triggered_decision_ids":[],"evidence_ids":list(evidence_ids),
            "writer_authentication_ref":store.writer_authentication_ref}

class I1GraphPublisher:
    """Each graph append has a distinct frozen EVIDENCE identity and exact bytes."""
    def __init__(self,store:EvidenceStore,scope:Scope,actor_id:str):
        self.store,self.scope,self.actor_id=store,scope,actor_id
        self.source_ids=[]
        self.graph_ids=[]
    def publish(self,content:bytes,evidence_class:str,*,derived:bool):
        store,scope,actor=self.store,self.scope,self.actor_id
        action=store.commit_action_event(event(store,scope,actor,"ACTION"),scope)
        entity=generate_id("EVIDENCE")
        schema=store.schemas.find_document("OP1_EVIDENCE_SCHEMA.json")
        digest=sha256_bytes(content)
        identity={"entity_id":entity,"entity_type":"EVIDENCE","schema_id":schema.schema_id,"schema_version":schema.version,
                  "actor_id":actor,"created_at_utc":utc_now(),"status":"COMMITTED","content_sha256":digest,
                  **{k:getattr(scope,k) for k in ("project_id","product_id","lineage_id","version_id","session_id","run_id")}}
        record={"identity":identity,"evidence_id":entity,"run_id":scope.run_id,"attempt_id":scope.attempt_id,
                "event_id":action["event_id"],"actor_id":actor,"relative_path":store.paths.object_relative(scope,"derived" if derived else "raw",entity,"bin"),
                "byte_length":len(content),"sha256":digest,"producer":"I4 offline source-byte reader / derived graph writer",
                "created_at_utc":utc_now(),"evidence_class":evidence_class,"derivation_class":"DERIVED_IMMUTABLE" if derived else "RAW_IMMUTABLE"}
        if derived:record["source_evidence_ids"]=list(self.source_ids)
        publication=event(store,scope,actor,"PUBLICATION",evidence_ids=[entity])
        receipt=store.publish_evidence(record,content,publication,scope,producer_kind="ACTOR")
        (self.graph_ids if derived else self.source_ids).append(entity)
        return receipt
    def seed_source(self,raw:bytes):
        return self.publish(raw,"I4_SOURCE_MANIFEST_BYTES",derived=False)
    def __call__(self,record):
        self.publish(canonical_json(record),"I4_APPEND_ONLY_GRAPH_RECORD",derived=True)
    def rejected(self,candidate,error):
        return self.publish(canonical_json({"candidate":candidate,"error":str(error),"outcome":getattr(error,"outcome","REJECT_GRAPH")}),
                            "I4_REJECTED_GRAPH_PUBLICATION",derived=True)
    def records(self):
        rows={r["object_id"]:r for r in self.store.manifest_rows()}
        return tuple((self.store.root/rows[e]["object_relative_path"]).read_bytes() for e in self.graph_ids
                     if rows[e]["evidence_class"]=="I4_APPEND_ONLY_GRAPH_RECORD")


"""Current offline reconstructions; historical identities and RAW remain source facts."""
from __future__ import annotations
from copy import deepcopy
from .identity import generate_id,canonical_json,sha256_bytes,strict_json_loads
from .schema_registry import SchemaRegistry
from .i4_graph import CausalGraph,GraphError,pointer

class Reconstruction:
    def __init__(self,corpus,index,admission,attempt_id,actor_id,created_at):
        self.corpus,self.index=corpus,index;self.files=corpus.files
        self.admission,self.attempt_id,self.actor_id,self.created_at=admission,attempt_id,actor_id,created_at
        self.schemas=SchemaRegistry();self.nodes=[];self.rules={};self.policies={};self.cases={}
    def binding(self,path):
        row=self.files[path]
        return {"corpus_path":path,"sha256":row["sha256"],"byte_length":row["byte_length"]}
    def observed(self,path,ptr=""):
        return {**self.binding(path),"pointer":ptr,"value":pointer(strict_json_loads(self.corpus.read(path)),ptr)}
    def env(self,kind,scope):
        schema=self.schemas.find_document("OP1_"+kind+"_SCHEMA.json" if kind in {"EVENT","EVIDENCE","ERROR","FINDING","DECISION"} else "OP1_IDENTITY_ENVELOPE_SCHEMA.json")
        return {"entity_id":generate_id(kind),"entity_type":kind,"schema_id":schema.schema_id,"schema_version":schema.version,
                "actor_id":self.actor_id,"created_at_utc":self.created_at,"status":"COMMITTED",**scope}
    def event(self,label,scope,bindings,*,role="OBSERVATION",observations=None):
        env=self.env("EVENT",scope)
        record={"identity":env,"event_id":env["entity_id"],"event_kind":"I4_CURRENT_RECONSTRUCTION_"+label,"event_role":role,
                "session_id":scope["session_id"],"run_id":scope["run_id"],"attempt_id":self.attempt_id,"actor_id":self.actor_id,
                "occurred_at_utc":self.created_at,"committed_sequence":len(self.nodes)+1,"parent_ids":[],"caused_by_ids":[],
                "payload_sha256":sha256_bytes(canonical_json(bindings)),"produced_artifact_ids":[],"produced_finding_ids":[],
                "resolved_finding_ids":[],"triggered_decision_ids":[],"evidence_ids":[],"writer_authentication_ref":"I4_OWNER_VERIFIED_CURRENT_RECONSTRUCTION"}
        return self.node(record,label,scope,bindings,observations)
    def node(self,record,label,scope,bindings,observations=None):
        support={b["corpus_path"]:self.binding(b["corpus_path"]) for b in bindings}
        observed=observations or [{"corpus_path":b["corpus_path"],"pointer":b["pointer"],"value":b["value"]} for b in bindings if "pointer" in b]
        value={"kind":"NODE","record":record,"source_bindings":list(support.values()),"derivation":{
            "record_purpose":"CURRENT_RECONSTRUCTION","observations":observed,"causal_basis":{},
            "subject":{"represented_fact":label,"historical_scope":{k:scope[k] for k in ("run_id","session_id")},"bindings":deepcopy(bindings)}}}
        self.nodes.append(value);return value
    def link(self,source,target,*,relation="parent_ids",kind="EXPLICIT_REFERENCE",assertions=None,meaning=None):
        src=CausalGraph.envelope(source)["entity_id"];dst=CausalGraph.envelope(target)["entity_id"]
        source["record"][relation].append({"entity_type":CausalGraph.envelope(target)["entity_type"],"entity_id":dst})
        rule={"edge_type":relation,"source_id":src,"target_id":dst,
              "source_subject":deepcopy(source["derivation"]["subject"]),"target_subject":deepcopy(target["derivation"]["subject"]),
              "proof_kind":"SOURCE_ASSERTION" if assertions else "CURRENT_COMMIT_PROTOCOL",
              "relationship_meaning":meaning or "current interpretation depends on prior current commitment; does not assert original historical causation"}
        basis={"kind":kind}
        if assertions:
            rule["assertions"]=deepcopy(assertions)
            known={b["corpus_path"] for b in source["source_bindings"]}
            for assertion in assertions:
                if assertion["corpus_path"] not in known:
                    source["source_bindings"].append(self.binding(assertion["corpus_path"]));known.add(assertion["corpus_path"])
        else:basis["committed_target_record_sha256"]=sha256_bytes(canonical_json(target["record"]))
        key=relation+":"+src+":"+dst;self.rules[key]=rule
        basis["interpretation_rule_sha256"]=sha256_bytes(canonical_json(rule))
        source["derivation"]["causal_basis"][relation+":"+dst]=basis
    def reference_cause(self,source,target,relation="event_id"):
        # EVIDENCE/ERROR event_id is scalar in the exact frozen schema.
        src=CausalGraph.envelope(source)["entity_id"];dst=CausalGraph.envelope(target)["entity_id"]
        source["record"][relation]=dst
        rule={"edge_type":relation,"source_id":src,"target_id":dst,"source_subject":deepcopy(source["derivation"]["subject"]),
              "target_subject":deepcopy(target["derivation"]["subject"]),"proof_kind":"CURRENT_COMMIT_PROTOCOL",
              "relationship_meaning":"current interpretation receipt/error assessment produced by prior current source observation; no historical RAW replacement"}
        self.rules[relation+":"+src+":"+dst]=rule
        source["derivation"]["causal_basis"][relation+":"+dst]={"kind":"EXPLICIT_REFERENCE","interpretation_rule_sha256":sha256_bytes(canonical_json(rule)),
              "committed_target_record_sha256":sha256_bytes(canonical_json(target["record"]))}
    def envelope_cause(self,node,event):
        entity=event["record"]["event_id"];CausalGraph.envelope(node)["caused_by_ids"]=[{"entity_type":"EVENT","entity_id":entity}]
        source=CausalGraph.envelope(node)["entity_id"]
        rule={"edge_type":"caused_by_ids","source_id":source,"target_id":entity,"source_subject":deepcopy(node["derivation"]["subject"]),
              "target_subject":deepcopy(event["derivation"]["subject"]),"proof_kind":"CURRENT_COMMIT_PROTOCOL",
              "relationship_meaning":"current finding/decision produced by already committed current review event; preserves historical failure"}
        self.rules["caused_by_ids:"+source+":"+entity]=rule
        node["derivation"]["causal_basis"]["caused_by_ids:"+entity]={"kind":"EXPLICIT_REFERENCE","interpretation_rule_sha256":sha256_bytes(canonical_json(rule)),
               "committed_target_record_sha256":sha256_bytes(canonical_json(event["record"]))}
    def receipt(self,event,scope,label):
        env=self.env("EVIDENCE",scope)
        body={"kind":"CURRENT_SOURCE_INTERPRETATION_RECEIPT","current_observation_event_id":event["record"]["event_id"],
              "represented_fact":label,"original_source_bindings":deepcopy(event["source_bindings"])}
        raw=canonical_json(body);env["content_sha256"]=sha256_bytes(raw)
        record={"identity":env,"evidence_id":env["entity_id"],"event_id":event["record"]["event_id"],"run_id":scope["run_id"],
                "attempt_id":self.attempt_id,"actor_id":self.actor_id,"relative_path":"derived/"+env["entity_id"]+".json",
                "byte_length":len(raw),"sha256":sha256_bytes(raw),"producer":"current offline I4 reconstruction",
                "created_at_utc":self.created_at,"evidence_class":"I4_SOURCE_INTERPRETATION_RECEIPT","derivation_class":"DERIVED_IMMUTABLE"}
        node=self.node(record,"current receipt for "+label,scope,event["derivation"]["subject"]["bindings"],event["derivation"]["observations"])
        node["source_bindings"]=deepcopy(event["source_bindings"]);node["derivation"]["receipt_payload"]=body
        self.reference_cause(node,event);return node
    def review_failure(self,event,receipt,scope,label,code,decision_outcome):
        evidence=[receipt["record"]["evidence_id"]];bindings=event["derivation"]["subject"]["bindings"]
        env=self.env("ERROR",scope)
        error=self.node({"identity":env,"error_id":env["entity_id"],"event_id":event["record"]["event_id"],"code":code,
             "stage":"CURRENT_OFFLINE_SOURCE_ASSESSMENT","message":label,"evidence_ids":evidence,"classification":"UNKNOWN" if code=="OWNERSHIP_NOT_PROVEN" else "KNOWN"},label,scope,bindings)
        self.reference_cause(error,event)
        review_action=self.event("CURRENT_FAILURE_REVIEW_ACTION",scope,bindings,role="ACTION")
        self.link(review_action,error,relation="caused_by_ids")
        env=self.env("FINDING",scope)
        finding=self.node({"identity":env,"finding_id":env["entity_id"],"subject_ids":[{"entity_type":"ERROR","entity_id":error["record"]["error_id"]}],
             "observation":label,"severity":"BLOCKING","evidence_ids":evidence,"initial_state":"OPEN"},"current finding: "+label,scope,bindings)
        self.envelope_cause(finding,review_action)
        env=self.env("DECISION",scope)
        decision=self.node({"identity":env,"decision_id":env["entity_id"],"decider_actor_id":self.actor_id,
             "subject_ids":[{"entity_type":"FINDING","entity_id":finding["record"]["finding_id"]}],"outcome":decision_outcome,
             "rationale":"Current analyst disposition only; original error/finding and RUN/SESSION states remain; no owner or runtime authority",
             "evidence_ids":evidence,"decided_at_utc":self.created_at,"resolves_finding_ids":[]},"current review disposition: "+decision_outcome,scope,bindings)
        self.envelope_cause(decision,review_action)
        publication=self.event("FAILURE_REVIEW_PUBLICATION",scope,bindings,role="RESOLUTION")
        publication["record"]["produced_finding_ids"]=[finding["record"]["finding_id"]]
        publication["record"]["triggered_decision_ids"]=[decision["record"]["decision_id"]]
        publication["record"]["evidence_ids"]=evidence
        self.link(publication,decision,relation="caused_by_ids",kind="EXPLICIT_DECISION")
        return publication
    def terminal(self,case,scope,last,evidence,classification,expected,*,component_label=None):
        bindings=[classification]
        if component_label:bindings.append(component_label)
        terminal=self.event(case+"_SOURCE_BOUND_CLASSIFICATION",scope,bindings,role="TERMINAL")
        terminal["record"]["evidence_ids"]=[n["record"]["evidence_id"] for n in evidence]
        self.link(terminal,last)
        policy={"required_evidence_classes":sorted({e["evidence_class"] for e in expected}),
                "expected_manifest_sha256":sha256_bytes(canonical_json(expected)),"evidence_registry":"VERIFIED_SOURCE_COMMITMENTS",
                "terminal_scope":{"scope_kind":"RECOVERY_COMPONENT" if component_label else "RUN","run_id":scope["run_id"]},
                "classification_binding":{k:v for k,v in classification.items() if k!="value"}}
        if component_label:
            policy["component_label_binding"]={k:v for k,v in component_label.items() if k!="value"}
            policy["terminal_scope"]["historical_component_label"]=component_label["value"]
        self.policies[terminal["record"]["event_id"]]=policy
        self.cases[case]={"terminal_event_id":terminal["record"]["event_id"],"expected_manifest":expected,"historical_outcome":classification["value"],
                         "coverage":"CURRENT_RECONSTRUCTION; original invalid EVENT proposals remain unadmitted"}
    def source_expected(self,entity,raw):
        committed=self.index.committed_evidence(entity);record=committed["record"]
        binding={k:raw[k] for k in ("corpus_path","original_package_member","sha256","byte_length") if k in raw}
        self.corpus.raw_binding(binding)
        if record["sha256"]!=binding["sha256"] or record["byte_length"]!=binding["byte_length"]:raise GraphError("selected RAW differs from source commitment")
        return {**binding,"source_evidence_id":entity,"evidence_class":record["evidence_class"],"evidence_record_binding":committed["record_binding"]}
    def native(self,case,controls,raw_rows):
        first=strict_json_loads(self.corpus.read(controls[0]["source"]["corpus_path"]))
        source_env=CausalGraph.envelope(self.index.objects[first["evidence_id"]])
        scope={k:source_env[k] for k in ("project_id","product_id","session_id","run_id")}
        scope.update(lineage_id=self.admission["lineage_id"],version_id=self.admission["version_id"])
        nodes={};receipts=[];previous=None;payloads={r["kind"]:strict_json_loads(self.corpus.read(r["source"]["corpus_path"])) for r in controls}
        by_kind={r["kind"]:r for r in controls};expected=[self.source_expected(r["evidence_id"],r["raw_content_binding"]) for r in raw_rows]
        for row in controls:
            kind=row["kind"];path=row["source"]["corpus_path"];payload=payloads[kind]
            bindings=[self.observed(path),self.observed(path,"/kind"),self.observed(path,"/event_id"),self.observed(path,"/subject_run_id"),self.observed(path,"/subject_session_id")]
            event=self.event(case+"_"+kind+"_CONTROL_OBSERVATION",scope,bindings)
            if previous:
                self.link(event,previous)
                prior_kind=previous["native_control_kind"]
                if payload["causal_predecessor_event_id"]!=payloads[prior_kind]["event_id"]:raise GraphError("control predecessor not exact same RUN source commitment")
                self.link(event,previous,relation="caused_by_ids",assertions=[self.observed(path,"/causal_predecessor_event_id"),self.observed(by_kind[prior_kind]["source"]["corpus_path"],"/event_id")],
                          meaning="explicit historical control publication dependency; does not by itself claim a native effect")
            event["native_control_kind"]=kind;nodes[kind]=event;previous=event
            if kind=="OUTER_CLAIM":
                reservation=payloads["RUN_RESERVED"]
                if payload["claim"]["run_authority_id"]!=reservation["authority"]["authority_id"]:raise GraphError("claim authority source mismatch")
                self.link(event,nodes["RUN_RESERVED"],relation="caused_by_ids",kind="CLAIM_AUTHORITY_BINDING",
                          assertions=[self.observed(path,"/claim/run_authority_id"),self.observed(by_kind["RUN_RESERVED"]["source"]["corpus_path"],"/authority/authority_id")],
                          meaning="historical claim explicitly binds exact recorded authority; no prospective grant")
            if kind=="RAW_CAPTURE":
                self.link(event,effect,relation="caused_by_ids",kind="DISPATCH_OPERATION_BINDING",
                          assertions=[self.observed(path,"/entries"),self.observed(path,"/exit_status_sha256"),self.observed(path,"/native_manifest_sha256")],
                          meaning="RAW capture explicitly commits the observed native process exit and native subtree for this exact operation; no time-only causation")
            receipt=self.receipt(event,scope,case+" "+kind);receipts.append(receipt)
            if kind=="DISPATCH_ACK":
                effect,effect_receipt=self.physical_native(case,scope,payloads,by_kind,raw_rows,nodes)
                receipts.append(effect_receipt)
            if kind=="OWNERSHIP_RECONCILED" and not payload["cleanup_proven"]:
                review=self.review_failure(event,receipt,scope,"source cleanup/ownership not proven","OWNERSHIP_NOT_PROVEN","PRESERVE_AMBIGUITY_AND_RECORDED_QUARANTINE")
                nodes["CURRENT_FAILURE_REVIEW"]=review
        assessment=self.event(case+"_CLOSURE_ASSESSMENT",scope,[self.observed(by_kind["RUN_TERMINAL"]["source"]["corpus_path"],"/status")])
        self.link(assessment,previous);self.link(assessment,effect)
        if "CURRENT_FAILURE_REVIEW" in nodes:self.link(assessment,nodes["CURRENT_FAILURE_REVIEW"])
        self.terminal(case,scope,assessment,receipts,self.observed(by_kind["RUN_TERMINAL"]["source"]["corpus_path"],"/status"),expected)
    def physical_native(self,case,scope,payloads,by_kind,raw_rows,nodes):
        # Physical observation requires dispatch, exit RAW and captured native outputs,
        # plus exact operation/output bindings. Control predecessor or time alone is insufficient.
        capture=payloads["RAW_CAPTURE"];dispatch=payloads["DISPATCH_ACK"];sidecar=payloads["IDENTITY_SIDECAR"]
        exit_row=next(r for r in raw_rows if r["evidence_class"]=="EXIT_STATUS");exit_path=exit_row["raw_content_binding"]["corpus_path"]
        exit_record=strict_json_loads(self.corpus.read(exit_path))
        if (capture["causal_predecessor_event_id"]!=dispatch["event_id"] or
            exit_record["native_output_root"]!=sidecar["mapping"]["NATIVE_OUTPUT_ROOT"] or
            not capture["native_main_present"] or not capture["native_preflight_present"] or
            capture["exit_status_sha256"]!=exit_row["raw_content_binding"]["sha256"] or
            not any(e["evidence_id"]==exit_row["evidence_id"] and e["sha256"]==capture["exit_status_sha256"] for e in capture["entries"])):
            raise GraphError("physical observation lacks exact dispatch/RAW/output bindings")
        bindings=[self.observed(exit_path),self.observed(by_kind["RAW_CAPTURE"]["source"]["corpus_path"],"/entries"),
                  self.observed(by_kind["RAW_CAPTURE"]["source"]["corpus_path"],"/native_main_present"),
                  self.observed(by_kind["RAW_CAPTURE"]["source"]["corpus_path"],"/native_preflight_present")]
        effect=self.event(case+"_RECORDED_NATIVE_EXECUTION_RESULT",scope,bindings)
        self.link(effect,nodes["DISPATCH_ACK"],relation="caused_by_ids",kind="DISPATCH_OPERATION_BINDING",
                  assertions=[self.observed(by_kind["RAW_CAPTURE"]["source"]["corpus_path"],"/causal_predecessor_event_id"),
                              self.observed(by_kind["RAW_CAPTURE"]["source"]["corpus_path"],"/exit_status_sha256"),
                              self.observed(by_kind["IDENTITY_SIDECAR"]["source"]["corpus_path"],"/mapping/NATIVE_OUTPUT_ROOT"),self.observed(exit_path,"/native_output_root")],
                  meaning="recorded dispatch operation produced bound process exit and native output observations; no new native execution")
        return effect,self.receipt(effect,scope,case+" recorded native execution")
    def recovery_e50(self):
        registry=strict_json_loads(self.corpus.read("v1/m/00155-f38d0ec736ae.json"))
        first=self.index.committed_evidence(registry["entries"][0]["evidence_id"]);env=first["record"]["identity"]
        scope={k:env[k] for k in ("project_id","product_id","session_id","run_id")};scope.update(lineage_id=self.admission["lineage_id"],version_id=self.admission["version_id"])
        paths={r["sha256"]:p for p,r in self.files.items()}
        entries={e["sha256"]:e for e in registry["entries"]}
        path_by_name={"request":"v1/m/00142-eb6dc1dd1a8e.json","owner":"v1/m/00156-1f11500282c7.json", "root":"v1/m/00150-76b1a647c0f7.json",
                      "wrapper":"v1/m/00181-179a80f85096.json","result":"v1/m/00178-0ffb29d2c237.json", "state":"v1/m/00147-e9c3938d29d0.json"}
        owner_raw=self.corpus.read(path_by_name["owner"]);root=strict_json_loads(self.corpus.read(path_by_name["root"]));wrapper=strict_json_loads(self.corpus.read(path_by_name["wrapper"]));result=strict_json_loads(self.corpus.read(path_by_name["result"]))
        if (sha256_bytes(owner_raw)!=root["owner_decision_sha256"] or root["powershell_error"]!="DuplicateKeysInJsonString" or
            wrapper["exit_code"]!=1 or wrapper["pktmon_stop_process_creations"]!=0 or result["PKTMON_STOP_PROCESS_CREATIONS"]!=0):
            raise GraphError("E50 exact owner/parser/wrapper/result source facts differ")
        stderr=self.corpus.read("v1/m/00185-962ad7c04c05.bin")
        owner=strict_json_loads(owner_raw)
        if (sha256_bytes(stderr)!=root["wrapper_stderr_sha256"] or wrapper["stderr_sha256"]!=root["wrapper_stderr_sha256"] or
            sha256_bytes(self.corpus.read(path_by_name["wrapper"]))!=root["stop_execution_result_sha256"] or
            b"duplicate" not in stderr.lower() or not all(key in owner for key in root["duplicate_key_pair"][0])):
            raise GraphError("E50 original wrapper/serialized key failure evidence not corroborated")
        stages=[("RECOVERY_REQUEST_ASSOCIATION","request",""),("EXACT_SERIALIZED_OWNER_DECISION","owner",""),
                ("ORIGINAL_POWERSHELL_DUPLICATE_CASE_KEY_FAILURE","root","/powershell_error"),
                ("ORIGINAL_WRAPPER_ABORT","wrapper","/exit_code"),("PKTMON_STOP_NOT_CREATED","wrapper","/pktmon_stop_process_creations"),
                ("RECOVERY_REMAINS_BLOCKED","result","/RESULT")]
        previous=None;receipts=[]
        for label,name,ptr in stages:
            bindings=[self.observed(path_by_name[name],ptr)]
            if name=="root":bindings.append({**self.binding("v1/m/00185-962ad7c04c05.bin"),"byte_digest":True,"value":root["wrapper_stderr_sha256"]})
            event=self.event("E50_"+label,scope,bindings)
            if previous:
                # First request/serialized-decision relationship is association,
                # only the current reading sequence is a structural parent.
                self.link(event,previous)
                if name!="owner":
                    assertions={
                        "root":[("root","/ROOT_CAUSE"),("root","/powershell_error"),("root","/owner_decision_sha256"),("root","/duplicate_key_pair")],
                        "wrapper":[("root","/powershell_error"),("root","/stop_execution_result_sha256"),("wrapper","/exit_code"),("wrapper","/stderr_sha256")],
                        "result":[("result","/RESULT"),("result","/PKTMON_STOP_PROCESS_CREATIONS"),("result","/STOP_ATTEMPT_CONSUMED"),("result","/HOST_CLEARANCE")]
                    }.get(name,[("wrapper","/exit_code"),("wrapper","/owned_helper_invocation_marker"),("wrapper","/pktmon_stop_process_creations")])
                    if label=="PKTMON_STOP_NOT_CREATED":
                        assertions=[("wrapper","/exit_code"),("wrapper","/owned_helper_invocation_marker"),("wrapper","/owned_helper_receipt"),("wrapper","/pktmon_stop_process_creations")]
                    self.link(event,previous,relation="caused_by_ids",kind="EXPLICIT_REFERENCE",
                              assertions=[self.observed(path_by_name[n],p) for n,p in assertions],
                              meaning="attributed original E50 "+label+" from preserved preceding failure; exact corroborating source bindings; not sole-cause proof")
            receipt=self.receipt(event,scope,"E50 "+label);receipts.append(receipt);previous=event
        review=self.review_failure(previous,receipts[-1],scope,"original E50 parser failure and blocked recovery preserved; E49 separate","OWNER_DECISION_CASE_INSENSITIVE_DUPLICATE_KEY","SEPARATE_OWNER_REVIEW_REQUIRED_NO_AUTOMATIC_RETRY")
        self.link(review,previous)
        expected=[]
        for entry in registry["entries"]:
            # Minimal independently auditable original records; exclude huge diagnostics.
            path=paths.get(entry["sha256"])
            if not path:continue
            expected.append(self.source_expected(entry["evidence_id"],self.binding(path)))
        self.terminal("E50",scope,review,receipts,self.observed(path_by_name["result"],"/RESULT"),expected,
                      component_label=self.observed(path_by_name["request"],"/attempt_id"))
    def plan(self):
        return {"schema":"package-g-op1-i4-current-reconstruction-plan@1","source_corpus_manifest_sha256":self.corpus.manifest_sha256,
                "nodes":deepcopy(self.nodes),"causal_rules":deepcopy(self.rules),"closure_policies":deepcopy(self.policies),"cases":deepcopy(self.cases),
                "coverage":"E50 recovery component and E87/E112/E113/E114 RUN reconstructions; E26/E49 source-only context remains distinct",
                "truth_boundary":"Current reconstruction never certifies rejected original causal EVENT graph, changes historical state, or replaces RAW"}

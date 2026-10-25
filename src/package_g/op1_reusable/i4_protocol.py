"""Read-only full I4 verification of an isolated, owner-committed fixed reconstruction."""
from __future__ import annotations
from pathlib import Path
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import canonical_json,strict_json_loads,sha256_bytes,generate_id
from .i4_graph import CausalGraph,SourceCorpus,GraphError,require_dag,CAUSAL
from .i4_source import SourceIndex
from .integrity import IntegrityVerifier
from .checkpoint_custody import root_identity

def read(path):return strict_json_loads(Path(path).read_bytes())
def save(path,value):
    with Path(path).open('xb') as stream:stream.write(canonical_json(value))
def demand(condition,message):
    if not condition:raise GraphError(message)

def verify_full(attempt,owner_attempt,corpus_root,implementation_inventory,worktree):
    attempt,owner_attempt,worktree=Path(attempt),Path(owner_attempt),Path(worktree)
    owner_result=read(owner_attempt/'RESULT.json');start=read(owner_attempt/'START.json')
    demand(owner_result['result']=='PASS_ISOLATED_OWNER_GRAPH_COMMITMENT' and owner_result['source_unchanged'],'owner graph admission was not clean')
    demand(start['implementation']==implementation_inventory,'full run implementation differs from fixed owner-committed implementation')
    profile=read(owner_attempt/'PUBLIC_TRUST.json');root=Path(owner_result['root_path'])
    demand(root_identity(root)==profile['root_identity'] and root_identity(root/'c')==profile['checkpoint_root_identity'],'owner root identity differs')
    baseline=read(owner_attempt/'OWNER_ROOT_IMMUTABLE_INVENTORY.json')
    current=[{'relative_path':p.relative_to(root).as_posix(),'sha256':sha256_bytes(p.read_bytes()),'byte_length':p.stat().st_size} for p in sorted(root.rglob('*')) if p.is_file()]
    demand(current==baseline,'fixed owner/source/control-plane bytes changed')
    custody=read(owner_attempt/'OWNER_CUSTODY_QUALIFICATION.json');candidate=read(owner_attempt/'ISOLATED_WRITER_CANDIDATE.json')
    log=(owner_attempt/'WRITER_LAUNCH_STDOUT.bin').read_text(encoding='utf-8-sig')
    demand(custody['result']=='PASS' and custody['writer_job_active_after']==0 and
           candidate['writer_appcontainer_sid']==profile['writer_appcontainer_sid'] and candidate['writer_capability_count']==0 and
           log.count('JOB_ASSIGNED=1 JOB_ACTIVE_AFTER=0')==1 and log.count('PROCESS_CREATED=PASS CHILD_EXIT=PASS')==1 and
           all(not p['granted'] and p['winerror']==5 for p in custody['effective_access_probes']),'isolated producer custody not demonstrated')
    key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(profile['owner_public_key_hex']))
    genesis=read(owner_attempt/'OWNER_GENESIS.json');key.verify(bytes.fromhex(genesis['signature_hex']),canonical_json(genesis['payload']))
    demand(genesis['payload']['trust_profile_sha256']==sha256_bytes(canonical_json(profile)),'external owner trust genesis differs')
    plan=read(root/'input/PLAN.json');demand(sha256_bytes(canonical_json(plan))==profile['plan_sha256'],'fixed owner plan differs')
    corpus=SourceCorpus.from_path(corpus_root,profile['source_corpus_manifest_sha256']);index=SourceIndex(corpus)
    tip=read(owner_attempt/'I1_TIP.json');integrity=IntegrityVerifier(Path(owner_result['store_path'])).verify(trusted_checkpoint=tip,trusted_checkpoint_public_key_hex=profile['owner_public_key_hex'])
    demand(integrity['result']=='PASS','authoritative I1 store integrity/checkpoint incomplete')
    store_root=Path(owner_result['store_path']);rows=[read(p) for p in sorted((store_root/'manifests').glob('*.json'))]
    graph_raw=tuple((store_root/r['object_relative_path']).read_bytes() for r in rows if r.get('evidence_class')=='I4_APPEND_ONLY_GRAPH_RECORD')
    demand([strict_json_loads(raw) for raw in graph_raw]==read(owner_attempt/'GRAPH_RECORDS.json'),'loose graph export differs from authoritative I1 payloads')
    trusted_tip=read(owner_attempt/'GRAPH_TIP.json')
    graph=CausalGraph.rebuild(corpus,graph_raw,checkpoint_public_key=profile['owner_public_key_hex'],trusted_tip=trusted_tip,
          closure_policies=plan['closure_policies'],causal_rules=plan['causal_rules'],source_index=index)
    demand(graph.fingerprint()==owner_result['semantic_graph_fingerprint'],'owner semantic graph differs')
    require_dag(graph.nodes,graph.edges)
    for edge in graph.edges:
        demand(graph.nodes[edge['target_id']]['sequence']<graph.nodes[edge['source_id']]['sequence'],'forward graph commitment')
        if edge['edge_type'] in CAUSAL:
            source=graph.nodes[edge['source_id']]
            demand(edge['edge_type']+':'+edge['target_id'] in source.get('derivation',{}).get('causal_basis',{}),'unsupported derived causation')
            left,right=CausalGraph.envelope(source),CausalGraph.envelope(graph.nodes[edge['target_id']])
            demand(all(left.get(k)==right.get(k) for k in ('run_id','session_id')),'unpermitted cross-RUN/session reconstruction')
    demand(graph.terminal_completeness()['classification']=='PASS' and len(graph.semantic_view()['closures'])==5,'terminal closure incomplete')
    closure_results={c['terminal_event_id']:c['classification'] for c in graph.semantic_view()['closures']}
    for case,data in plan['cases'].items():
        expected={'AMBIGUOUS':'AMBIGUOUS_CONSUMPTION'}.get(data['historical_outcome'],data['historical_outcome'])
        demand(closure_results[data['terminal_event_id']]==expected,'closure misclassified historical outcome '+case)
    errors=[n for n in graph.nodes.values() if CausalGraph.envelope(n)['entity_type']=='ERROR']
    findings=[n for n in graph.nodes.values() if CausalGraph.envelope(n)['entity_type']=='FINDING']
    decisions=[n for n in graph.nodes.values() if CausalGraph.envelope(n)['entity_type']=='DECISION']
    demand(len(errors)==len(findings)==len(decisions)==2 and all(n['record']['initial_state']=='OPEN' for n in findings),'original failure assessment lost after review')
    demand(all(not n['record']['resolves_finding_ids'] and n['record']['identity'].get('caused_by_ids') for n in decisions),'current review invented repair or omitted causing event')
    observed_labels={n['record'].get('event_kind') for n in graph.nodes.values()}
    for case in ('E87','E112','E113','E114'):
        for stage in ('RUN_RESERVED','OUTER_CLAIM','LAUNCH_INTENT','DISPATCH_ACK','RAW_CAPTURE','OWNERSHIP_RECONCILED','RUN_TERMINAL'):
            demand('I4_CURRENT_RECONSTRUCTION_'+case+'_'+stage+'_CONTROL_OBSERVATION' in observed_labels,'real graph stage missing '+case+' '+stage)
        demand('I4_CURRENT_RECONSTRUCTION_'+case+'_RECORDED_NATIVE_EXECUTION_RESULT' in observed_labels,'native effect source observation missing')
    demand('I4_CURRENT_RECONSTRUCTION_E87_SESSION_QUARANTINED_CONTROL_OBSERVATION' in observed_labels,'ambiguous Session quarantine missing')
    for case in ('E112','E113','E114'):demand('I4_CURRENT_RECONSTRUCTION_'+case+'_SESSION_CONTINUED_CONTROL_OBSERVATION' in observed_labels,'safe recorded Session continuation missing')
    for stage in ('RECOVERY_REQUEST_ASSOCIATION','EXACT_SERIALIZED_OWNER_DECISION','ORIGINAL_POWERSHELL_DUPLICATE_CASE_KEY_FAILURE','ORIGINAL_WRAPPER_ABORT','PKTMON_STOP_NOT_CREATED','RECOVERY_REMAINS_BLOCKED'):
        demand('I4_CURRENT_RECONSTRUCTION_E50_'+stage in observed_labels,'E50 exact source stage missing')
    owner_node=next(n for n in graph.nodes.values() if n['record'].get('event_kind')=='I4_CURRENT_RECONSTRUCTION_E50_EXACT_SERIALIZED_OWNER_DECISION')
    demand(not owner_node['record']['caused_by_ids'],'recovery request association was promoted to historical causal edge')
    rejection=read(owner_attempt/'HISTORICAL_BOUNDARY_REJECTIONS.json')
    demand(rejection['count']==25 and all(r['outcome']=='REJECT_GRAPH' for r in rejection['rejections']),'invalid original source EVENT rejection evidence missing')
    demand(any(r.get('evidence_class')=='I4_REJECTED_GRAPH_PUBLICATION' for r in rows),'rejections were not retained through I1')
    preservation=read(worktree/'reports/engineering/OP1_REUSABLE_I4/I4_PRESERVATION_BASELINE.json')
    baseline_rows=preservation.get('preserved_files',preservation.get('files',preservation.get('source_baseline',[]))) if isinstance(preservation,dict) else preservation
    differences=[]
    for row in baseline_rows:
        path=Path(row.get('absolute_path',row.get('path',str(worktree/row.get('relative_path','')))))
        if sha256_bytes(path.read_bytes())!=row['sha256']:differences.append(str(path))
    demand(baseline_rows and not differences,'I0-I3/protected runtime preservation not proven')
    save(attempt/'PRESERVATION.json',{'result':'PASS','files_verified':len(baseline_rows),'mismatches':differences,'historical_mutation':0,'protected_runtime_files_modified':0})
    # Only fresh derived views are removed. Authoritative records/source stay intact.
    view=attempt/'DERIVED_GRAPH_VIEW.json';save(view,graph.semantic_view());view_digest=sha256_bytes(view.read_bytes());view.unlink()
    rebuilt=CausalGraph.rebuild(corpus,graph_raw,checkpoint_public_key=profile['owner_public_key_hex'],trusted_tip=trusted_tip,
          closure_policies=plan['closure_policies'],causal_rules=plan['causal_rules'],source_index=index)
    save(view,rebuilt.semantic_view());demand(sha256_bytes(view.read_bytes())==view_digest and rebuilt.fingerprint()==graph.fingerprint(),'derived rebuild not deterministic')
    # Explicit full-run rejection receipts. Rejections never mutate the committed graph.
    adversaries=[]
    def rejected(label,probe,fn,outcome='REJECT_GRAPH'):
        before=probe.records
        try:fn()
        except GraphError as exc:
            demand(exc.outcome==outcome,label+' returned incorrect classification')
            demand(probe.records==before,label+' mutated graph history')
            adversaries.append({'case':label,'expected':outcome,'observed':exc.outcome,'reason':str(exc),'history_unchanged':True})
        else:raise GraphError(label+' unexpectedly accepted')
    for length in (1,2,20):
        edges=[{'edge_type':'caused_by_ids','source_id':str(i),'target_id':str((i+1)%length)} for i in range(length)]
        rejected('ADV-12-cycle-'+str(length),graph,lambda edges=edges,length=length:require_dag({str(i):{} for i in range(length)},edges))
    base=next(n for n in graph.nodes.values() if n['record'].get('event_role')=='OBSERVATION')
    def mutant():
        node=deepcopy(base);entity=generate_id('EVENT');node['record']['event_id']=node['record']['identity']['entity_id']=entity
        node['record']['parent_ids']=[];node['record']['caused_by_ids']=[];return node
    forged=mutant();forged['record']['parent_ids']=[{'entity_type':'EVENT','entity_id':generate_id('EVENT')}]
    rejected('ADV-13-forged-parent',graph,lambda:graph.append(forged))
    missing_actor=mutant();missing_actor['record']['identity'].pop('actor_id')
    rejected('ADV-14-missing-actor',graph,lambda:graph.append(missing_actor),'REJECT_RECORD')
    for field,kind in (('run_id','RUN'),('session_id','SESSION')):
        crossed=mutant();crossed['record'][field]=crossed['record']['identity'][field]=generate_id(kind)
        crossed['record']['parent_ids']=[{'entity_type':'EVENT','entity_id':base['record']['event_id']}]
        rejected('ADV-26-cross-'+field,graph,lambda crossed=crossed:graph.append(crossed))
    no_closures=tuple(raw for raw in graph_raw if strict_json_loads(raw)['kind']!='CLOSURE')
    incomplete=CausalGraph.rebuild(corpus,no_closures,checkpoint_public_key=profile['owner_public_key_hex'],closure_policies=plan['closure_policies'],causal_rules=plan['causal_rules'],source_index=index)
    demand(incomplete.terminal_completeness()['classification']=='INCOMPLETE_EVIDENCE','ADV-23 missing closure misclassified')
    adversaries.append({'case':'ADV-23','expected':'INCOMPLETE_EVIDENCE','observed':'INCOMPLETE_EVIDENCE','history_unchanged':True})
    changed=deepcopy(plan['closure_policies']);case=plan['cases']['E112'];terminal=case['terminal_event_id'];changed[terminal]['required_evidence_classes'].append('REQUIRED_CLASS_ABSENT_ADVERSARIAL')
    class_probe=CausalGraph.rebuild(corpus,no_closures,checkpoint_public_key=profile['owner_public_key_hex'],closure_policies=changed,causal_rules=plan['causal_rules'],source_index=index)
    closure=next(strict_json_loads(raw) for raw in graph_raw if strict_json_loads(raw).get('terminal_event_id')==terminal)
    closure['required_evidence_classes']=changed[terminal]['required_evidence_classes']
    rejected('ADV-27-valid-hash-missing-class',class_probe,lambda:class_probe.append(closure,checkpoint_public_key=profile['owner_public_key_hex']),'INCOMPLETE_EVIDENCE')
    rejected('signed-tip-valid-prefix-rollback',incomplete,lambda:incomplete.verify_tip(trusted_tip,profile['owner_public_key_hex']),'INCOMPLETE_EVIDENCE')
    save(attempt/'FULL_ADVERSARIAL_REJECTIONS.json',adversaries)
    save(attempt/'FULL_SOURCE_RECONCILIATION.json',{'source_corpus_manifest_sha256':corpus.manifest_sha256,'source_signatures_verified':len(index.commitments),
         'source_declared_unadmitted_cross_run_edges':25,'source_declared_unadmitted_cross_session_edges':13,'reconstruction_nodes':len(graph.nodes),'reconstruction_edges':len(graph.edges),
         'closure_registry':'VERIFIED_SOURCE_COMMITMENTS; original evidence identities remain source commitments, not admitted dangling graph nodes',
         'RAW_availability':'Embedded members rehashed; omitted native archives rely on exact accepted I3 archived-byte verification bindings; graphs never replace RAW'})
    result={name:'PASS' for name in ('CAUSAL_DAG_VALIDATION','PARENT_COMMITMENT_VALIDATION','SOURCE_CLOSURE','FAILURE_PRESERVATION','REPAIR_DECISION_RETAINS_ORIGINAL_FAILURE',
        'TERMINAL_CLOSURE','REAL_EVIDENCE_GRAPH_A','REAL_EVIDENCE_GRAPH_B','REAL_EVIDENCE_GRAPH_C','CROSS_RUN_VALIDATION','ADV_12','ADV_13','ADV_14','ADV_23','ADV_26','ADV_27',
        'INVALID_GRAPH_MATRIX','REBUILDABLE_VIEWS','DETERMINISTIC_GRAPH_REBUILD','I1_GRAPH_INTEGRATION','I2_HISTORY_PRESERVED','I3_HISTORY_PRESERVED')}
    result.update(result='PASS',UNSUPPORTED_CAUSATION=0,HISTORICAL_MUTATION=0,PROTECTED_RUNTIME_FILES_MODIFIED=0,SEMANTIC_GRAPH_FINGERPRINT=graph.fingerprint(),
                  source_corpus_manifest_sha256=corpus.manifest_sha256,owner_attempt=str(owner_attempt),owner_root_inventory_sha256=sha256_bytes(canonical_json(baseline)),
                  implementation_sha256=sha256_bytes(canonical_json(implementation_inventory)),native_cases_executed=0,physical_c2_executed=False,i5_started=False,i6_started=False)
    save(attempt/'FULL_I4_PROTOCOL_RESULT.json',result);return result

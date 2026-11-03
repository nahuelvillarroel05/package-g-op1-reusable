"""Build conservative aggregate readiness from historical and current evidence."""
import hashlib,json,shutil
from pathlib import Path
W=Path(__file__).resolve().parent;ROOT=W.parents[1];R=ROOT/'Engineering/Active_Candidate/repo';P=R/'experiments/runs/run-004';OLD=ROOT/'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001'
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def bind(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
def put(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def main():
    rows=[]
    counts={'BFCL':{'tasks':4696},'SWE-bench':{'memberships':3642,'distinct_tasks':2819},'MCPMark':{'tasks':127,'logical_results':762,'trajectory_files':759},'Terminal-Bench':{'tasks':89,'published_trials':445},'SWE-bench Pro':{'tasks':642},'tau2-bench':{'base_tasks':150,'localized_variants':900}}
    reports={'BFCL':'bfcl/BFCL_EVALUATOR_DEPENDENCY_REPORT.md','SWE-bench':'swebench/SWE_OFFICIAL_EVALUATION_READINESS.md','MCPMark':'MCPMARK_VERIFIER_READINESS.md','Terminal-Bench':'TERMINAL_HARBOR_READINESS.md','SWE-bench Pro':'swebench_pro/SWEBENCH_PRO_V2_SOURCE_STATUS.json','tau2-bench':'TAU2_EVALUATOR_READINESS.md'}
    for f in load(OLD/'RUN004_EXECUTION_READINESS_BY_FAMILY.json')['families']:
        row={'BENCHMARK':f['BENCHMARK'],'POPULATION':counts[f['BENCHMARK']]}
        mapping={'CORPUS_READY':'TASK_POPULATION_READY','AUTHENTIC_OUTPUT_READY':'AUTHENTIC_OUTPUTS_AVAILABLE','SOURCE_BINDING_READY':'SOURCE_BINDINGS_VERIFIED','PGOP1_OFFLINE_AUDIT_READY':'PGOP1_AUDIT_READY','OFFICIAL_EVALUATOR_READY':'OFFICIAL_EVALUATOR_READY','OFFICIAL_RUNTIME_READY':'ISOLATED_RUNTIME_AVAILABLE','RECOVERY_READY':'RECOVERY_READY','CONTAMINATION_REVIEWED':'CONTAMINATION_REVIEWED','FULL_CAMPAIGN_READY':'CAMPAIGN_READY'}
        row.update({a:f[b] for a,b in mapping.items()})
        report=W/reports[f['BENCHMARK']]
        row.update({'CURRENT_REPORT':bind(report) if report.exists() else {'path':str(report),'status':'PENDING_AGENT_REPORT'},'PREVIOUS_EVIDENCE':f['EVIDENCE'],'BASELINE_BLOCKERS':f['MISSING_DEPENDENCIES'],'OFFLINE_SCOPE':'Development only; no compatible full semantic coverage inferred','RECOVERY_SCOPE':'Two existing shards/1127 descriptors freshly sampled; complete per-family source-body recovery not repeated','READINESS_SCOPE':'Full selected-version family, not successful bounded component scoring'})
        rows.append(row)
    data={'schema':'pgop1.run004.readiness.v3','status':'BLOCKED_FOR_FULL_CAMPAIGN','RUN004_CONTRACT':'NOT_APPROVED','RUN004_FINAL_FREEZE':'NOT_ISSUED','RUN004_EXECUTION':'NOT_EXECUTED','contract_revision':'pgop1.run004.multibenchmark.contract.rev003','families':rows,'ready_families':0,'no_quota_cap':True,'completion_requires_modalities':['OFFLINE_EVIDENCE_AUDIT','OFFICIAL_EVALUATOR_EXECUTION'],'owner_approval':'NOT_ISSUED','limitations':'Inherited corpus readiness is not a fresh corpus reprocess. Consult current report for bounded evaluator progress; full readiness remains blocked.'}
    put(W/'RUN004_READINESS_MATRIX.json',data);put(W/'contract/RUN004_READINESS_MATRIX.json',data)
    target=P/'RUN004_READINESS_MATRIX.json';pre=W/'preimages/Engineering/Active_Candidate/repo/experiments/runs/run-004/RUN004_READINESS_MATRIX.json'
    if not pre.exists():shutil.copyfile(target,pre)
    put(target,data)
    dep=load(OLD/'BENCHMARK_EXECUTION_DEPENDENCY_MATRIX.json');modes=[]
    for f in rows:
        fam=f['BENCHMARK'];prior=[x for x in dep['rows'] if x['BENCHMARK']==fam]
        for mode in ['OFFLINE_EVIDENCE_AUDIT','OFFICIAL_ARCHIVED_RESULT_REPLAY','OFFICIAL_RESULT_REGRADE','OFFICIAL_ORACLE_VALIDATION','OFFICIAL_FRESH_TASK_EXECUTION','FULL_AGENT_BENCHMARK_EXECUTION']:
            oldmode='OFFLINE_EVIDENCE_AUDIT' if mode=='OFFLINE_EVIDENCE_AUDIT' else 'FULL_AGENT_BENCHMARK' if mode=='FULL_AGENT_BENCHMARK_EXECUTION' else 'OFFICIAL_TASK_EXECUTION' if mode in ['OFFICIAL_FRESH_TASK_EXECUTION','OFFICIAL_ORACLE_VALIDATION'] else 'OFFICIAL_RESULT_REGRADE'
            src=next(x for x in prior if x['EVALUATION_MODE']==oldmode)
            judges=src['LLM_JUDGE_REQUIRED']
            if fam=='tau2-bench':
                judges='COMMUNICATE_SEMANTIC_AND_NL_ASSERTION_WHEN_APPLICABLE; STATE_ACTION_MECHANICAL_SEPARATE'
                if mode=='OFFLINE_EVIDENCE_AUDIT':judges='NOT_FOR_STRUCTURAL_AUDIT; SEMANTIC_COMMUNICATE_OR_NL_REQUIRE_BOUND_JUDGE_OUTPUTS'
            modes.append({'BENCHMARK':fam,'EVALUATION_MODE':mode,'DOCKER_REQUIRED':src['DOCKER_REQUIRED'],'ISOLATION_REQUIRED':src['OTHER_ISOLATION_REQUIRED'],'MODEL_REQUIRED':src['MODEL_EXECUTION_REQUIRED'],'LLM_JUDGE_REQUIRED':judges,'OFFLINE_FEASIBLE':'PARTIAL' if mode=='OFFLINE_EVIDENCE_AUDIT' and f['PGOP1_OFFLINE_AUDIT_READY']=='PARTIAL' else 'CONDITIONAL_ON_EXACT_INPUT_AND_COMPONENT','OFFICIAL_EVALUATOR_AVAILABLE':'PARTIAL_PINNED_COMPONENTS; SEE_CURRENT_REPORT','RUNTIME_AVAILABLE':'BLOCKED_FOR_FULL_MODE','EXECUTION_READY':'BLOCKED_FOR_FULL_MODE','SOURCE':f['CURRENT_REPORT'],'interpretation':'Mode requirement is category/procedure dependent; static reading is not official replay; oracle never agent performance'})
    evaluators={'schema':'pgop1.run004.evaluator-readiness.v3','scope':'Full-family requirements, distinct from bounded component executions','families':rows,'modes':modes,'official_execution_results':'AUTHENTIC_EVALUATION_RECEIPTS.json','source_matrix':bind(OLD/'BENCHMARK_EXECUTION_DEPENDENCY_MATRIX.json')}
    put(W/'SIX_FAMILY_EVALUATOR_READINESS.json',evaluators)
    pre=W/'preimages/Engineering/Active_Candidate/repo/experiments/runs/run-004/RUN004_EVALUATOR_MANIFEST.json'
    if not pre.exists():shutil.copyfile(P/'RUN004_EVALUATOR_MANIFEST.json',pre)
    put(P/'RUN004_EVALUATOR_MANIFEST.json',evaluators);put(W/'contract/RUN004_EVALUATOR_MANIFEST.json',evaluators)
    print(json.dumps({'families':len(rows),'modes':len(modes),'full_ready':0}))
if __name__=='__main__':main()

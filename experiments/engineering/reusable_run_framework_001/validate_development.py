"""Explicit local development validation, using only freshly authored fixtures.

This driver creates two independent synthetic configurations and calls the same
framework/adapter APIs. It never reads original benchmark populations. It is not
a campaign dispatcher. Run only under separately authorized engineering scope.
"""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, datetime

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO))
from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark.core import recover
from runtime.candidate.run_adapter_bridge import process_authored_unit, family_operations
from runtime.candidate.run_framework import load_config

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,data):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    raw=data.encode('utf-8') if isinstance(data,str) else json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    with p.open('xb') as f:f.write(raw)
def git(*args):
    return subprocess.check_output(['git','-c','safe.directory='+REPO.as_posix(),'-C',str(REPO),*args],text=True).strip()
def ref(p):return {'path':str(Path(p).resolve()),'sha256':sha(p)}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def fixtures(root,variant):
    revision='a'*40
    cases=[]
    def add(family,version,path,task):cases.append({'family':family,'version':version,'revision':revision,'source_path':str(path),'task_id':task,'unit_id':family+':'+str(len(cases))})
    swe=root/'swe.json';write(swe,[{'instance_id':'authored-swe-'+variant,'repo':'example/authored','base_commit':revision,'patch':'inert authored patch','test_patch':'inert authored test patch','problem_statement':'Synthetic development fixture.'}])
    add('swebench','full',swe,'authored-swe-'+variant)
    bfcl=root/'BFCL_v4_simple_python.json';write(bfcl,[{'id':'simple_python_authored_'+variant,'question':[[{'role':'user','content':'Authored synthetic fixture.'}]],'function':[]}])
    add('bfcl_v4','V4',bfcl,'simple_python_authored_'+variant)
    if variant=='B':
        # A declared malformed source tests durable error dispositions. It is
        # not silently dropped from this independent development denominator.
        bad=root/'bad'/'BFCL_v4_simple_python.json';write(bad,[{'id':'simple_python_bad_B','question':[],'function':[]}])
        add('bfcl_v4','V4',bad,'simple_python_bad_B')
        return cases
    pro=root/'pro'/'instance_authored_A';write(pro/'task.toml','schema_version = "1.0"\n[task]\nname = "swebench-pro/instance_authored_A"\n');write(pro/'instruction.md','Authored synthetic fixture.\n')
    add('swebench_pro_v2','V2',pro/'instruction.md','instance_authored_A')
    term=root/'terminal'/'authored-terminal';write(term/'task.toml','schema_version = "1.0"\n[task]\nname = "terminal-bench/authored-terminal"\nkeywords = ["authored"]\n[metadata]\ncategory = "synthetic"\n');write(term/'instruction.md','Authored fixture\n');write(term/'tests/test.sh','# inert authored fixture\n');write(term/'tests/test_fixture.py','# inert authored fixture\n')
    add('terminal_bench_2','2.0',term/'task.toml','authored-terminal')
    mcp=root/'mcp/tasks/authored/standard/synthetic/authored-task';write(mcp/'meta.json',{'task_id':'authored-task','category_id':'synthetic','mcp':['authored'],'tags':['synthetic']});write(mcp/'description.md','Authored fixture\n');write(mcp/'verify.py','# inert authored fixture\n')
    add('mcpmark_verified','Verified@'+revision[:12],mcp/'meta.json','authored/standard/synthetic/authored-task')
    tau=root/'tau/retail/tasks.json';write(tau,[{'id':'authored_A','user_scenario':{'instructions':{'domain':'retail','reason_for_call':'Authored fixture.'}},'evaluation_criteria':{'actions':[]}}])
    add('tau_bench','2.0.0:text-v1',tau,'tau2:retail:authored_A')
    return cases

def prepare(root):
    root=Path(root).resolve();root.mkdir(exist_ok=False)
    configs=[]
    code=[p for p in (REPO/'runtime/candidate/run_framework').glob('*.py')]
    code += [REPO/'runtime/candidate'/n for n in ['run_adapter_bridge.py','context_engine.py','multibenchmark/core.py','multibenchmark/software.py','multibenchmark/operations.py','multibenchmark/calling.py']]
    # Bind the existing frozen dependency closure, without modifying it.
    code += [p for p in (REPO/'runtime/candidate/deps/i4_i5').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    for variant in ['A','B']:
        work=root/variant;source=work/'sources';source.mkdir(parents=True)
        cases=fixtures(source,variant)
        sources=[ref(p) for p in sorted(source.rglob('*')) if p.is_file()]
        write(work/'dataset.json',{'sources':sources,'cases':cases,'origin':'FRESH_AUTHORED_DEVELOPMENT_ONLY'})
        write(work/'selection.json',{'expected_units':[x['unit_id'] for x in cases]})
        write(work/'contract.json',{'id':'authored-development-'+variant,'semantics':'TASK_DEFINITION_ONLY','external_actions_authorized':False})
        write(work/'adapters.json',family_operations())
        write(work/'predicates.json',{'structural_task_binding':'v1','agent_semantics':'UNSUPPORTED_NO_AUTHENTIC_OUTPUT','custom_metric_contract':'development-'+variant})
        write(work/'exclusions.json',{'original_benchmark_cases':'ALL_EXCLUDED','reserved_evidence_accessed':False})
        config={'schema':'pgop1.experimental.run-execution.v1','campaign_id':'framework-development-'+variant,
                'run_id':'framework-development-'+variant,'campaign_attempt_id':'attempt-0001',
                'contract_version':'authored-development-'+variant,'run_purpose':'Bounded independent framework development validation',
                'candidate_commit':git('rev-parse','HEAD'),'candidate_tree':git('rev-parse','HEAD^{tree}'),
                'code_root':str(REPO),'code_files':[ref(p) for p in code],
                'contract_path':str(work/'contract.json'),'contract_sha256':sha(work/'contract.json'),
                'dataset_manifest_path':str(work/'dataset.json'),'input_manifest_sha256':sha(work/'dataset.json'),
                'input_bindings':sources,'benchmark_families':sorted({x['family'] for x in cases}),
                'adapter_registry':ref(work/'adapters.json'),'predicate_contracts':ref(work/'predicates.json'),
                'execution_modes':['AUTHORED_DEVELOPMENT_TASK_INGESTION_ONLY'],
                'selection_manifest':ref(work/'selection.json'),'exclusion_ledger':ref(work/'exclusions.json'),
                'resource_budget':{'max_units_per_shard':2 if variant=='A' else 1,'max_source_bytes':100000 if variant=='A' else 50000},
                'stop_criteria':{'unexpected_external_call':'STOP','on_processing_error':'PRESERVE_DISPOSITION'},
                'checkpoint_policy':{'interval':1},'recovery_policy':{'mode':'READ_ONLY_NO_RESUME'},
                'audit_policy':{'execution_completeness':'NOT_CERTIFIED','source_origin':'AUTHORED_ONLY'},
                'allowlisted_roots':[str(REPO),str(work)],'expected_units':[x['unit_id'] for x in cases]}
        write(work/'config.json',config);configs.append(work/'config.json')
    return configs

def execute_development(config,root):
    config=Path(config);cfg=json.loads(config.read_text(encoding='utf-8'));work=config.parent
    outputs=work/'outputs';outputs.mkdir()
    out=outputs/cfg['run_id']/'attempts'/cfg['campaign_attempt_id']
    campaign=load_config(config,[work],out,[REPO,work],[outputs])
    write(work/'PREFLIGHT.json',campaign.preflight());write(work/'SHARD_PLAN.json',campaign.shard_plan())
    dataset=json.loads((work/'dataset.json').read_text(encoding='utf-8'));commitments={x['path']:x['sha256'] for x in dataset['sources']}
    records=[]
    for item in dataset['cases']:
        started=now();campaign.begin_unit(item['unit_id'],{'started_at':started,'producer_pid':os.getpid(),'source':ref(item['source_path']),'origin':'AUTHORED_DEVELOPMENT'})
        engine_root=work/'contexts'/item['unit_id'].replace(':','-')
        try:
            result=process_authored_unit(Engine(engine_root),**{k:item[k] for k in ['family','version','revision','source_path','task_id']},source_sha256=sha(item['source_path']),allowed_roots=[work/'sources'],source_commitments=commitments)
            state='TASK_DEFINITION_STORED'
        except ValueError as error:
            result={'error_type':type(error).__name__,'error':str(error),'semantic_status':'UNKNOWN','evaluator_status':'NOT_RUN'};state='PROCESSING_ERROR'
        record={'unit_id':item['unit_id'],'family':item['family'],'started_at':started,'finished_at':now(),'producer_pid':os.getpid(),'state':state,'source':ref(item['source_path']),'result':result,'engine_root':str(engine_root)}
        record_path=work/'results'/(item['unit_id'].replace(':','-')+'.json');write(record_path,record)
        campaign.complete_unit(item['unit_id'],state,{'result_manifest':ref(record_path),'source':ref(item['source_path']),'started_at':started,'finished_at':record['finished_at'],'semantic_status':'UNKNOWN'})
        records.append(record)
    write(work/'REPORT.json',campaign.report())
    before={str(p):sha(p) for p in out.rglob('*') if p.is_file()}
    command=[sys.executable,'-B','-m','runtime.candidate.run_framework','recover','--config',str(config),'--config-root',str(work),'--trusted-root',str(REPO),'--trusted-root',str(work),'--output-root',str(outputs),'--output',str(out)]
    child=subprocess.run(command,cwd=REPO,capture_output=True,text=True,check=True)
    recovered=json.loads(child.stdout)
    assert len(recovered['completed'])==len(dataset['cases']) and not recovered['pending'] and not recovered['inflight']
    assert before=={str(p):sha(p) for p in out.rglob('*') if p.is_file()}
    # Separate fresh process verifies the existing Engine receipts for every
    # successful descriptor, preserving opaque family semantics and no dispatch.
    engine_code="import json,sys;from runtime.candidate.context_engine import Engine;from runtime.candidate.multibenchmark.core import recover;d=json.load(open(sys.argv[1],encoding='utf-8'));n=0\nfor x in d:\n if x['state']=='TASK_DEFINITION_STORED':\n  y=recover(Engine(x['engine_root']),x['result']['receipt']);assert y['audit_verdict']=='NOT_EVALUATED';n+=1\nprint(json.dumps({'recovered':n,'pid':__import__('os').getpid()}))"
    write(work/'ALL_RESULTS.json',records)
    engine_child=subprocess.run([sys.executable,'-B','-c',engine_code,str(work/'ALL_RESULTS.json')],cwd=REPO,capture_output=True,text=True,check=True)
    summary={'configuration':ref(config),'framework_recovery':recovered,'engine_recovery':json.loads(engine_child.stdout),'producer_pid':os.getpid(),'recovery_process_distinct':True,'framework_bytes_unchanged':True,'redispatches':0,'processing_errors':sum(x['state']=='PROCESSING_ERROR' for x in records),'semantic_claims':0,'RUN004_EXECUTION':'NOT_EXECUTED'}
    write(work/'FRESH_PROCESS_RECOVERY.json',summary)
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);args=parser.parse_args()
    root=Path(args.output).resolve();configs=prepare(root)
    hashes={str(p):sha(p) for p in (REPO/'runtime/candidate/run_framework').glob('*.py')}
    results=[execute_development(c,root) for c in configs]
    assert hashes=={str(p):sha(p) for p in (REPO/'runtime/candidate/run_framework').glob('*.py')}
    write(root/'TWO_CONFIGURATION_REUSE_TEST.json',{'status':'PASS_BOUNDED_DEVELOPMENT','same_framework_sha256':hashes,'results':results,'scope':'six families/six units A; two families/three units B including one preserved malformed-unit error; no original benchmark task/evaluator/agent/RUN004'})
    print(json.dumps({'status':'PASS_BOUNDED_DEVELOPMENT','output':str(root)}))

"""Owner-authorized engineering campaign; never formal RUN-002 or a holdout.

The plan reuses RUN-001's source identities and commitments. Outputs stay in a
new excluded workspace; the historical plan, results and sources are immutable.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from runtime.candidate.swebench_claim_audit.campaign import run_campaign, POST_SONNET_CAMPAIGN
from runtime.candidate.swebench_claim_audit.bind_campaign import bind_campaign
from runtime.candidate.swebench_claim_audit.adapter import _safe_path
from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit, recover_generalized_audit
from runtime.candidate.context_engine import Engine, canonical_json

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def save(path,value):
    raw=(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode('utf-8')
    if path.exists() and path.read_bytes()!=raw:
        raise RuntimeError('IMMUTABLE_OUTPUT_CONFLICT:'+path.name)
    path.parent.mkdir(parents=True,exist_ok=True)
    if not path.exists():
        path.write_bytes(raw)

def memory_available():
    from ctypes import wintypes
    class Status(ctypes.Structure):
        _fields_=[('length',wintypes.DWORD),('load',wintypes.DWORD)]+[
            (name,ctypes.c_ulonglong) for name in ('total','available','page_total',
            'page_available','virtual_total','virtual_available','extended')]
    status=Status(); status.length=ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise RuntimeError('MEMORY_PREFLIGHT_UNAVAILABLE')
    return status.available

def prepare(data,workspace):
    history=data/'Engineering'/'PGOP1_RUN_001'
    old=json.loads((history/'FINAL_PLAN_002.json').read_bytes())
    supplemental=json.loads((history/'SUPPLEMENTAL_VALIDATION_PLAN_001.json').read_bytes())
    inventory=json.loads((history/'INPUT_INVENTORY.json').read_bytes())
    listing=history/'frozen_input_listing.jsonl'
    if digest(listing)!=inventory['frozen_listing_sha256'] or len(inventory['files'])!=25580:
        raise RuntimeError('SNAPSHOT_IDENTITY_MISMATCH')
    plan=json.loads(json.dumps(old))
    identities={s['path']:s for s in plan['sources']}
    for source in supplemental['sources']:
        if source['path'] in identities:
            if source!=identities[source['path']]:
                raise RuntimeError('BASELINE_SOURCE_CONFLICT')
        else:
            plan['sources'].append(source)
            identities[source['path']]=source
    if len(plan['sources'])!=3802:
        raise RuntimeError('BASELINE_PROCESSING_UNIVERSE_MISMATCH')
    plan['campaign_id']=POST_SONNET_CAMPAIGN
    plan['discovery_profile']='local-archive-layout.post-sonnet.v1'
    plan['excluded_output_subtrees']=[workspace.relative_to(data).as_posix()]
    upgrades=0
    for source in plan['sources']:
        if source['parser_id']=='pgop1.swebench.trajectory.aider_markdown.unsupported.v1':
            source['parser_id']='pgop1.swebench.trajectory.aider_markdown_unattributed.v1'
            upgrades+=1
    # Requests retain the exact source joins from the historical snapshot.
    by_path={r['path']:r for r in plan['sources']}
    for request in plan['requests']:
        request['evidence']=[dict(by_path[r['path']]) for r in request['evidence']]
    changed=[]; total_bytes=0
    for source in plan['sources']:
        path=_safe_path(data,source['path'])
        # Preserve the Engine's before-read exclusion wall, including GOLD and secrets.
        if any(p.casefold() in {'.aws','gold','gold20','holdout','secrets','.ssh'} for p in path.parts):
            raise RuntimeError('EXCLUDED_SOURCE_IN_PLAN')
        if not path.is_file() or path.stat().st_size!=source['bytes'] or digest(path)!=source['sha256']:
            changed.append(source['source_id'])
        total_bytes+=source['bytes']
    free=shutil.disk_usage(workspace).free
    available=memory_available()
    report=dict(schema='pgop1.post-sonnet.preflight.v1',source_files_in_snapshot=25580,
        planned_sources=len(plan['sources']),execution_requests=len(plan['requests']),
        upgraded_aider_sources=upgrades,source_bytes=total_bytes,source_mismatches=changed,
        disk_free_bytes=free,memory_available_bytes=available,
        disk_reserve_bytes=70000000000,memory_minimum_bytes=4000000000,concurrency=1,
        frozen_inventory_sha256=digest(history/'INPUT_INVENTORY.json'),listing_sha256=digest(listing),
        baseline_plan_sha256=digest(history/'FINAL_PLAN_002.json'),
        supplemental_plan_sha256=digest(history/'SUPPLEMENTAL_VALIDATION_PLAN_001.json'),
        inaccessible_historical_directories=25,
        status='PASS' if not changed and free>70000000000 and available>4000000000 else 'BLOCKED')
    save(workspace/'full-engineering-run'/'PREFLIGHT_V2.json',report)
    save(workspace/'full-engineering-run'/'PLAN_PREPARED_V2.json',plan)
    print(json.dumps(report))
    return plan,report

def execute(data,workspace,review_path):
    out=workspace/'full-engineering-run'
    plan=json.loads((out/'PLAN_PREPARED_V2.json').read_bytes())
    review=json.loads(review_path.read_bytes())
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    if review.get('candidate_commit')!=head or review.get('decision') not in {
            'PASS_WITH_EXACT_SCOPE','PASS_WITH_NONMATERIAL_LIMITATIONS'} or review.get('effective_model')!='gpt-6-astra':
        raise RuntimeError('EXACT_ASTRA_REVIEW_REQUIRED')
    if subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True).strip():
        raise RuntimeError('CANDIDATE_NOT_FROZEN')
    paths=subprocess.check_output(['git','ls-files','runtime/candidate'],cwd=REPO,text=True).splitlines()
    plan['code_commit']=head
    plan['code_sha256']={p:digest(REPO/p) for p in paths}
    plan['independent_review']=dict(decision=review['decision'],candidate_commit=head,
        model=review['effective_model'],audit_sha256=digest(review_path))
    save(out/'EXECUTION_MANIFEST.json',plan)
    result=run_campaign(data,plan,out/'campaign',resume=(out/'campaign'/'binding.json').exists())
    record_campaign_execution(out,result)
    context=bind_campaign(data,plan,out/'campaign',out/'context')
    save(out/'CONTEXT_EXECUTION.json',context)
    derivation=verify_instance_derivations(data,out)
    print(json.dumps(dict(campaign=result,context_units=context['units'])))
    if derivation['failures']:
        raise RuntimeError('INSTANCE_DERIVATION_FAILURES_PRESERVED')

def record_campaign_execution(out,result):
    primary=out/'CAMPAIGN_EXECUTION.json'
    if primary.exists():
        previous=json.loads(primary.read_bytes())
        if any(previous.get(key)!=result.get(key) for key in (
                'campaign_id','code_commit','plan_sha256','files','audits','status')):
            raise RuntimeError('CAMPAIGN_EXECUTION_IDENTITY_CHANGED')
        # Resume has different executed/recovered counters; preserve the initial
        # receipt and append a content-addressed recovery receipt for this state.
        key=hashlib.sha256(canonical_json(result)).hexdigest()[:16]
        save(out/('CAMPAIGN_RECOVERY_'+key+'.json'),result)
    else:
        save(primary,result)

def verify_instance_derivations(data,out):
    """Separate instance-semantic checks from the storage aggregate's PASS."""
    journal=[json.loads(line) for line in (out/'campaign'/'attempts.jsonl').read_bytes().splitlines()]
    parent=out/'instance-derivation'; parent.mkdir(exist_ok=True)
    rows=[]
    for event in journal:
        if event['event']!='COMPLETE' or not event['unit'].startswith('audit-'):continue
        result_path=out/'campaign'/event['result_path']
        if digest(result_path)!=event['sha256']:raise RuntimeError('AUDIT_RESULT_CHANGED')
        audit=json.loads(result_path.read_bytes())
        receipt_path=parent/(event['unit']+'-verification.json')
        context=parent/event['unit']
        if receipt_path.exists():
            saved=json.loads(receipt_path.read_bytes())
            if saved['audit_result_sha256']!=event['sha256']:raise RuntimeError('DERIVATION_INPUT_CHANGED')
            if saved['status']=='DERIVATION_VERIFIED':
                fresh=recover_generalized_audit(context)
                if fresh['derivation']['status']!='DERIVATION_VERIFIED':raise RuntimeError('DERIVATION_RECOVERY_FAILED')
                verify_campaign_capsule(context,audit,fresh)
            elif saved['status']=='DERIVATION_NOT_VERIFIED':
                if not error_without_references(audit):raise RuntimeError('UNVERIFIABLE_NONERROR_AUDIT')
            rows.append(saved); continue
        if context.exists():raise RuntimeError('AMBIGUOUS_DERIVATION_CONTEXT_NO_REDISPATCH')
        row=dict(unit=event['unit'],audit_result_sha256=event['sha256'])
        if not audit.get('SOURCE_PROVENANCE',{}).get('evidence_references'):
            if error_without_references(audit):
                row.update(status='DERIVATION_NOT_VERIFIED',reason='ERROR_AUDIT_WITHOUT_ADMITTED_REFERENCES',
                           final_error=audit.get('FINAL_ERROR'),audit_verdict=audit.get('AUDIT_VERDICT'))
            else:
                row.update(status='FAILED',error_code='UNVERIFIABLE_NONERROR_AUDIT')
        else:
            try:
                bound=bind_generalized_audit(audit,data,context)
                recovered=recover_generalized_audit(context)
                if recovered['derivation']['status']!='DERIVATION_VERIFIED':
                    raise RuntimeError('INSTANCE_DERIVATION_NOT_VERIFIED')
                verify_campaign_capsule(context,audit,recovered)
                row.update(status=recovered['derivation']['status'],binding=bound,recovery=recovered)
            except Exception as exc:
                row.update(status='FAILED',error_type=type(exc).__name__,
                           error_code=getattr(exc,'code','UNEXPECTED_DERIVATION_ERROR'))
        save(receipt_path,row); rows.append(row)
    summary=dict(schema='pgop1.post-sonnet.instance-derivation.v1',audits=len(rows),
        verified=sum(r['status']=='DERIVATION_VERIFIED' for r in rows),
        not_verified=sum(r['status']=='DERIVATION_NOT_VERIFIED' for r in rows),
        failures=sum(r['status']=='FAILED' for r in rows),results=[{
            k:v for k,v in row.items() if k not in {'binding','recovery'}} for row in rows])
    save(out/'DERIVATION_VERIFICATION.json',summary)
    return summary

def error_without_references(audit):
    return (audit.get('FINAL_ERROR') is not None and audit.get('AUDIT_VERDICT') in {
        'INTEGRITY_FAILURE','VERIFICATION_ERROR','INSUFFICIENT_EVIDENCE'}
        and not audit.get('AGENT_STATEMENT')
        and not audit.get('SOURCE_PROVENANCE',{}).get('evidence_references'))

def verify_campaign_capsule(context,audit,recovery):
    receipt=json.loads((context/'generalized-bridge-receipt.json').read_bytes())
    raw=Engine(context).read_source(receipt['capsule']['source_id'])
    if hashlib.sha256(raw).hexdigest()!=recovery['capsule_sha256']:
        raise RuntimeError('DERIVATION_CAPSULE_COMMITMENT_MISMATCH')
    capsule=json.loads(raw)
    if canonical_json(capsule['audit_result'])!=canonical_json(audit):
        raise RuntimeError('DERIVATION_CAMPAIGN_AUDIT_MISMATCH')

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=['prepare','execute'])
    p.add_argument('--data-root',type=Path,required=True)
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--review',type=Path)
    args=p.parse_args()
    if args.mode=='prepare': prepare(args.data_root,args.workspace)
    elif args.review: execute(args.data_root,args.workspace,args.review)
    else: p.error('--review required for execute')

if __name__=='__main__':main()

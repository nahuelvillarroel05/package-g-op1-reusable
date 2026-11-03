"""External, hash-bound full BFCL structural comparison driver.

No source bodies or references are exported. Every archived response is joined by
exact task ID, reserve IDs are excluded before either auditor, and each auditor
receives only {id,result} plus {id,function}. No benchmark/tool/model execution.
"""
from __future__ import annotations
import collections, datetime, hashlib, json, os, pathlib, sys

ROOT = pathlib.Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
REPO = ROOT / "Engineering/Active_Candidate/repo"
WORK = ROOT / "Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/bfcl"
OLD = ROOT / "Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001"
PLAN_PATH = OLD / "attempts/attempt-0004/PLAN.json"
INV_PATH = OLD / "FULL_TASK_INVENTORY.json"
ATTEMPT = WORK / "attempt-002"
PROCESSING_PLAN_PATH = WORK / "PROCESSING_PLAN_002.json"
RESERVED = {f"simple_python_{i}" for i in range(20,40)}
CATEGORIES = {"simple_python", "live_simple", "multiple", "live_multiple"}

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "experiments/engineering/corpus_001"))
from runtime.candidate.bfcl_structured_audit import audit as audit_v1
from runtime.candidate.bfcl_structured_audit_v2 import audit as audit_v2
from experiments.engineering.corpus_001.archive_catalog import iter_rows


def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p):
    h=hashlib.sha256()
    with pathlib.Path(p).open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()
def canonical(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
def dump_new(p,v):
    with pathlib.Path(p).open("x",encoding="utf-8",newline="\n") as f:
        json.dump(v,f,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False);f.write("\n");f.flush();os.fsync(f.fileno())
def git(*args):
    import subprocess
    return subprocess.check_output(["git","-c","safe.directory="+REPO.as_posix(),"-C",str(REPO),*args],text=True).strip()
def rep_kind(v):
    if isinstance(v,str): return "TOOL_CALL_ENVELOPE" if "<tool_call>" in v or "</tool_call>" in v else "OTHER_STRING"
    if isinstance(v,list): return "NATIVE_LIST"
    if isinstance(v,dict): return "NATIVE_OBJECT"
    return "OTHER_OR_MISSING"
def predicate_summary(result):
    p=result.get("predicates") if isinstance(result,dict) else None
    return {k:p.get(k) for k in sorted(p)} if isinstance(p,dict) else {}
def source_id(src):
    return sha_bytes(canonical({"path":src["path"],"sha256":src["sha256"],"role":src["role"],"revision":src["revision"],"model_id":src["model_id"],"category":src["category"]}))

def task_map(auxiliary):
    found={}; task_sources={}
    for src in auxiliary:
        if src.get("role")!="AUDIT_TASK_DEFINITION": raise ValueError("unexpected auxiliary source role")
        p=pathlib.Path(src["path"]); raw=p.read_bytes()
        if sha_bytes(raw)!=src["sha256"]: raise ValueError("task source hash mismatch: "+str(p))
        task_sources[str(p)]=src["sha256"]
        for pos,row in iter_rows(raw):
            if not isinstance(row,dict) or not isinstance(row.get("id"),str): continue
            tid=row["id"]
            if tid in RESERVED: continue
            # Auditor gets only task identity and declared function schemas.
            if "function" not in row: continue
            projected={"id":tid,"function":row["function"]}
            if tid in found: raise ValueError("duplicate task definition: "+tid)
            found[tid]={"task":projected,"path":str(p),"sha256":src["sha256"],"row_index":pos,"row_sha256":sha_bytes(canonical(projected))}
    return found,task_sources

def main():
    if ATTEMPT.exists(): raise ValueError("attempt directory exists; recovery requires explicit receipt reconciliation")
    ATTEMPT.mkdir(parents=True)
    plan_bytes=PLAN_PATH.read_bytes(); plan_sha=sha_bytes(plan_bytes); plan=json.loads(plan_bytes)
    response_sources=[s for s in plan["sources"] if s.get("role")=="MODEL_RESPONSE"]
    task_sources=plan["auxiliary_sources"]
    if len(response_sources)!=2765 or len(task_sources)!=19: raise ValueError("pinned source plan population changed")
    free=__import__("shutil").disk_usage(WORK).free
    if free < 50*1024**3: raise ValueError("less than 50 GiB free")
    baseline={"schema":"pgop1.bfcl.full-scale-plan.v1","plan_path":str(PLAN_PATH),"plan_sha256":plan_sha,
      "task_inventory_path":str(INV_PATH),"task_inventory_sha256":sha_file(INV_PATH),
      "baseline_code_commit":"d8b1766aff0e5bfa4018ccd61de9642cbb14f92e","candidate_checkout_head":git("rev-parse","HEAD"),
      "candidate_tree":git("rev-parse","HEAD^{tree}"),"repository_worktree":"CLEAN_REQUIRED_BUT_EXTERNAL_DRIVER",
      "runtime_sha256":{"v1":sha_file(REPO/"runtime/candidate/bfcl_structured_audit.py"),"v2":sha_file(REPO/"runtime/candidate/bfcl_structured_audit_v2.py"),"catalog":sha_file(REPO/"experiments/engineering/corpus_001/archive_catalog.py")},
      "model_response_source_count":len(response_sources),"task_definition_source_count":len(task_sources),
      "selection":"all MODEL_RESPONSE rows with a string task ID, excluding reserved simple_python_20..39 before auditor calls; retain exact-task-unbound rows with explicit UNKNOWN binding and abstentions",
      "auditor_input_projection":"response={id,result}; exact-bound task={id,function}; unbound task={id}; no labels, references, publisher scores, or result bodies are emitted",
      "driver_sha256":sha_file(pathlib.Path(__file__)),"free_bytes_at_start":free,
      "same_inputs":"same projected task and response objects passed to V1 and V2",
      "excluded_reserves":sorted(RESERVED),"reserve_eligibility":"UNKNOWN_PENDING_ACCESS_REVIEW",
      "semantic_claim":"NONE; structural task-relative only","tool_calls":0,"model_execution":0,"official_evaluator_execution":0,
      "source_scan_bytes_expected":sum(pathlib.Path(s["path"]).stat().st_size for s in response_sources),
      "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    dump_new(PROCESSING_PLAN_PATH,baseline)
    tasks,task_source_map=task_map(task_sources)
    dump_new(ATTEMPT/"TASK_BINDING_SUMMARY.json",{"task_definition_sources":task_source_map,"bound_task_count":len(tasks),"labels_read_or_used":False,"reserved_task_ids_scored":0})
    agg=collections.Counter(); percat=collections.defaultdict(collections.Counter); perrep=collections.defaultdict(collections.Counter)
    source_manifest=[];eligible=reserved=unresolved=aggregate=archived_rows=response_task_rows=task_bound=0
    rows_dir=ATTEMPT/"sources"; rows_dir.mkdir()
    for idx,src in enumerate(response_sources):
        p=pathlib.Path(src["path"]); raw=p.read_bytes(); actual=sha_bytes(raw)
        if actual!=src["sha256"]: raise ValueError("response source hash mismatch: "+str(p))
        source_key=source_id(src); seen=set(); counts=collections.Counter(); file_rows=0; outpath=rows_dir/(f"source-{idx:05d}.jsonl")
        tmp=outpath.with_suffix(".jsonl.partial")
        with tmp.open("x",encoding="utf-8",newline="\n") as out:
            for pos,row in iter_rows(raw):
                file_rows+=1
                if not isinstance(row,dict): aggregate+=1; counts["non_object_row"]+=1; continue
                tid=row.get("id")
                if not isinstance(tid,str): aggregate+=1; continue
                counts["response_task_rows"]+=1
                if tid in RESERVED: reserved+=1; counts["reserved_excluded"]+=1; continue
                binding=tasks.get(tid)
                if binding is None:
                    unresolved+=1; counts["unresolved_task"]+=1; task={"id":tid}
                    task_source_path=None;task_source_hash=None;task_source_row=None;task_row_hash=None
                    binding_status="SOURCE_BINDING_NOT_PROVEN"
                else:
                    task_bound+=1;counts["task_bound"]+=1;task=binding["task"]
                    task_source_path=binding["path"];task_source_hash=binding["sha256"]
                    task_source_row=binding["row_index"];task_row_hash=binding["row_sha256"]
                    binding_status="EXACT_TASK_ID_AND_PINNED_TASK_DEFINITION"
                if tid in seen: counts["duplicate_task_id_in_source"]+=1
                seen.add(tid)
                # Project away score/reference/other fields before either auditor.
                response={"id":tid,"result":row.get("result")}
                v2=audit_v2(task,response)
                raw_result=response.get("result")
                if not tid.startswith("simple_python_"):
                    v1_status="ABSTAIN_UNSUPPORTED_CATEGORY";v1_direct_status="NOT_RUN_OUTSIDE_V1_SCOPE";v1_predicates={}
                elif not (isinstance(raw_result,str) and "<tool_call>" in raw_result):
                    v1_status="ABSTAIN_UNSUPPORTED_RESPONSE_REPRESENTATION";v1_direct_status="NOT_RUN_BY_ARCHIVE_GATEWAY";v1_predicates={}
                elif binding is None:
                    v1_status="ABSTAIN_INVALID_TASK";v1_direct_status="NOT_RUN_TASK_BINDING_UNPROVEN";v1_predicates={}
                else:
                    v1=audit_v1(task,response);v1_status=v1.get("status","UNKNOWN")
                    v1_direct_status=v1_status;v1_predicates=predicate_summary(v1)
                rid=sha_bytes(canonical({"source_path":str(p),"source_sha256":actual,"row_index":pos,"source_identity":source_key}))
                result={"row_id":rid,"task_id":tid,"source_path":str(p),"source_sha256":actual,"source_row_index":pos,
                    "response_row_sha256":sha_bytes(canonical(row)),"source_binding_status":binding_status,
                    "task_source_path":task_source_path,"task_source_sha256":task_source_hash,
                    "task_source_row_index":task_source_row,"task_row_sha256":task_row_hash,
                    "model_id":src["model_id"],"category":src["category"],"source_revision":src["revision"],"benchmark_version":src["version"],
                    "representation":rep_kind(response.get("result")),"result_value_type":type(response.get("result")).__name__,
                    "v1_status":v1_status,"v1_direct_status":v1_direct_status,"v1_predicates":v1_predicates,
                    "v1_v2_common_applicability":bool(binding is not None and tid.startswith("simple_python_") and isinstance(raw_result,str) and "<tool_call>" in raw_result),
                    "v2_status":v2.get("status","UNKNOWN"),"v2_predicates":predicate_summary(v2),
                    "semantic_verdict":"NOT_COMPARABLE"}
                out.write(json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n")
                counts["eligible"]+=1;agg[(result["v1_status"],result["v2_status"])]+=1
                percat[src["category"]][(result["v1_status"],result["v2_status"])]+=1
                perrep[result["representation"]][(result["v1_status"],result["v2_status"])]+=1
            out.flush();os.fsync(out.fileno())
        os.replace(tmp,outpath)
        eligible+=counts["eligible"]; archived_rows+=file_rows; response_task_rows+=counts.get("response_task_rows",0)
        receipt={"source_index":idx,"source_id":source_key,"source_path":str(p),"source_sha256_before":actual,
          "source_size":len(raw),"source_row_count":file_rows,"eligible_rows":counts["eligible"],"task_bound_rows":counts["task_bound"],
          "reserved_excluded":counts["reserved_excluded"],"unresolved_task_rows":counts["unresolved_task"],
          "result_part":str(outpath),"result_part_sha256":sha_file(outpath),"counts":dict(counts),
          "completed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
        with (ATTEMPT/"SOURCE_CHECKPOINTS.jsonl").open("a",encoding="utf-8",newline="\n") as cp:
            cp.write(json.dumps(receipt,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n");cp.flush();os.fsync(cp.fileno())
        source_manifest.append(receipt)
        if (idx+1)%50==0 or idx+1==len(response_sources):
            print(json.dumps({"sources_done":idx+1,"sources_total":len(response_sources),"eligible_rows":eligible,"reserved_excluded":reserved,"unresolved_rows":unresolved,"aggregate_rows":aggregate}),flush=True)
    # Rehash every declared task and response source after processing.
    rehash=[]
    for s in response_sources:
        actual=sha_file(s["path"]); ok=actual==s["sha256"]
        rehash.append({"path":s["path"],"sha256_expected":s["sha256"],"sha256_after":actual,"match":ok})
        if not ok: raise ValueError("response source changed after processing: "+s["path"])
    for p,expected in task_source_map.items():
        actual=sha_file(p);ok=actual==expected;rehash.append({"path":p,"sha256_expected":expected,"sha256_after":actual,"match":ok})
        if not ok: raise ValueError("task source changed after processing: "+p)
    dump_new(ATTEMPT/"SOURCE_REHASH.json",{"sources_checked":len(rehash),"all_match":all(x["match"] for x in rehash),"sources":rehash})
    final=WORK/"row_audit_results.jsonl"
    with final.open("xb") as dst:
        for receipt in source_manifest:
            with pathlib.Path(receipt["result_part"]).open("rb") as src: shutil_copy(src,dst)
        dst.flush();os.fsync(dst.fileno())
    totals=collections.Counter(); v1=collections.Counter();v2=collections.Counter();common=0
    # Re-read output without response bodies; recompute final lineage checks and status counts.
    with final.open("r",encoding="utf-8") as f:
        for line in f:
            r=json.loads(line);totals["rows"]+=1;v1[r["v1_status"]]+=1;v2[r["v2_status"]]+=1;common+=int(r["v1_v2_common_applicability"])
    results={"schema":"pgop1.bfcl.full-scale-results.v1","status":"COMPLETED_STRUCTURAL_DEVELOPMENT_ONLY",
      "processing_plan_sha256":sha_file(PROCESSING_PLAN_PATH),"pinned_source_plan_sha256":plan_sha,
      "archived_model_response_rows":response_task_rows,"archived_physical_rows":archived_rows,"eligible_rows":totals["rows"],"reserved_rows_excluded":reserved,"source_binding_not_proven_rows":unresolved,"aggregate_rows_excluded":aggregate,
      "expected_historical_model_response_rows":776653,"archived_row_count_matches_historical":response_task_rows==776653,"eligible_denominator_kind":"all nonreserve MODEL_RESPONSE rows, including explicit source-binding-unknown rows",
      "exact_task_bound_rows":task_bound,"source_binding_not_proven_rows":unresolved,
      "v1_archive_gateway_statuses":dict(v1),"v2_statuses":dict(v2),
      "v1_v2_common_applicability_rows":common,"transition_counts":{" | ".join(k):n for k,n in agg.items()},
      "category_transition_counts":{k:{" | ".join(a):n for a,n in c.items()} for k,c in percat.items()},
      "representation_transition_counts":{k:{" | ".join(a):n for a,n in c.items()} for k,c in perrep.items()},
      "distinct_models":len({s["model_id"] for s in response_sources}),"categories":sorted({s["category"] for s in response_sources}),
      "response_source_files":len(response_sources),"task_definition_source_files":len(task_source_map),
      "source_rehash":"PASS","row_results_path":str(final),"row_results_sha256":sha_file(final),"row_results_bytes":final.stat().st_size,
      "row_results_have_source_bodies":False,"labels_or_references_used":False,"producer_task_revision":"UNKNOWN","semantic_verdict":"NOT_COMPARABLE",
      "official_evaluator_executions":0,"tool_or_model_execution":0,"reserve_eligibility":"UNKNOWN_PENDING_ACCESS_REVIEW",
      "completed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    dump_new(WORK/"BFCL_FULL_SCALE_RESULTS.json",results)
    print(json.dumps({"status":results["status"],"archived_model_response_rows":response_task_rows,"archived_physical_rows":archived_rows,"eligible_rows":totals["rows"],"reserved_rows_excluded":reserved,"unresolved_rows":unresolved,"result_sha256":results["row_results_sha256"]}),flush=True)

def shutil_copy(src,dst):
    import shutil
    shutil.copyfileobj(src,dst,1024*1024)

if __name__=="__main__": main()

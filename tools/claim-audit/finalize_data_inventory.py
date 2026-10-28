
import pathlib,json,hashlib,collections,datetime,stat,re
import pyarrow.parquet as pq
ROOT=pathlib.Path(r"D:\PGOP1_DATA\SWEbench"); WS=ROOT/"Engineering"/"PGOP1_RUN_001"
LIST=WS/"frozen_input_listing.jsonl"; SUM=json.loads((WS/"frozen_input_listing_summary.json").read_text(encoding="utf-8"))
HIST=json.loads((WS/"repo"/"runs"/"swebench-claim-audit-v1"/"campaign-selection"/"CAMPAIGN_SELECTION_V4_PUBLIC.json").read_text(encoding="utf-8"))
histids={x["instance_id"] for x in HIST["instances"]}; histrepos={x["repository_id"] for x in HIST["instances"]}
protocol=json.loads((WS/"SPLIT_PROTOCOL.json").read_text(encoding="utf-8")); ph=hashlib.sha256((WS/"SPLIT_PROTOCOL.json").read_bytes()).hexdigest()
def classify(rel,ext):
 q=rel.casefold(); p=q.split("/"); ds="UNKNOWN"; role="unclassified_auxiliary"; elig="EXCLUDE_UNLESS_RECLASSIFIED"
 for n in ("verified","multilingual","experiments-main","experiments","lite","full"):
  if n in p: ds=n.upper().replace("-MAIN",""); break
 if p[0].startswith("pgop1_") or p[0]=="engineering": ds="HISTORICAL_ENGINEERING"
 if "swe-bench-main" in p: ds="SWE_BENCH_UPSTREAM"
 if "logs" in p and ("trajs" in p or "logs" in p): ds="LOCAL_AGENT_RUNS"
 if ds=="SWE_BENCH_UPSTREAM": role,elig="source_evaluator_or_dataset_code","REFERENCE_CODE_NOT_AGENT_EVIDENCE"
 elif ds=="HISTORICAL_ENGINEERING": role,elig="historical_derived_or_audit_artifact","EXCLUDE_HISTORICAL_DERIVED_COPY"
 elif ds in ("FULL","LITE","VERIFIED","MULTILINGUAL"):
  role,elig=("dataset_cache_metadata","METADATA_ONLY_NO_INSTANCE_DOUBLE_COUNT") if ".cache" in p else (("raw_problem_dataset_rows","PROCESSABLE_INSTANCE_SOURCE_AFTER_ROW_VALIDATION") if ext==".parquet" else ("dataset_distribution_metadata","METADATA_ONLY"))
 elif ds=="LOCAL_AGENT_RUNS":
  role,elig=("agent_trajectory","CANDIDATE_AGENT_EVIDENCE") if "trajs" in p else (("agent_patch","CANDIDATE_PATCH_EVIDENCE_NO_EXECUTION") if ext in (".diff",".patch") else ("agent_log_or_run_record","CANDIDATE_AGENT_EVIDENCE"))
 elif ds=="EXPERIMENTS":
  role,elig=("historical_agent_trajectory","CANDIDATE_PUBLIC_AGENT_EVIDENCE_LICENSE_REVIEW") if "chat-transcripts" in q else (("third_party_evaluator_result","REFERENCE_RESULT_ONLY_NO_CLAIM_INFERENCE") if "/results/" in q else (("agent_patch","CANDIDATE_PATCH_EVIDENCE_NO_EXECUTION") if ext in (".diff",".patch") else (("submission_metadata","PROVENANCE_METADATA_ONLY") if "metadata.yaml" in q else ("experiment_support_artifact","SUPPORTING_METADATA_NOT_AGENT_TRAJECTORY"))))
 elif ext in (".json",".jsonl",".csv",".parquet",".orc",".feather",".sqlite"): role,elig="structured_unclassified","EXCLUDE_UNLESS_RECLASSIFIED"
 elif ext in (".gz",".zip",".diff"): role,elig="compressed_or_patch_unclassified","EXCLUDE_UNLESS_RECLASSIFIED"
 elif ext in (".py",".md",".txt",".yaml",".yml"): role,elig="code_documentation_or_auxiliary","EXCLUDE_UNLESS_RECLASSIFIED"
 return ds,role,elig
records=[]; herrors=[]; drift=[]; rc=collections.Counter(); ec=collections.Counter(); tc=collections.Counter()
for line in LIST.open(encoding="utf-8"):
 x=json.loads(line); rel=x["relative_path"]; p=ROOT.joinpath(*rel.split("/")); h=hashlib.sha256(); n=0
 try:
  b=p.stat()
  if (b.st_size,b.st_mtime_ns)!=(x["size_bytes"],x["mtime_ns"]): drift.append({"path":rel,"phase":"before_hash","frozen_size":x["size_bytes"],"observed_size":b.st_size,"frozen_mtime_ns":x["mtime_ns"],"observed_mtime_ns":b.st_mtime_ns})
  with p.open("rb") as f:
   for z in iter(lambda:f.read(1024*1024),b""): h.update(z); n+=len(z)
  a=p.stat()
  if (a.st_size,a.st_mtime_ns)!=(b.st_size,b.st_mtime_ns): drift.append({"path":rel,"phase":"during_hash","before_size":b.st_size,"after_size":a.st_size,"before_mtime_ns":b.st_mtime_ns,"after_mtime_ns":a.st_mtime_ns})
  sha=h.hexdigest()
 except OSError as e: sha=None; herrors.append({"relative_path":rel,"error_type":type(e).__name__,"error":str(e)})
 ds,role,elig=classify(rel,x["file_type"]); key=hashlib.sha256(rel.encode("utf-8")).hexdigest()[:20]
 x.update({"source_id":"SRC-"+key,"sha256":sha,"hash_bytes_read":n,"dataset":ds,"split":"UNKNOWN_UNLESS_SOURCE_TABLE","submission":"UNKNOWN_UNLESS_PATH_METADATA","source_revision":"UNKNOWN_UNVERIFIED","evidence_role":role,"processing_eligibility":elig,"private_original_path":str(p),"safe_publication_path":f"source/{ds.lower()}/{key}{x['file_type'] if x['file_type']!='[no_extension]' else ''}"})
 records.append(x); rc[role]+=1; ec[elig]+=1; tc[x["file_type"]]+=1
listing_sha=hashlib.sha256(LIST.read_bytes()).hexdigest()
inv={"schema_version":"1.1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"scope":"All accessible regular files from frozen pre-hash listing; current Engineering/PGOP1_RUN_001 workspace excluded.","snapshot_root_private":str(ROOT),"frozen_listing_sha256":listing_sha,"regular_files_listed":len(records),"files_hashed":sum(x["sha256"] is not None for x in records),"file_hash_errors":herrors,"stat_drift":drift,"files":records}
(WS/"INPUT_INVENTORY.json").write_text(json.dumps(inv,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
prov={"schema_version":"1.1","scope_note":"Path-derived classifications. Dataset/split/submission/revision remain unknown unless verified in the metadata extraction below. No trajectory or heldout outcome text read.","records":[{k:x[k] for k in ("source_id","private_original_path","safe_publication_path","sha256","size_bytes","dataset","split","submission","source_revision","evidence_role","processing_eligibility")} for x in records]}
(WS/"SOURCE_PROVENANCE.json").write_text(json.dumps(prov,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
tables={"FULL":["full/data/dev-00000-of-00001.parquet","full/data/test-00000-of-00001.parquet"],"LITE":["lite/data/dev-00000-of-00001.parquet","lite/data/test-00000-of-00001.parquet"],"VERIFIED":["verified/data/test-00000-of-00001.parquet"],"MULTILINGUAL":["multilingual/data/test-00000-of-00001.parquet"]}
members=collections.defaultdict(dict); shards=[]
for ds,paths in tables.items():
 for rel in paths:
  pf=pq.ParquetFile(ROOT/rel); tab=pq.read_table(ROOT/rel,columns=["instance_id","repo"])
  for iid,repo in zip(tab["instance_id"].to_pylist(),tab["repo"].to_pylist()): members[iid][ds]=repo
  shards.append({"path":rel,"dataset":ds,"rows":pf.metadata.num_rows,"fields_read":["instance_id","repo"],"outcome_fields_read":False})
pair=collections.Counter()
for m in members.values():
 for a in m:
  for b in m:
   if a<b: pair[a+" intersect "+b]+=1
trajs=[]
for x in records:
 rel=x["relative_path"]
 if rel.casefold().startswith("logs/trajs/") and ".traj." in rel.casefold():
  name=rel.rsplit("/",1)[-1].split(".traj",1)[0]; mt=re.match(r"^(.*)-([0-9]+)(?:\.js-[0-9]+)?$",name)
  rawrepo=mt.group(1) if mt else ""; canonical=(rawrepo+"-"+mt.group(2)) if mt else name
  if rawrepo.endswith(".js"): rawrepo=rawrepo.rsplit("-",1)[0]
  repo=rawrepo.replace("__","/",1) if "__" in rawrepo else "UNKNOWN"
  trajs.append({"source_id":x["source_id"],"path":rel,"filename_instance_id":name,"canonical_instance_id":canonical,"repo_group":repo,"identity_parse_status":"PARSED_FROM_FILENAME" if mt else "UNPARSED"})
histrepo_norm={x.replace("__","/",1) for x in histrepos}; assignments=[]
for t in trajs:
 iid=t["canonical_instance_id"]; repo=t["repo_group"]
 if iid in histids: s="HISTORICAL_DEVELOPMENT_CASES"
 elif repo in histrepo_norm: s="NEW_DEVELOPMENT_ALLOW_HISTORICAL_PROVENANCE"
 elif repo=="UNKNOWN": s="UNASSIGNED_NO_GROUP_KEY"
 else:
  bucket=int(hashlib.sha256(("PGOP1_RUN_001_SPLIT_V1|"+repo).encode()).hexdigest()[0],16)
  s="NEW_DEVELOPMENT" if bucket<4 else "HELDOUT" if bucket<8 else "UNUSED_RESERVE"
 assignments.append({**t,"split_assignment":s,"grouping_rule":"repository"})
(WS/"SPLIT_ASSIGNMENT.json").write_text(json.dumps({"schema_version":"1.0","protocol_id":protocol["protocol_id"],"protocol_sha256":ph,"historical_selection_sha256":HIST["selection_sha256"],"historical_ids":sorted(histids),"historical_repositories":sorted(histrepos),"assignments":assignments,"heldout_outcome_text_inspected":False,"counts":dict(collections.Counter(x["split_assignment"] for x in assignments))},indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
dataset_counts={d:sum(d in m for m in members.values()) for d in tables}
summary={"snapshot_root":str(ROOT),"frozen_listing_sha256":listing_sha,"files_listed":len(records),"files_hashed":len(records)-len(herrors),"hash_errors":herrors,"stat_drift":drift,"bytes_hashed":sum(x["hash_bytes_read"] for x in records),"unreadable_directory_errors":SUM["listing_errors"],"file_type_counts":dict(sorted(tc.items())),"role_counts":dict(rc),"eligibility_counts":dict(ec),"dataset_shards":shards,"dataset_instance_counts":dataset_counts,"unique_dataset_instance_ids":len(members),"pairwise_overlap_ids":dict(pair),"trajectory_files":len(trajs),"trajectory_unique_filename_ids":len({x["filename_instance_id"] for x in trajs}),"trajectory_repo_groups":dict(collections.Counter(x["repo_group"] for x in trajs)),"split_assignment_counts":dict(collections.Counter(x["split_assignment"] for x in assignments))}
(WS/"inventory_hash_summary.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
matrix={"schema_version":"1.0","eligibility_is_not_verdict":True,"role_counts":dict(rc),"processing_eligibility_counts":dict(ec),"rules":{"raw_problem_dataset_rows":"After row identity/parser validation only.","agent_trajectory":"Candidate evidence; retain instance/submission attribution; never execute embedded commands.","agent_patch":"Evidence only; no execution through inventory.","third_party_evaluator_result":"Reference result only, not an agent claim.","source_evaluator_or_dataset_code":"Reference code, never a trajectory.","historical_derived_or_audit_artifact":"Exclude from fresh inputs; preserve lineage.","unclassified":"Exclude pending review."},"listing_error_count":len(SUM["listing_errors"]),"hash_error_count":len(herrors),"stat_drift_count":len(drift),"heldout_text_inspected":False}
(WS/"ELIGIBILITY_MATRIX.json").write_text(json.dumps(matrix,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
text=f"""# PGOP1 RUN-001 input inventory and dataset coverage

## Status

Read-only inventory over the frozen pre-hash listing, excluding the current Engineering/PGOP1_RUN_001 workspace. Snapshot coverage is incomplete: {len(SUM['listing_errors'])} protected directory enumeration failures are preserved exactly in frozen_input_listing_summary.json. No ACL changes or access bypasses were attempted.

## File inventory

- Regular files listed and hashed: {len(records):,}/{len(records):,}
- Bytes streamed through SHA-256: {sum(x['hash_bytes_read'] for x in records):,}
- Hash read errors: {len(herrors)}
- Frozen-listing size/mtime drift: {len(drift)}
- Inaccessible directory enumeration errors: {len(SUM['listing_errors'])}

INPUT_INVENTORY.json retains private paths, hashes, source IDs, roles, and safe publication projections. SOURCE_PROVENANCE.json records path-derived provenance. Eligibility labels are not audit verdicts.

## Dataset row coverage

Only instance_id and repo columns were read from the six dataset shards. Patch, test patch, problem statement, hints, evaluation result, trajectory, and claim text were not read.

| Dataset | Unique instance IDs |
|---|---:|
| Full | {dataset_counts['FULL']:,} |
| Lite | {dataset_counts['LITE']:,} |
| Verified | {dataset_counts['VERIFIED']:,} |
| Multilingual | {dataset_counts['MULTILINGUAL']:,} |
| Unique across datasets | {len(members):,} |

Pairwise overlap counts are recorded in inventory_hash_summary.json: {json.dumps(dict(pair),ensure_ascii=False)}.

## Agent and historical artifacts

The filename-only logs/trajs catalog has {len(trajs)} files, {len({x['filename_instance_id'] for x in trajs})} unique filename IDs, and {len({x['repo_group'] for x in trajs})} provisional repository groups. The twelve public historical development IDs are excluded. Remaining IDs that share a historical repository are marked NEW_DEVELOPMENT_ALLOW_HISTORICAL_PROVENANCE, never independent heldout evidence. Other groups use the frozen deterministic group hash rule. Split assignments are in SPLIT_ASSIGNMENT.json; no heldout outcomes were inspected.

SWE-bench-main is source/evaluator code, not an agent trajectory. experiments-main/evaluation/**/results/ is third-party evaluator-result material, and chat-transcripts/ is historical agent evidence. PGOP1_* and prior Engineering trees are historical derived artifacts, not fresh raw sources.

## Formats

Observed extensions include JSON, JSONL, gzip, diff, CSV, Parquet, ORC, Feather, SQLite, YAML/YML, text/Markdown, Python and archives. Exact counts and per-file role classification are in INPUT_INVENTORY.json. Format presence alone does not establish eligibility.

## Limits

This inventory does not claim processing or audit completion. A dataset row is not an agent run or claim. Dataset, split, submission, and revision fields stay unknown unless separately verified. The snapshot remains incomplete due to access-denied directories.
"""
(WS/"DATASET_COVERAGE_REPORT.md").write_text(text,encoding="utf-8")
print(json.dumps({"files":len(records),"hashed":len(records)-len(herrors),"hash_errors":len(herrors),"stat_drift":len(drift),"bytes":sum(x["hash_bytes_read"] for x in records),"dataset_counts":dataset_counts,"unique_dataset_ids":len(members),"overlap":dict(pair),"trajectory_count":len(trajs),"repo_groups":dict(collections.Counter(x["repo_group"] for x in trajs)),"splits":dict(collections.Counter(x["split_assignment"] for x in assignments))},indent=2))

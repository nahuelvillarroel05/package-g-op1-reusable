
import pathlib,json,hashlib,datetime,collections,re
ws=pathlib.Path(r"D:\PGOP1_DATA\SWEbench\Engineering\PGOP1_RUN_001")
# Preserve the initially generated assignment as an append-only preliminary attempt.
cur=json.loads((ws/"SPLIT_ASSIGNMENT.json").read_text(encoding="utf-8"))
(ws/"SPLIT_ASSIGNMENT_PRELIMINARY.json").write_text(json.dumps(cur,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
inv=json.loads((ws/"INPUT_INVENTORY.json").read_text(encoding="utf-8"))
prov=json.loads((ws/"SOURCE_PROVENANCE.json").read_text(encoding="utf-8"))
summary=json.loads((ws/"inventory_hash_summary.json").read_text(encoding="utf-8"))
up=json.loads((ws/"UPSTREAM_VERIFICATION.json").read_text(encoding="utf-8"))
upfiles={x["path"]:x for x in up["files"] if x.get("status")=="MATCH"}
for f in inv["files"]:
 rel=f["relative_path"]; parts=rel.split("/")
 if rel.startswith("experiments-main/evaluation/") and len(parts)>=4:
  f["dataset"]="EXPERIMENTS_"+parts[2].upper()
  f["split"]="CATALOG_"+parts[2].upper()
  f["submission"]=parts[3]
 if rel.startswith(("full/data/","lite/data/","verified/data/","multilingual/data/")):
  for split in ("dev","test"):
   if f"/{split}-" in "/"+rel: f["split"]=split.upper()
 if f["dataset"]=="SWE_BENCH_UPSTREAM" and rel.startswith("SWE-bench-main/"):
  path="/".join(parts[1:])
  if path in upfiles:
   f["source_revision"]=up["commit"]
   f["source_revision_evidence"]="UPSTREAM_VERIFICATION.json MATCH"
for s in prov["records"]:
 source=next((x for x in inv["files"] if x["source_id"]==s["source_id"]),None)
 if source:
  for k in ("dataset","split","submission","source_revision","evidence_role","processing_eligibility"):
   s[k]=source[k]
  if source.get("source_revision_evidence"): s["source_revision_evidence"]=source["source_revision_evidence"]
(ws/"INPUT_INVENTORY.json").write_text(json.dumps(inv,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
(ws/"SOURCE_PROVENANCE.json").write_text(json.dumps(prov,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
# Freeze addendum before any heldout transcript or trajectory content is opened.
addendum={"schema_version":"1.0","protocol_id":"PGOP1_RUN_001_PRE_RESULT_INSPECTION_SPLIT_V1_ADDENDUM","parent_protocol_sha256":hashlib.sha256((ws/"SPLIT_PROTOCOL.json").read_bytes()).hexdigest(),"frozen_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"heldout_text_inspected":False,"additional_rules":[
 "For logs/trajs the inherited source provenance treats the complete local collection as one shared historical source submission. Exact model/submission revision remains UNKNOWN. No trajectory from this shared collection is an independent submission holdout.",
 "Preserve repository-level deterministic buckets as exploratory partitions only. If a bucket would otherwise be HELDOUT, label it REPOSITORY_HELDOUT_SHARED_SUBMISSION_NOT_INDEPENDENT; do not use it to claim independent generalization.",
 "Keep the twelve historical instance IDs HISTORICAL_DEVELOPMENT_CASES. Additional trajectories in those six historical repositories remain NEW_DEVELOPMENT_ALLOW_HISTORICAL_PROVENANCE.",
 "Create separate catalog-only public experiment splits by submission directory. These are not independent claim-language evaluations because no independent claim-language reference is identified and no transcript content is inspected.",
 "The source submission identifier for logs/trajs is not exposed by paths and stays UNKNOWN; LOCAL_LOGS_TRAJS_COLLECTION is a grouping label only."
],"basis":"Path inventory plus inherited source-level provenance message from the orchestrating agent; no files in logs/trajs or chat-transcripts were opened."}
raw=(json.dumps(addendum,indent=2,ensure_ascii=False)+"\n").encode("utf-8")
(ws/"SPLIT_PROTOCOL_ADDENDUM.json").write_bytes(raw); (ws/"SPLIT_PROTOCOL_ADDENDUM.sha256").write_text(hashlib.sha256(raw).hexdigest()+"  SPLIT_PROTOCOL_ADDENDUM.json\n",encoding="ascii")
# Corrected trajectory split preserving repository buckets and binding shared source collection.
hist=json.loads((ws/"repo"/"runs"/"swebench-claim-audit-v1"/"campaign-selection"/"CAMPAIGN_SELECTION_V4_PUBLIC.json").read_text(encoding="utf-8"))
histids={x["instance_id"] for x in hist["instances"]}
old=cur["assignments"]; corrected=[]; counts=collections.Counter()
for x in old:
 y=dict(x); y["submission_group_id"]="LOCAL_LOGS_TRAJS_COLLECTION"; y["source_submission_id"]="UNKNOWN"; y["source_submission_revision"]="UNKNOWN"
 if y["split_assignment"]=="HELDOUT": y["split_assignment"]="REPOSITORY_HELDOUT_SHARED_SUBMISSION_NOT_INDEPENDENT"
 y["independence_status"]="NOT_INDEPENDENT_SHARED_HISTORICAL_SOURCE_SUBMISSION"
 corrected.append(y); counts[y["split_assignment"]]+=1
new={"schema_version":"1.1","protocol_id":addendum["protocol_id"],"base_protocol_sha256":addendum["parent_protocol_sha256"],"addendum_sha256":hashlib.sha256(raw).hexdigest(),"historical_selection_sha256":hist["selection_sha256"],"historical_ids":sorted(histids),"shared_submission_group":"LOCAL_LOGS_TRAJS_COLLECTION","source_submission_id":"UNKNOWN","source_submission_revision":"UNKNOWN","assignments":corrected,"heldout_outcome_text_inspected":False,"independent_trajectory_heldout_count":0,"counts":dict(counts)}
(ws/"SPLIT_ASSIGNMENT.json").write_text(json.dumps(new,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
# Separate public experiment transcript catalog and deterministic whole-submission hash split.
listing=[x["relative_path"] for x in map(json.loads,(ws/"frozen_input_listing.jsonl").open(encoding="utf-8"))]
subfiles=collections.defaultdict(list); subdatasets=collections.defaultdict(set)
for rel in listing:
 if rel.casefold().startswith("experiments-main/evaluation/"):
  parts=rel.split("/")
  if len(parts)>=4:
   sub=parts[3]; subfiles[sub].append(rel); subdatasets[sub].add(parts[2])
transcripts=collections.Counter()
for sub,paths in subfiles.items():
 for rel in paths:
  if "chat-transcripts/" in rel.casefold(): transcripts[sub]+=1
subassign=[]
for sub,paths in sorted(subfiles.items()):
 h=hashlib.sha256(("PGOP1_RUN_001_PUBLIC_SUBMISSION_SPLIT_V1|"+sub).encode()).hexdigest()
 bucket=int(h[0],16)
 split="CATALOG_DEV" if bucket<4 else "CATALOG_HELDOUT" if bucket<8 else "CATALOG_RESERVE"
 subassign.append({"submission_id":sub,"dataset_partitions":sorted(subdatasets[sub]),"file_count":len(paths),"chat_transcript_file_count":transcripts[sub],"split":split,"group_hash_sha256":h,"evaluation_status":"CATALOG_ONLY_NO_INDEPENDENT_CLAIM_LANGUAGE_REFERENCE"})
public={"schema_version":"1.0","protocol_id":addendum["protocol_id"],"addendum_sha256":hashlib.sha256(raw).hexdigest(),"selection_rule":"Whole submission folder; SHA256('PGOP1_RUN_001_PUBLIC_SUBMISSION_SPLIT_V1|'+submission_id), first hex nibble 0-3=CATALOG_DEV, 4-7=CATALOG_HELDOUT, 8-f=CATALOG_RESERVE.","submission_count":len(subassign),"chat_transcript_count":sum(transcripts.values()),"heldout_text_inspected":False,"independent_claim_language_reference":False,"assignments":subassign,"counts":dict(collections.Counter(x["split"] for x in subassign))}
(ws/"PUBLIC_SUBMISSION_SPLIT.json").write_text(json.dumps(public,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
summary["unreadable_directory_errors"]=summary.get("unreadable_directory_errors",[])
summary["unreadable_directory_error_count"]=len(summary["unreadable_directory_errors"])
summary["trajectory_split_assignment_counts"]=dict(counts)
summary["independent_trajectory_heldout_count"]=0
summary["public_evaluation_submission_directories"]=len(subassign)
summary["public_chat_transcript_files"]=sum(transcripts.values())
(ws/"inventory_hash_summary.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
report=f"""# PGOP1 RUN-001 input inventory and dataset coverage

## Status

Read-only inventory over the frozen pre-hash listing, excluding the current Engineering/PGOP1_RUN_001 workspace. Snapshot coverage is incomplete: {len(summary['unreadable_directory_errors'])} protected directory enumeration failures are preserved exactly in frozen_input_listing_summary.json. No permission or ACL changes were attempted.

## File inventory

- Regular files listed and SHA-256 hashed: {inv['files_hashed']:,}/{inv['regular_files_listed']:,}.
- Bytes streamed through SHA-256: {summary['bytes_hashed']:,}.
- Hash read errors: {len(inv['file_hash_errors'])}.
- Frozen-listing size/mtime drift: {len(inv['stat_drift'])}.
- Unreadable directory enumeration errors: {len(summary['unreadable_directory_errors'])}.

INPUT_INVENTORY.json retains private paths, hashes, stable source IDs, roles, eligibility and safe publication projections. SOURCE_PROVENANCE.json records file-level provenance. Source revision is assigned only to files independently matched in UPSTREAM_VERIFICATION.json; other revisions remain UNKNOWN.

## Dataset row coverage

Only instance_id and repo columns were read from six dataset shards. Patch, test patch, problem statement, hints, evaluator result, trajectory and claim text were not read.

| Dataset | Unique instance IDs |
|---|---:|
| Full | {summary['dataset_instance_counts']['FULL']:,} |
| Lite | {summary['dataset_instance_counts']['LITE']:,} |
| Verified | {summary['dataset_instance_counts']['VERIFIED']:,} |
| Multilingual | {summary['dataset_instance_counts']['MULTILINGUAL']:,} |
| Unique across datasets | {summary['unique_dataset_instance_ids']:,} |

Pairwise overlap counts are in inventory_hash_summary.json: {json.dumps(summary['pairwise_overlap_ids'])}.

## Agent, submission and historical artifacts

The filename-only logs/trajs catalog contains {len(corrected)} files across {len(summary['trajectory_repo_groups'])} provisional repository groups. It includes the twelve historical development IDs. Forty additional IDs share the six historical repositories and are labeled NEW_DEVELOPMENT_ALLOW_HISTORICAL_PROVENANCE. Repository buckets outside those repositories yield 59 NEW_DEVELOPMENT candidates, 49 repository-heldout candidates, and 104 reserve candidates. Because all logs/trajs share one historical source-submission group, independent heldout trajectory count is zero; the 49 are exploratory repository-heldout only. Exact IDs are in SPLIT_ASSIGNMENT.json; the earlier assignment is preserved as SPLIT_ASSIGNMENT_PRELIMINARY.json.

The public experiment catalog contains {len(subassign)} submission directories and {sum(transcripts.values())} chat-transcript files. PUBLIC_SUBMISSION_SPLIT.json gives deterministic whole-submission catalog partitions. The heldout transcript contents remain unopened and this catalog split is not an independent claim-language evaluation.

SWE-bench-main is source/evaluator code, not an agent trajectory. experiments-main/evaluation/**/results/ is third-party evaluator-result material, and chat-transcripts/ is historical agent evidence. PGOP1_* and prior Engineering trees are historical derived artifacts, not fresh raw sources.

## Formats and limits

Observed types include JSON, JSONL, gzip, diff, CSV, Parquet, ORC, Feather, SQLite, YAML/YML, text/Markdown, Python and archives. Exact counts and roles are machine-readable in INPUT_INVENTORY.json. Format presence alone does not establish processing eligibility.

This is an inventory and coverage report, not a processed campaign result. A dataset row is not an agent run or claim. The snapshot remains incomplete because protected directories could not be read.
"""
(ws/"DATASET_COVERAGE_REPORT.md").write_text(report,encoding="utf-8")
print(json.dumps({"listing_errors":len(summary["unreadable_directory_errors"]),"trajectory_splits":dict(counts),"public_submission_counts":public["counts"],"public_submissions":len(subassign),"transcripts":sum(transcripts.values()),"upstream_revision_bound_files":sum(1 for x in inv["files"] if x.get("source_revision")==up["commit"])},indent=2))

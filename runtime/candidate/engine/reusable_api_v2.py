"""Configure an additional Engineering relationship without editing the engine."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from runtime import *
from engine import execute,recover
def register_relationship(case_id,provider_source,consumer_source,output_schema,negative_mode):
 for source in (provider_source,consumer_source):
  original=Path(source)
  if original.is_symlink() or original.resolve().parent!=ROOT:raise ValueError('source outside campaign before read')
 r={'CASE_ID':case_id,'RELATIONSHIP_ID':uid('REL'),'CLASSIFICATION':'ENGINEERING_LIVE',
 'PROVIDER_ID':uid('PROVIDER'),'PROVIDER_SOURCE':str(Path(provider_source).resolve()),'PROVIDER_SHA256':sha(Path(provider_source).read_bytes()),
 'CONSUMER_ID':uid('CONSUMER'),'CONSUMER_SOURCE':str(Path(consumer_source).resolve()),'CONSUMER_SHA256':sha(Path(consumer_source).read_bytes()),
 'OUTPUT_ID':uid('OUTPUT'),'OUTPUT_SCHEMA':output_schema,'INPUT_CONTRACT':output_schema,'SOURCE_ID':uid('SOURCE'),
 'EXECUTION_METHOD':'ISOLATED_PYTHON_PINNED_WORKER_DIRECT_POPEN','AUTHORITY_SCOPE':CONFIG['authority_scope'],
 'VERIFICATION_METHOD':'ACTUAL_CONSUMER_RECOMPUTATION_AND_FRESH_PROCESS_RECOVERY','NEGATIVE_MODE':negative_mode}
 validate_relationship(r)
 return r
def retry_with_new_id(relationship,variant,parent_attempt_id):
 if not parent_attempt_id:raise ValueError('exact parent attempt required')
 rows=[json.loads(line) for line in (ROOT/'ATTEMPT_REGISTRY.jsonl').read_bytes().splitlines()]
 parents=[row for row in rows if row.get('record_type')=='BEFORE_EXECUTION' and row.get('ATTEMPT_ID')==parent_attempt_id]
 if len(parents)!=1 or parents[0]['CASE_ID']!=relationship['CASE_ID']:raise ValueError('parent absent or relationship mismatch')
 parent_request=read(Path(parents[0]['directory'])/'request.json')
 if parent_request['relationship']!=relationship:raise ValueError('parent relationship commitments mismatch')
 return execute(relationship,variant,parent_attempt_id)

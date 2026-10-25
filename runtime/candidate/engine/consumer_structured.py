import json
from pathlib import Path
from runtime import sha,verify_receipt
def consume(r,d):
 verify_receipt(d);body=Path(d,'provider.stdout').read_bytes();a=json.loads(body)
 if set(a)!={'schema','request_id','nonce','values','sum','squares'} or a['schema']!='engineering.totals.v1' or a['request_id']!=r['REQUEST_ID'] or a['nonce']!=r['nonce'] or a['values']!=r['values'] or a['sum']!=sum(r['values']) or a['squares']!=sum(v*v for v in r['values']):raise ValueError('structured contract rejected')
 return {'processed_sha256':sha(body),'rows_processed':len(a['values']),'sum':a['sum'],'squares':a['squares']}

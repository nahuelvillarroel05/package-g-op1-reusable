import json
def produce(r):
 values=r['values']
 print(json.dumps({'schema':'engineering.totals.v1','request_id':r['REQUEST_ID'],'nonce':r['nonce'],'values':values,'sum':sum(values),'squares':sum(v*v for v in values)},sort_keys=True))

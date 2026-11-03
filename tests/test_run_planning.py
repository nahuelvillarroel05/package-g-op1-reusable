from copy import deepcopy
import pytest
from runtime.candidate.run_framework.planning import plan_shards, verify_shards

def plan(units):
    return plan_shards(units, max_units=2, resource_limits={'max_bytes':1024},
                       checkpoint_interval=1, recovery_policy={'mode':'RECOVERY_READ_ONLY'})

def test_population_independent_deterministic_partition():
    for units in [['z', 'a', 'm'], ['other:4', 'other:2', 'other:7', 'other:0', 'other:8']]:
        p = plan(units)
        assert p == plan(list(reversed(units)))
        assert verify_shards(units, p)['omitted'] == 0
        assert [x for s in p['shards'] for x in s['UNIT_IDS']] == sorted(units)

@pytest.mark.parametrize('alteration',['omit','duplicate','substitute','count','hash','order'])
def test_tampered_partition_rejected(alteration):
    units=['a','b','c','d']; p=deepcopy(plan(units))
    if alteration=='omit': p['shards'].pop()
    if alteration=='duplicate': p['shards'][1]=deepcopy(p['shards'][0])
    if alteration=='substitute': p['shards'][1]['UNIT_IDS'][-1]='alien'
    if alteration=='count': p['shards'][0]['EXPECTED_UNITS']=999
    if alteration=='hash': p['INPUT_SET_SHA256']='0'*64
    if alteration=='order': p['shards'].reverse()
    with pytest.raises(ValueError): verify_shards(units,p)

def test_duplicate_and_invalid_limits_rejected():
    with pytest.raises(ValueError): plan(['a','a'])
    with pytest.raises(ValueError): plan_shards(['a'], max_units=True, resource_limits={'b':1}, checkpoint_interval=1,recovery_policy={'mode':'read'})

@pytest.mark.parametrize('field',['hash','bound','resources','interval','recovery'])
def test_policy_tampering_rejected(field):
    p=plan(['a','b'])
    if field=='hash': p['POLICY_SHA256']='0'*64
    if field=='bound': p['SHARD_MAX_UNITS']=1
    if field=='resources': p['shards'][0]['RESOURCE_LIMITS']={'max_bytes':999999}
    if field=='interval': p['shards'][0]['CHECKPOINT_INTERVAL']=9999
    if field=='recovery': p['shards'][0]['RECOVERY_POLICY']={'mode':'SILENT_REDISPATCH'}
    with pytest.raises(ValueError): verify_shards(['a','b'],p)

def test_policy_checked_against_independent_configuration():
    p=plan(['a','b'])
    expected={'max_units':2,'resource_limits':{'max_bytes':1024},
              'checkpoint_interval':1,'recovery_policy':{'mode':'RECOVERY_READ_ONLY'}}
    assert verify_shards(['a','b'],p,expected_policy=expected)['status']=='PASS'
    with pytest.raises(ValueError): verify_shards(['a','b'],p,expected_policy={**expected,'max_units':3})

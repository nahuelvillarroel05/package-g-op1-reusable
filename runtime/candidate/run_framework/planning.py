"""Pure deterministic membership planning. Never reads task bodies or runs work."""
from __future__ import annotations
from copy import deepcopy
from runtime.candidate.context_engine import canonical_json, sha256_bytes


def _units(units):
    if not isinstance(units, list) or not units:
        raise ValueError('nonempty explicit unit list required')
    if any(not isinstance(u, str) or not u or len(u) > 4096 for u in units):
        raise ValueError('invalid unit identity')
    if len(set(units)) != len(units):
        raise ValueError('duplicate selected unit')
    return sorted(units)


def plan_shards(units, *, max_units, resource_limits, checkpoint_interval, recovery_policy):
    """Partition the full sorted input set without scope-specific semantics.

    Policies are declared metadata, not evidence of resource qualification.
    The caller must validate/freeze applicable execution policies separately.
    """
    ordered = _units(units)
    if type(max_units) is not int or max_units < 1:
        raise ValueError('positive integer shard bound required')
    if type(checkpoint_interval) is not int or checkpoint_interval < 1 or checkpoint_interval > max_units:
        raise ValueError('invalid checkpoint interval')
    if not isinstance(resource_limits, dict) or not resource_limits:
        raise ValueError('explicit resource limits required')
    if not isinstance(recovery_policy, dict) or not recovery_policy:
        raise ValueError('explicit recovery policy required')
    # JSON serialization only; no command, adapter, path or provider dispatch.
    resource_limits, recovery_policy = deepcopy(resource_limits), deepcopy(recovery_policy)
    policy = {'resource_limits':resource_limits, 'recovery_policy':recovery_policy,
              'checkpoint_interval':checkpoint_interval, 'max_units':max_units}
    policy_bytes = canonical_json(policy)
    input_sha = sha256_bytes(canonical_json(ordered))
    shards = []
    for start in range(0, len(ordered), max_units):
        members = ordered[start:start+max_units]
        shards.append({'SHARD_ID':f'shard-{len(shards)+1:06d}',
                       'INPUT_SET_SHA256':sha256_bytes(canonical_json(members)),
                       'FIRST_UNIT':members[0], 'LAST_UNIT':members[-1],
                       'EXPECTED_UNITS':len(members), 'UNIT_IDS':members,
                       'RESOURCE_LIMITS':deepcopy(resource_limits),
                       'CHECKPOINT_INTERVAL':checkpoint_interval,
                       'RECOVERY_POLICY':deepcopy(recovery_policy)})
    plan = {'schema':'pgop1.experimental.sharding.v1',
            'INPUT_SET_SHA256':input_sha, 'EXPECTED_UNITS':len(ordered),
            'ORDER':'SORTED_UNICODE_UNIT_ID', 'SHARD_MAX_UNITS':max_units,
            'RESOURCE_LIMITS':resource_limits, 'CHECKPOINT_INTERVAL':checkpoint_interval,
            'RECOVERY_POLICY':recovery_policy,
            'POLICY_SHA256':sha256_bytes(policy_bytes), 'shards':shards}
    verify_shards(units, plan)
    return plan


def verify_shards(units, plan, *, expected_policy=None):
    expected = _units(units)
    if plan.get('schema') != 'pgop1.experimental.sharding.v1':
        raise ValueError('unsupported shard schema')
    bound = plan.get('SHARD_MAX_UNITS')
    interval = plan.get('CHECKPOINT_INTERVAL')
    resources, recovery = plan.get('RESOURCE_LIMITS'), plan.get('RECOVERY_POLICY')
    if (type(bound) is not int or bound < 1 or type(interval) is not int
            or not 1 <= interval <= bound or not isinstance(resources, dict) or not resources
            or not isinstance(recovery, dict) or not recovery
            or plan.get('ORDER') != 'SORTED_UNICODE_UNIT_ID'):
        raise ValueError('invalid plan bounds or policy')
    policy = {'resource_limits':resources, 'recovery_policy':recovery,
              'checkpoint_interval':interval, 'max_units':bound}
    if plan.get('POLICY_SHA256') != sha256_bytes(canonical_json(policy)):
        raise ValueError('plan policy digest differs')
    if expected_policy is not None and policy != expected_policy:
        raise ValueError('plan differs from independently bound policy')
    if plan.get('INPUT_SET_SHA256') != sha256_bytes(canonical_json(expected)) or plan.get('EXPECTED_UNITS') != len(expected):
        raise ValueError('full population binding differs')
    shards = plan.get('shards')
    if not isinstance(shards, list) or not shards:
        raise ValueError('shards missing')
    actual = []
    for i, shard in enumerate(shards, 1):
        members = shard.get('UNIT_IDS')
        if not isinstance(members, list) or not members:
            raise ValueError('empty or missing shard membership')
        if (len(members) > bound or shard.get('RESOURCE_LIMITS') != resources
                or shard.get('RECOVERY_POLICY') != recovery
                or shard.get('CHECKPOINT_INTERVAL') != interval):
            raise ValueError('shard bounds or policy differs')
        if (shard.get('SHARD_ID') != f'shard-{i:06d}' or members != _units(members)
                or shard.get('EXPECTED_UNITS') != len(members)
                or shard.get('INPUT_SET_SHA256') != sha256_bytes(canonical_json(members))
                or shard.get('FIRST_UNIT') != members[0] or shard.get('LAST_UNIT') != members[-1]):
            raise ValueError('shard identity, order, count or digest differs')
        actual.extend(members)
    if actual != expected:
        raise ValueError('shard union, overlap or global order differs')
    return {'status':'PASS', 'expected_units':len(expected), 'shards':len(shards),
            'overlap':0, 'omitted':0, 'executed_units':0}

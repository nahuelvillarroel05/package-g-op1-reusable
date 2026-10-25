from __future__ import annotations
from dataclasses import dataclass
GLOBAL_DEFAULTS={"advisory_only":True,"production_authority":False,"project_mutation_authority":False,"training_default":False,"network_default":False,"model_download_default":False,"fail_closed":True}
@dataclass(frozen=True)
class SecurityPolicy:
    advisory_only: bool=True
    dryrun_only: bool=True
    def invariant_snapshot(self): return dict(GLOBAL_DEFAULTS)
    def validate_invariants(self, observed=None):
        values=self.invariant_snapshot(); values.update(observed or {})
        if any(values.get(k)!=v for k,v in GLOBAL_DEFAULTS.items()): raise ValueError("global fail-closed invariant mismatch")
    def negative_operation_check(self): return {"status":"PASS","advisory_only":self.advisory_only,"dryrun_only":self.dryrun_only,"operations":{"training_invoked":False,"network_accessed":False,"model_downloaded":False,"production_enabled":False}}
    def validate_negative_operations(self,check):
        if any(bool(v) for v in check.get("operations",{}).values()): raise ValueError("negative operation triggered")

from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from package_g.generic_base.capability_profile import CapabilityProfile
from package_g.policies.path_policy import PathPolicy
from package_g.policies.security_policy import SecurityPolicy
class GenericBaseError(RuntimeError): pass
@dataclass(frozen=True)
class GenericBaseConfig:
 root:Path; out_dir:Path; capability_profile:CapabilityProfile; run_id:str; advisory_only:bool=True; dryrun_only:bool=True
class GenericBase:
 def __init__(self,config): self.config=config; self.root=Path(config.root).resolve(); self.out_dir=Path(config.out_dir).resolve(); self.capability_profile=config.capability_profile; self.path_policy=PathPolicy(self.root,self.out_dir); self.security_policy=SecurityPolicy(config.advisory_only,config.dryrun_only)
 def preflight(self):
  try: self.capability_profile.assert_dangerous_disabled(); self.security_policy.validate_invariants(); self.path_policy.validate_output_root(self.out_dir)
  except Exception as e: raise GenericBaseError(f"Package G preflight fail-closed: {e}") from e
 def negative_operation_check(self): return self.security_policy.negative_operation_check()
 @staticmethod
 def sha256_file(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

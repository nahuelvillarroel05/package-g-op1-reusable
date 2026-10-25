from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
class PathPolicyError(ValueError): pass
@dataclass(frozen=True)
class PathPolicy:
    root: Path
    output_root: Path
    def __post_init__(self):
        object.__setattr__(self,"root",Path(self.root).resolve()); object.__setattr__(self,"output_root",Path(self.output_root).resolve())
    def _check(self,path,output=False):
        p=Path(path)
        if ".." in p.parts or str(p).startswith("\\"): raise PathPolicyError("path traversal or UNC path rejected")
        if p.exists() and p.is_symlink(): raise PathPolicyError("symlink rejected")
        r=p.resolve()
        base=self.output_root if output else self.root
        try: r.relative_to(base)
        except ValueError as e: raise PathPolicyError("path outside authorized root") from e
        return r
    def validate_input_path(self,path): return self._check(path)
    def validate_output_root(self,path): return self._check(path,True)

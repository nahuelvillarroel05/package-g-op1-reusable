"""Inert configuration, deterministic planning, and immutable run receipts.

This module does not launch configured code or perform adapter/evaluator work.
Callers must bracket work with begin_unit/complete_unit. Recovery is read-only;
inflight or interrupted publications are never resumed automatically.
"""
from __future__ import annotations
import hashlib, json, os, re, stat, uuid, subprocess, io, tarfile, time
from pathlib import Path, PurePosixPath
from typing import Any
from .preflight_diagnostics import classify_probe_exception, git_inventory_warning
if os.name == "nt":
    import msvcrt
else:
    import fcntl

SCHEMA = "pgop1.experimental.run-execution.v1"
RECEIPT_SCHEMA = "pgop1.reusable-run-receipt.v1"
CHECKPOINT_SCHEMA = "pgop1.reusable-run-checkpoint.v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
PATH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
ZERO = "0" * 64

class FrameworkError(ValueError): pass

class PreflightDiagnosticError(FrameworkError):
    """Framework-compatible failure carrying a sanitized stable diagnostic."""
    def __init__(self, message: str, diagnostic: dict):
        super().__init__(message)
        self.diagnostic = dict(diagnostic)

def canonical(value: Any) -> bytes:
    def valid(x):
        if isinstance(x, float): raise FrameworkError("floating point values are forbidden")
        if isinstance(x, dict):
            if any(not isinstance(k, str) for k in x): raise FrameworkError("JSON object keys must be strings")
            for v in x.values(): valid(v)
        elif isinstance(x, list):
            for v in x: valid(v)
        elif x is not None and not isinstance(x, (str, int, bool)): raise FrameworkError("unsupported JSON value")
    valid(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def digest(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()

def _loads(raw: bytes):
    def hook(pairs):
        result = {}
        for k, v in pairs:
            if k in result: raise FrameworkError("duplicate JSON key")
            result[k] = v
        return result
    try: value = json.loads(raw.decode("utf-8"), object_pairs_hook=hook, parse_constant=lambda _: (_ for _ in ()).throw(FrameworkError("nonfinite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError) as e: raise FrameworkError("invalid UTF-8 JSON") from e
    canonical(value)
    return value

def _path(value, exists=True):
    p = Path(value).absolute()
    for part in (p, *p.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)(): raise FrameworkError("reparse path rejected")
    return p.resolve(strict=exists)

def _within(p, roots): return any(p == r or r in p.parents for r in roots)

def _write_immutable(path: Path, raw: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())

def _git_read(root: Path, *args, binary=False):
    env=os.environ.copy()
    for key in ("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS","GIT_CONFIG_SYSTEM"):
        env.pop(key,None)
    env.update({"GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_NOSYSTEM":"1","GIT_NO_LAZY_FETCH":"1",
                "GIT_TERMINAL_PROMPT":"0","GIT_OPTIONAL_LOCKS":"0"})
    command=["git","--no-optional-locks","-c",f"safe.directory={root}","-c","core.fsmonitor=false",
             "-c",f"core.hooksPath={os.devnull}","-C",str(root),*args]
    return subprocess.run(command,check=True,capture_output=True,text=not binary,timeout=10,env=env)


def _verify_committed_code(root, commit, bindings):
    """Verify all pinned file bytes with one in-memory Git archive; never extract.

    Archive export rules can only cause a mismatch/missing-file rejection. Every
    expected file must appear once as a regular file with its exact SHA256.
    """
    expected = {_path(item["path"], True).relative_to(root).as_posix(): item["sha256"] for item in bindings}
    if len(expected) != len(bindings):
        raise FrameworkError("duplicate candidate code path")
    try:
        raw = _git_read(root, "archive", "--format=tar", commit, "--", *expected, binary=True).stdout
        found = set()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile() or member.name not in expected or member.name in found:
                    raise FrameworkError("candidate archive contains unexpected or nonregular member")
                stream = archive.extractfile(member)
                if stream is None or digest(stream.read()) != expected[member.name]:
                    raise FrameworkError("candidate file hash differs from committed bytes")
                found.add(member.name)
        if found != set(expected):
            raise FrameworkError("candidate code file is not committed at selected commit")
    except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        raise FrameworkError("candidate committed code archive could not be verified") from exc

class Campaign:
    def __init__(self, cfg, config_sha256, config_path, config_roots, output, output_roots):
        self.config, self.config_sha256 = cfg, config_sha256
        self._config_snapshot=canonical(cfg)
        self.config_path=_path(config_path,True)
        self.config_roots=[_path(x,True) for x in config_roots]
        requested_output = Path(output).absolute()
        self._can_write = not requested_output.exists()
        self._write_blocked = False
        self._writer_token=uuid.uuid4().hex
        self.output = _path(output, exists=False)
        self.output_roots=[_path(x,True) for x in output_roots]
        self.registry_root=self.output_roots[0]
        self._registered=False
        self.run_id = cfg["run_id"]
        self._preflight = None
        self._committed_code_verified = None

    def preflight(self):
        if canonical(self.config)!=self._config_snapshot:
            raise FrameworkError("in-memory external configuration changed after load")
        self.config_path=_path(self.config_path,True)
        if not self.config_path.is_file() or not _within(self.config_path,self.config_roots):
            raise FrameworkError("external configuration path escaped caller root")
        if digest(self.config_path.read_bytes())!=self.config_sha256:
            raise FrameworkError("external configuration bytes changed after load")
        cfg = self.config
        roots = [_path(x, True) for x in cfg["allowlisted_roots"]]
        rows=[]
        descriptors = [(group,item) for group in ("code_files","input_bindings") for item in cfg[group]]
        descriptors += [(group,cfg[group]) for group in ("adapter_registry","predicate_contracts","selection_manifest","exclusion_ledger")]
        for group,item in descriptors:
            p=_path(item["path"], True)
            if not p.is_file() or not _within(p, roots): raise FrameworkError("bound file outside allowlist or not regular")
            h=digest(p.read_bytes())
            if h != item["sha256"]: raise FrameworkError("bound file byte hash mismatch: "+item["path"])
            rows.append({"path":str(p),"sha256":h,"role":group})
        code_root=_path(cfg["code_root"], True)
        if not code_root.is_dir() or not _within(code_root, roots): raise FrameworkError("code root outside allowlist")
        if any(not _within(_path(x["path"],True),[code_root]) for x in cfg["code_files"]):
            raise FrameworkError("candidate code binding is outside code root")
        for field, expected in (("contract_path",cfg["contract_sha256"]),("dataset_manifest_path",cfg["input_manifest_sha256"])):
            p=_path(cfg[field],True)
            if not _within(p,roots) or not p.is_file() or digest(p.read_bytes())!=expected: raise FrameworkError(field+" byte binding mismatch")
        selected=_loads(_path(cfg["selection_manifest"]["path"],True).read_bytes())
        if not isinstance(selected,dict) or selected.get("expected_units")!=cfg["expected_units"]:
            raise FrameworkError("expected units do not exactly match frozen selection manifest")
        git_started = time.monotonic()
        try:
            commit=_git_read(code_root,"rev-parse","HEAD").stdout.strip()
            tree=_git_read(code_root,"rev-parse","HEAD^{tree}").stdout.strip()
            status_result=_git_read(code_root,"status","--porcelain","--untracked-files=normal")
            status=status_result.stdout
        except (OSError,subprocess.SubprocessError) as e:
            elapsed_ms = max(0, int((time.monotonic() - git_started) * 1000))
            raise PreflightDiagnosticError(
                "candidate Git identity could not be verified",
                classify_probe_exception(e, elapsed_ms=elapsed_ms)) from None
        if commit!=cfg["candidate_commit"] or tree!=cfg["candidate_tree"]: raise FrameworkError("candidate Git identity mismatch")
        if status.strip(): raise FrameworkError("candidate working tree is dirty")
        if status_result.stderr.strip():
            elapsed_ms = max(0, int((time.monotonic() - git_started) * 1000))
            raise PreflightDiagnosticError(
                "candidate Git inventory emitted warnings",
                git_inventory_warning(elapsed_ms=elapsed_ms))
        # Only the immutable committed-object comparison is reusable. All live
        # file bytes, paths, HEAD/tree and Git dirtiness were checked above on
        # this invocation. Never cache source bodies or working-tree checks.
        committed_key = (str(code_root), commit, tree,
                         canonical(cfg["code_files"]))
        if self._committed_code_verified != committed_key:
            _verify_committed_code(code_root, commit, cfg["code_files"])
            self._committed_code_verified = committed_key
        self._preflight={"run_id":self.run_id,"campaign_id":cfg["campaign_id"],"contract_version":cfg["contract_version"],
            "config_sha256":self.config_sha256,"candidate_commit":commit,"candidate_tree":tree,
            "candidate_code_sha256":digest(canonical(sorted(rows,key=lambda x:(x["role"],x["path"])))),
            "input_manifest_sha256":cfg["input_manifest_sha256"],"contract_sha256":cfg["contract_sha256"],
            "files":sorted(rows,key=lambda x:(x["role"],x["path"]))}
        return dict(self._preflight)

    def shard_plan(self):
        self.preflight()
        from .planning import plan_shards, verify_shards
        budget=self.config["resource_budget"]
        maximum=budget.get("max_units_per_shard")
        interval=self.config["checkpoint_policy"].get("interval")
        plan=plan_shards(self.config["expected_units"],max_units=maximum,
                         resource_limits=budget,checkpoint_interval=interval,
                         recovery_policy=self.config["recovery_policy"])
        verify_shards(self.config["expected_units"],plan,expected_policy={
            "max_units":maximum,"checkpoint_interval":interval,"resource_limits":budget,
            "recovery_policy":self.config["recovery_policy"]})
        return plan

    def _acquire(self):
        out=_path(self.output,False)
        if not _within(out,self.output_roots): raise FrameworkError("output root binding changed")
        self.output.mkdir(parents=True,exist_ok=True)
        out=_path(self.output,True)
        if out!=self.output or not _within(out,self.output_roots): raise FrameworkError("output reparse/path changed during creation")
        p=self.output/"writer.lock"
        _path(p,False)
        if p.exists() or p.is_symlink():
            st=p.lstat()
            if stat.S_ISLNK(st.st_mode) or getattr(p,"is_junction",lambda:False)() or not stat.S_ISREG(st.st_mode):
                raise FrameworkError("writer lock path is not a regular file")
        flags=os.O_CREAT|os.O_RDWR
        if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
        fd=os.open(p,flags,0o600)
        try:
            st=os.fstat(fd)
            path_stat=p.lstat()
            if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(path_stat.st_mode)
                    or getattr(p,"is_junction",lambda:False)() or not os.path.samestat(path_stat,st)):
                raise FrameworkError("writer lock ownership mismatch")
            if os.name=="nt":
                if st.st_size==0: os.write(fd,b"0"); os.fsync(fd)
                os.lseek(fd,0,os.SEEK_SET); msvcrt.locking(fd,msvcrt.LK_LOCK,1)
            else: fcntl.flock(fd,fcntl.LOCK_EX)
            return fd
        except BaseException: os.close(fd); raise
    @staticmethod
    def _release(fd):
        try:
            if os.name=="nt": os.lseek(fd,0,os.SEEK_SET); msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)

    def _publish(self, state, kind, unit, phase, payload):
        seq=len(state["receipts"])+1
        attempt_id=state["open_attempts"].get(unit) if phase=="terminal" else f"{self.config['campaign_id']}:{self.run_id}:{self.config['campaign_attempt_id']}:{unit}:{uuid.uuid4().hex}"
        if not attempt_id: raise FrameworkError("terminal receipt has no bound start identity")
        receipt={"schema":RECEIPT_SCHEMA,"run_id":self.run_id,"campaign_id":self.config["campaign_id"],
            "attempt_id":attempt_id,"unit_id":unit,"phase":phase,"disposition":kind,"sequence":seq,
            "parent_receipt_sha256":state["receipts"][-1]["sha256"] if state["receipts"] else None,
            "bindings":{k:self._preflight[k] for k in ("config_sha256","contract_sha256","candidate_commit","candidate_tree","candidate_code_sha256","input_manifest_sha256")},
            "payload":payload}
        raw=canonical(receipt); sha=digest(raw); name=f"receipts/{seq:08d}-{sha}.json"
        _write_immutable(self.output/name,raw)
        rec={"sequence":seq,"path":name,"sha256":sha,"attempt_id":attempt_id,"unit_id":unit,"phase":phase}
        receipts=state["receipts"]+[rec]
        completed=set(state["completed"]); pending=set(state["pending"]); inflight=set(state["inflight"])
        if phase=="start": pending.discard(unit); inflight.add(unit)
        else: inflight.discard(unit); completed.add(unit)
        checkpoint={"schema":CHECKPOINT_SCHEMA,"run_id":self.run_id,"campaign_id":self.config["campaign_id"],
            "sequence":len(state["checkpoints"])+1,"parent_checkpoint_sha256":state["checkpoints"][-1]["sha256"] if state["checkpoints"] else None,
            "ordered_receipt_sha256":[r["sha256"] for r in receipts],"completed_units":sorted(completed),
            "pending_units":sorted(pending),"inflight_units":sorted(inflight),"bindings":self._preflight}
        cpraw=canonical(checkpoint); cph=digest(cpraw); cpname=f"checkpoints/{checkpoint['sequence']:08d}-{cph}.json"
        _write_immutable(self.output/cpname,cpraw)
        idx={"sequence":len(state["index"])+1,"receipt_path":name,"receipt_sha256":sha,"checkpoint_path":cpname,"checkpoint_sha256":cph}
        # Index records are also canonical UTF-8 with one framing newline.
        with (self.output/"INDEX.jsonl").open("ab") as f: f.write(canonical(idx)+b"\n"); f.flush(); os.fsync(f.fileno())
        return {**receipt,"receipt_path":name,"receipt_sha256":sha,"checkpoint_path":cpname,"checkpoint_sha256":cph}

    def recover(self):
        if self._preflight is None: raise FrameworkError("preflight required")
        frozen=self._preflight
        try: current=self.preflight()
        except BaseException: raise
        if current!=frozen: raise FrameworkError("bound files changed since preflight; recovery blocked")
        if not _within(_path(self.output,False),self.output_roots): raise FrameworkError("output root binding changed")
        index_path=self.output/"INDEX.jsonl"
        registry_dir=self.registry_root/".pgop1-run-registry"
        run_marker=registry_dir/(self.run_id+".json")
        attempt_registry=self.registry_root/".pgop1-attempt-registry"
        attempt_key=digest(canonical([self.run_id,self.config["campaign_attempt_id"]]))
        attempt_marker=attempt_registry/(attempt_key+".json")
        for directory in (registry_dir,attempt_registry):
            _path(directory,False)
            if directory.exists() and _path(directory,True)!=directory.resolve(strict=True):
                raise FrameworkError("registry directory reparse/path rejected")
        for marker_path in (run_marker,attempt_marker):
            _path(marker_path,False)
            if marker_path.exists() and _path(marker_path,True)!=marker_path.resolve(strict=True):
                raise FrameworkError("registry marker reparse/path rejected")
        if not index_path.exists():
            if (any((self.output/x).exists() for x in ("receipts","checkpoints","writer.owner")) or attempt_marker.exists()):
                raise FrameworkError("orphan or interrupted publication without index; recovery blocked")
            units=set(self.config["expected_units"])
            return {"receipts":[],"checkpoints":[],"index":[],"completed":set(),"pending":units,"inflight":set(),"open_attempts":{},"complete":False}
        expected_run={"schema":"pgop1.experimental.run-id-reservation.v1","run_id":self.run_id,
                      "campaign_id":self.config["campaign_id"]}
        expected_attempt={"schema":"pgop1.experimental.run-attempt-reservation.v1","run_id":self.run_id,
                          "campaign_id":self.config["campaign_id"],"campaign_attempt_id":self.config["campaign_attempt_id"],
                          "config_sha256":self.config_sha256}
        if (not run_marker.is_file() or run_marker.is_symlink() or _loads(run_marker.read_bytes())!=expected_run
                or not attempt_marker.is_file() or attempt_marker.is_symlink() or _loads(attempt_marker.read_bytes())!=expected_attempt):
            raise FrameworkError("global run/attempt reservation missing or changed")
        if _path(index_path,True)!=index_path.resolve(strict=True) or index_path.is_symlink() or not index_path.is_file(): raise FrameworkError("index reparse/type rejected")
        raw=index_path.read_bytes()
        if raw and not raw.endswith(b"\n"): raise FrameworkError("interrupted index append; recovery blocked")
        lines=raw.splitlines(); rows=[_loads(x) for x in lines]
        if any(canonical(row)!=line for row,line in zip(rows,lines)): raise FrameworkError("noncanonical index record")
        owner_path=self.output/"writer.owner"
        if not owner_path.is_file() or owner_path.is_symlink(): raise FrameworkError("writer ownership receipt missing or unsafe")
        owner=_loads(owner_path.read_bytes())
        if (not isinstance(owner,dict) or set(owner)!={"schema","run_id","campaign_id","campaign_attempt_id","token"}
                or owner.get("schema")!="pgop1.reusable-run-writer-owner.v1"
                or owner.get("run_id")!=self.run_id or owner.get("campaign_id")!=self.config["campaign_id"]
                or owner.get("campaign_attempt_id")!=self.config["campaign_attempt_id"]
                or not isinstance(owner.get("token"),str) or not owner["token"]):
            raise FrameworkError("writer ownership binding invalid")
        receipts=[]; checkpoints=[]; completed=set(); inflight=set(); pending=set(self.config["expected_units"]); previous_receipt=None; previous_cp=None; attempt_open={}; seen_attempts=set()
        bindings={k:self._preflight[k] for k in ("config_sha256","contract_sha256","candidate_commit","candidate_tree","candidate_code_sha256","input_manifest_sha256")}
        for i,row in enumerate(rows,1):
            if (not isinstance(row,dict) or set(row)!={"sequence","receipt_path","receipt_sha256","checkpoint_path","checkpoint_sha256"}
                    or type(row["sequence"]) is not int or row["sequence"]!=i
                    or not all(isinstance(row[k],str) for k in ("receipt_path","receipt_sha256","checkpoint_path","checkpoint_sha256"))
                    or not HEX.fullmatch(row["receipt_sha256"]) or not HEX.fullmatch(row["checkpoint_sha256"])):
                raise FrameworkError("index sequence/schema invalid")
            rp=row["receipt_path"]; cp=row["checkpoint_path"]
            rp_parts=PurePosixPath(rp).parts; cp_parts=PurePosixPath(cp).parts
            if (len(rp_parts)!=2 or rp_parts[0]!="receipts" or rp_parts[1]!=f"{i:08d}-{row['receipt_sha256']}.json"
                    or len(cp_parts)!=2 or cp_parts[0]!="checkpoints" or cp_parts[1]!=f"{len(checkpoints)+1:08d}-{row['checkpoint_sha256']}.json"):
                raise FrameworkError("unsafe immutable artifact path")
            receipt_path=self.output/rp; checkpoint_path=self.output/cp
            if (_path(receipt_path,True)!=receipt_path.resolve(strict=True) or _path(checkpoint_path,True)!=checkpoint_path.resolve(strict=True)
                    or not _within(receipt_path.resolve(),[self.output]) or not _within(checkpoint_path.resolve(),[self.output])):
                raise FrameworkError("immutable artifact reparse/path rejected")
            rb=receipt_path.read_bytes(); cb=checkpoint_path.read_bytes()
            if digest(rb)!=row["receipt_sha256"] or digest(cb)!=row["checkpoint_sha256"]: raise FrameworkError("immutable artifact digest mismatch")
            r=_loads(rb); c=_loads(cb)
            if canonical(r)!=rb or canonical(c)!=cb: raise FrameworkError("noncanonical immutable payload")
            receipt_fields={"schema","run_id","campaign_id","attempt_id","unit_id","phase","disposition","sequence","parent_receipt_sha256","bindings","payload"}
            checkpoint_fields={"schema","run_id","campaign_id","sequence","parent_checkpoint_sha256","ordered_receipt_sha256","completed_units","pending_units","inflight_units","bindings"}
            if set(r)!=receipt_fields or set(c)!=checkpoint_fields: raise FrameworkError("receipt/checkpoint field set differs")
            if (r.get("schema")!=RECEIPT_SCHEMA or c.get("schema")!=CHECKPOINT_SCHEMA
                    or r.get("run_id")!=self.run_id or c.get("run_id")!=self.run_id
                    or r.get("campaign_id")!=self.config["campaign_id"] or c.get("campaign_id")!=self.config["campaign_id"]):
                raise FrameworkError("run identity/schema mismatch")
            if (type(r.get("sequence")) is not int or r.get("sequence")!=i
                    or r.get("parent_receipt_sha256")!=previous_receipt
                    or r.get("bindings")!=bindings): raise FrameworkError("receipt parent/sequence/binding mismatch")
            unit=r.get("unit_id"); phase=r.get("phase")
            if not isinstance(unit,str) or unit not in pending|inflight|completed or phase not in ("start","terminal"):
                raise FrameworkError("unknown unit or phase")
            if (phase=="start" and r.get("disposition")!="STARTED") or (phase=="terminal" and (not isinstance(r.get("disposition"),str) or not r["disposition"])):
                raise FrameworkError("receipt disposition/phase invalid")
            if phase=="start":
                if unit not in pending: raise FrameworkError("duplicate or invalid start")
                expected_prefix=f"{self.config['campaign_id']}:{self.run_id}:{self.config['campaign_attempt_id']}:{unit}:"
                attempt_id=r.get("attempt_id")
                if not isinstance(attempt_id,str) or not attempt_id.startswith(expected_prefix) or attempt_id in seen_attempts:
                    raise FrameworkError("attempt identity is malformed or duplicated")
                seen_attempts.add(attempt_id)
                pending.remove(unit); inflight.add(unit); attempt_open[unit]=r.get("attempt_id")
            else:
                if unit not in inflight or unit not in attempt_open: raise FrameworkError("terminal without unique start")
                if r.get("attempt_id") != attempt_open[unit]: raise FrameworkError("attempt identity changed between start and terminal")
                inflight.remove(unit); completed.add(unit); del attempt_open[unit]
            if (type(c.get("sequence")) is not int or c.get("sequence")!=len(checkpoints)+1
                    or c.get("parent_checkpoint_sha256")!=previous_cp
                    or c.get("ordered_receipt_sha256")!=[x["sha256"] for x in receipts]+[row["receipt_sha256"]]):
                raise FrameworkError("checkpoint chain/membership mismatch")
            if c.get("bindings")!=self._preflight or c.get("completed_units")!=sorted(completed) or c.get("pending_units")!=sorted(pending) or c.get("inflight_units")!=sorted(inflight): raise FrameworkError("checkpoint set/binding mismatch")
            receipts.append({"sha256":row["receipt_sha256"],"sequence":i,"path":rp,"unit_id":unit,"phase":phase}); checkpoints.append({"sha256":row["checkpoint_sha256"],"path":cp}); previous_receipt=row["receipt_sha256"]; previous_cp=row["checkpoint_sha256"]
        expected_receipts={Path(x["path"]).name for x in receipts}; expected_checkpoints={Path(x["path"]).name for x in checkpoints}
        actual_receipts={p.name for p in (self.output/"receipts").glob("*")} if (self.output/"receipts").exists() else set()
        actual_checkpoints={p.name for p in (self.output/"checkpoints").glob("*")} if (self.output/"checkpoints").exists() else set()
        if actual_receipts != expected_receipts or actual_checkpoints != expected_checkpoints: raise FrameworkError("orphan immutable artifact; interrupted publication blocks recovery")
        return {"receipts":receipts,"checkpoints":checkpoints,"index":rows,"completed":completed,"pending":pending,"inflight":inflight,"open_attempts":attempt_open,"complete":not pending and not inflight}

    def begin_unit(self,unit_id:str,payload:dict[str,Any]):
        return self._record(unit_id,"STARTED","start",payload)
    def complete_unit(self,unit_id:str,disposition:str,payload:dict[str,Any]):
        if not isinstance(disposition,str) or not disposition: raise FrameworkError("terminal disposition required")
        return self._record(unit_id,disposition,"terminal",payload)
    def _record(self,unit,kind,phase,payload):
        if self._preflight is None: raise FrameworkError("preflight required")
        if not self._can_write or self._write_blocked: raise FrameworkError("existing or interrupted run is read-only; fresh RUN_ID required")
        if unit not in self.config["expected_units"] or not isinstance(payload,dict): raise FrameworkError("unit/payload invalid")
        canonical(payload)
        original=self._preflight
        try:
            current=self.preflight()
        except BaseException:
            self._write_blocked=True
            raise
        if current != original:
            self._write_blocked=True
            raise FrameworkError("bound files changed after preflight; run quarantined")
        fd=self._acquire()
        try:
            state=self.recover()
            self._claim_writer()
            if (phase=="start" and unit not in state["pending"]) or (phase=="terminal" and unit not in state["inflight"]): raise FrameworkError("unit is not in required lifecycle state")
            try:
                return self._publish(state,kind,unit,phase,payload)
            except BaseException:
                self._write_blocked = True
                raise
        finally: self._release(fd)

    def _claim_writer(self):
        path=self.output/"writer.owner"
        registry=self.registry_root/".pgop1-run-registry"
        _path(self.registry_root,True)
        if registry.exists() and (registry.is_symlink() or getattr(registry,"is_junction",lambda:False)()): raise FrameworkError("run registry reparse rejected")
        registry.mkdir(parents=True,exist_ok=True)
        _path(registry,True)
        registration=registry/(self.run_id+".json")
        marker={"schema":"pgop1.experimental.run-id-reservation.v1","run_id":self.run_id,
                "campaign_id":self.config["campaign_id"]}
        attempt_registry=self.registry_root/".pgop1-attempt-registry"
        if attempt_registry.exists() and (attempt_registry.is_symlink() or getattr(attempt_registry,"is_junction",lambda:False)()): raise FrameworkError("attempt registry reparse rejected")
        attempt_registry.mkdir(parents=True,exist_ok=True)
        _path(attempt_registry,True)
        attempt_key=digest(canonical([self.run_id,self.config["campaign_attempt_id"]]))
        attempt_registration=attempt_registry/(attempt_key+".json")
        attempt_marker={"schema":"pgop1.experimental.run-attempt-reservation.v1","run_id":self.run_id,
                       "campaign_id":self.config["campaign_id"],"campaign_attempt_id":self.config["campaign_attempt_id"],
                       "config_sha256":self.config_sha256}
        if not self._registered:
            if registration.exists():
                if _path(registration,True)!=registration.resolve(strict=True) or registration.is_symlink() or _loads(registration.read_bytes())!=marker:
                    raise FrameworkError("RUN_ID is already bound to another campaign")
            else: _write_immutable(registration,canonical(marker))
            try: _write_immutable(attempt_registration,canonical(attempt_marker))
            except FileExistsError: raise FrameworkError("campaign attempt ID already reserved; fresh attempt ID required")
            self._registered=True
        expected={"schema":"pgop1.reusable-run-writer-owner.v1","run_id":self.run_id,
                  "campaign_id":self.config["campaign_id"],"campaign_attempt_id":self.config["campaign_attempt_id"],"token":self._writer_token}
        try:
            _write_immutable(path,canonical(expected))
        except FileExistsError:
            if path.is_symlink() or not path.is_file(): raise FrameworkError("writer owner record path invalid")
            observed=_loads(path.read_bytes())
            if observed!=expected: raise FrameworkError("another writer owns this run namespace; recovery is read-only")

    def report(self):
        s=self.recover()
        return {"schema":"pgop1.reusable-run-report.v1","run_id":self.run_id,"campaign_id":self.config["campaign_id"],
            "config_sha256":self.config_sha256,"contract_sha256":self.config["contract_sha256"],
            "candidate_commit":self.config["candidate_commit"],"candidate_tree":self.config["candidate_tree"],
            "input_manifest_sha256":self.config["input_manifest_sha256"],"expected_count":len(self.config["expected_units"]),
            "completed_count":len(s["completed"]),"pending_units":sorted(s["pending"]),"inflight_units":sorted(s["inflight"]),
            "status":"COMPLETE_WITH_DISPOSITIONS" if s["complete"] else "PARTIAL","execution_completeness":"NOT_CERTIFIED",
            "receipt_count":len(s["receipts"]),"checkpoint_count":len(s["checkpoints"])}

def load_config(path, allowed_config_roots, output, trusted_path_roots, trusted_output_roots):
    p=_path(path,True); roots=[_path(x,True) for x in allowed_config_roots]
    if not p.is_file() or not _within(p,roots): raise FrameworkError("configuration outside trusted caller roots")
    raw=p.read_bytes(); c=_loads(raw)
    required={"schema","campaign_id","run_id","campaign_attempt_id","contract_version","run_purpose","candidate_commit","candidate_tree","code_root","code_files","contract_path","contract_sha256","dataset_manifest_path","input_manifest_sha256","input_bindings","benchmark_families","adapter_registry","predicate_contracts","execution_modes","selection_manifest","exclusion_ledger","resource_budget","stop_criteria","checkpoint_policy","recovery_policy","audit_policy","allowlisted_roots","expected_units"}
    if not isinstance(c,dict) or set(c)!=required or c["schema"]!=SCHEMA: raise FrameworkError("configuration schema/fields invalid")
    for k in ("campaign_id","run_id","campaign_attempt_id","contract_version","candidate_commit","candidate_tree"):
        if not isinstance(c[k],str) or not IDENT.fullmatch(c[k]): raise FrameworkError("invalid identity: "+k)
    for k in ("run_id","campaign_attempt_id"):
        stem=c[k].split(".",1)[0].upper()
        if (not PATH_ID.fullmatch(c[k]) or c[k] in {".",".."} or c[k].endswith(".")
                or stem in {"CON","PRN","AUX","NUL",*(f"COM{i}" for i in range(1,10)),*(f"LPT{i}" for i in range(1,10))}):
            raise FrameworkError("unsafe path identity: "+k)
    for k in ("contract_sha256","input_manifest_sha256"):
        if not isinstance(c[k],str) or not HEX.fullmatch(c[k]): raise FrameworkError("invalid digest: "+k)
    if not isinstance(c["allowlisted_roots"],list) or not c["allowlisted_roots"] or not all(isinstance(x,str) for x in c["allowlisted_roots"]): raise FrameworkError("explicit allowed roots required")
    trusted=[_path(x,True) for x in trusted_path_roots]
    if not trusted: raise FrameworkError("independent trusted path roots required")
    configured=[_path(x,True) for x in c["allowlisted_roots"]]
    if any(not _within(root,trusted) for root in configured): raise FrameworkError("configuration allowlist exceeds caller trusted roots")
    output_path=_path(output,False); output_roots=[_path(x,True) for x in trusted_output_roots]
    if len(output_roots)!=1 or not _within(output_path,output_roots): raise FrameworkError("one canonical caller trusted output root is required")
    if not any(output_path.relative_to(root).parts==(c["run_id"],"attempts",c["campaign_attempt_id"]) for root in output_roots if _within(output_path,[root])):
        raise FrameworkError("output must be <trusted_root>/<RUN_ID>/attempts/<campaign_attempt_id>")
    if not isinstance(c["run_purpose"],str) or not c["run_purpose"]: raise FrameworkError("run_purpose required")
    for k in ("benchmark_families","execution_modes"):
        if not isinstance(c[k],list) or not c[k] or any(not isinstance(x,str) or not x for x in c[k]) or len(set(c[k]))!=len(c[k]): raise FrameworkError(k+" must be unique nonempty strings")
    for k in ("adapter_registry","predicate_contracts","selection_manifest","exclusion_ledger"):
        if not isinstance(c[k],dict) or set(c[k])!={"path","sha256"} or not isinstance(c[k]["path"],str) or not isinstance(c[k]["sha256"],str) or not HEX.fullmatch(c[k]["sha256"]): raise FrameworkError(k+" binding invalid")
    for k in ("resource_budget","stop_criteria","checkpoint_policy","recovery_policy","audit_policy"):
        if not isinstance(c[k],dict) or not c[k]: raise FrameworkError(k+" policy required")
    if type(c["resource_budget"].get("max_units_per_shard")) is not int or c["resource_budget"]["max_units_per_shard"]<1:
        raise FrameworkError("resource_budget.max_units_per_shard must be a positive integer")
    if type(c["checkpoint_policy"].get("interval")) is not int or not 1<=c["checkpoint_policy"]["interval"]<=c["resource_budget"]["max_units_per_shard"]:
        raise FrameworkError("checkpoint_policy.interval must be bounded by shard size")
    if c["recovery_policy"].get("mode")!="READ_ONLY_NO_RESUME": raise FrameworkError("recovery_policy must prohibit resume")
    for k in ("code_files","input_bindings"):
        if not isinstance(c[k],list) or not c[k]: raise FrameworkError("nonempty "+k+" required")
        paths=set()
        for x in c[k]:
            if not isinstance(x,dict) or set(x)!={"path","sha256"} or not isinstance(x["path"],str) or not isinstance(x["sha256"],str) or not HEX.fullmatch(x["sha256"]): raise FrameworkError("invalid "+k+" binding")
            if x["path"] in paths: raise FrameworkError("duplicate bound path")
            paths.add(x["path"])
    u=c["expected_units"]
    if not isinstance(u,list) or not u or any(not isinstance(x,str) or not IDENT.fullmatch(x) for x in u) or len(set(u))!=len(u): raise FrameworkError("expected_units must be unique identifiers")
    for k in ("contract_path","dataset_manifest_path"):
        if not isinstance(c[k],str): raise FrameworkError(k+" required")
    if not isinstance(c["code_root"],str): raise FrameworkError("code_root required")
    checkpoint_schema=c["checkpoint_policy"].get("schema",CHECKPOINT_SCHEMA)
    if checkpoint_schema=="pgop1.reusable-run-checkpoint.v2":
        from .incremental import CampaignV2
        return CampaignV2(c,digest(raw),p,roots,output,output_roots)
    if checkpoint_schema!=CHECKPOINT_SCHEMA:
        raise FrameworkError("unsupported checkpoint schema")
    return Campaign(c,digest(raw),p,roots,output,output_roots)

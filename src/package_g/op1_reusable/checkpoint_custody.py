"""Owner-side, append-only checkpoint journal for I1 engineering.

The signer must run under a separately provisioned Windows SID with an owner-only
key and root. Tests that run both roles under one SID are synthetic and do not
qualify custody or grant operational admission.
"""
from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import secrets
import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import native_ntfs
from .identity import canonical_json, sha256_bytes, strict_json_loads, validate_id, validate_sha256
from .integrity import IntegrityVerifier, checkpoint_payload
from .storage_paths import StoragePaths, check_ancestors, pin_parent_directories


_CHECKPOINT_NAME = re.compile(r"CHK-([0-9]{6})\.json\Z")
_MANIFEST_NAME = re.compile(r"([0-9]{12})-PG-ART-[0-9a-f]{32}\.json\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_REQUEST_KEYS = frozenset({"sign_request_id", "checkpoint"})
_CHECKPOINT_KEYS = frozenset({
    "checkpoint_id", "sequence", "root_id", "genesis_checkpoint", "previous_checkpoint_id",
    "previous_checkpoint_sha256", "payload_sha256", "manifest_count",
    "signer_actor_id", "signing_key_id", "created_at_utc",
    "source_lineage_id", "source_version_id", "store_id",
    "evidence_root_identity", "store_header_sha256",
})
_RECEIPT_KEYS = frozenset({
    "checkpoint", "sign_request_id", "sign_receipt_id", "signature_id",
    "signature_hex", "admission_signature_hex", "sign_request_sha256", "checkpoint_payload_sha256",
})


class CheckpointError(RuntimeError):
    """Custody input, chain, or publication is uncertain; no authority follows."""


@dataclass(frozen=True)
class ChainTrust:
    signer_actor_id: str
    signing_key_id: str
    public_key_hex: str
    signer_sid: str
    writer_sid: str
    custody_root_identity: str
    request_root_identity: str
    evidence_root_identity: str
    store_header_sha256: str
    store_id: str
    lineage_id: str
    version_id: str
    writer_boundary: str = "WINDOWS_ACCOUNT"
    writer_appcontainer_sid: str | None = None

    @property
    def root_id(self) -> str:
        return "ROOT-" + sha256_bytes(self.custody_root_identity.encode("ascii"))[:32]

    def __post_init__(self) -> None:
        validate_id(self.signer_actor_id, "ACTOR")
        validate_id(self.store_id, "RESOURCE")
        validate_id(self.lineage_id, "LINEAGE")
        validate_id(self.version_id, "VERSION")
        if not re.fullmatch(r"KEY-[0-9a-f]{32}", self.signing_key_id):
            raise CheckpointError("invalid signing key ID")
        if not _SID.fullmatch(self.signer_sid) or not _SID.fullmatch(self.writer_sid):
            raise CheckpointError("exact Windows SID required")
        if self.writer_boundary == "WINDOWS_ACCOUNT":
            if self.signer_sid == self.writer_sid or self.writer_appcontainer_sid is not None:
                raise CheckpointError("distinct Windows account writer required")
        elif self.writer_boundary == "WINDOWS_APPCONTAINER":
            if (not isinstance(self.writer_appcontainer_sid, str)
                    or not re.fullmatch(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+", self.writer_appcontainer_sid)):
                raise CheckpointError("exact writer AppContainer package SID required")
        else:
            raise CheckpointError("unsupported writer boundary")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key_hex))
        except (ValueError, TypeError) as exc:
            raise CheckpointError("invalid pinned public key") from exc
        if len(self.public_key_hex) != 64:
            raise CheckpointError("invalid pinned public key length")
        if self.signing_key_id != "KEY-" + sha256_bytes(bytes.fromhex(self.public_key_hex))[:32]:
            raise CheckpointError("signing key ID differs from public key")
        for value in (self.custody_root_identity, self.request_root_identity, self.evidence_root_identity):
            if not re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{32}", value):
                raise CheckpointError("invalid pinned NTFS root identity")
        validate_sha256(self.store_header_sha256)


def current_sid() -> str:
    """Get the actual process-token user SID, without a caller-supplied name."""
    if os.name != "nt":
        raise CheckpointError("Windows process token required")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    adv.OpenProcessToken.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
    ]
    adv.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    adv.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p),
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token = ctypes.c_void_p()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise CheckpointError("cannot open process token")
    try:
        size = ctypes.c_uint32()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if size.value < ctypes.sizeof(ctypes.c_void_p):
            raise CheckpointError("cannot size token user")
        buffer = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise CheckpointError("cannot read token user")
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        sid_string = ctypes.c_wchar_p()
        if not adv.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_string)):
            raise CheckpointError("cannot format token SID")
        try:
            value = sid_string.value
        finally:
            kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        if not value or not _SID.fullmatch(value):
            raise CheckpointError("invalid process-token SID")
        return value
    finally:
        kernel.CloseHandle(token)


def current_appcontainer_identity() -> tuple[str | None, int]:
    """Read package SID and capability count from the process primary token."""
    if os.name != "nt":
        raise CheckpointError("Windows process token required")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    adv.OpenProcessToken.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
    ]
    adv.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    adv.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p),
    ]
    token = ctypes.c_void_p()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise CheckpointError("cannot open process token")
    try:
        def info(kind: int) -> ctypes.Array:
            size = ctypes.c_uint32()
            adv.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
            if not 1 <= size.value <= 65536:
                raise CheckpointError("cannot size process token information")
            buffer = ctypes.create_string_buffer(size.value)
            if not adv.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
                raise CheckpointError("cannot read process token information")
            return buffer

        app_flag = info(29)  # TokenIsAppContainer
        if len(app_flag) < ctypes.sizeof(ctypes.c_uint32):
            raise CheckpointError("invalid AppContainer flag")
        if ctypes.c_uint32.from_buffer(app_flag).value == 0:
            return None, 0
        app_info = info(31)  # TokenAppContainerSid
        if len(app_info) < ctypes.sizeof(ctypes.c_void_p):
            raise CheckpointError("invalid AppContainer SID information")
        sid_pointer = ctypes.c_void_p.from_buffer(app_info).value
        if not sid_pointer:
            raise CheckpointError("AppContainer token lacks package SID")
        sid_string = ctypes.c_wchar_p()
        if not adv.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_string)):
            raise CheckpointError("cannot format AppContainer SID")
        try:
            package_sid = sid_string.value
        finally:
            kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        if not package_sid or not re.fullmatch(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+", package_sid):
            raise CheckpointError("invalid process AppContainer SID")
        groups = info(30)  # TokenCapabilities, TOKEN_GROUPS begins with DWORD GroupCount.
        if len(groups) < ctypes.sizeof(ctypes.c_uint32):
            raise CheckpointError("invalid AppContainer capabilities")
        return package_sid, ctypes.c_uint32.from_buffer(groups).value
    finally:
        kernel.CloseHandle(token)


def _assert_no_thread_impersonation() -> None:
    """A thread token must not override a process identity check."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentThread.restype = ctypes.c_void_p
    adv.OpenThreadToken.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    thread_token = ctypes.c_void_p()
    if adv.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(thread_token)):
        kernel.CloseHandle(thread_token)
        raise CheckpointError("thread impersonation is not admitted")
    if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
        raise CheckpointError("thread token status is uncertain")


def _require_signer_token(trust: ChainTrust) -> None:
    _assert_no_thread_impersonation()
    if current_sid() != trust.signer_sid or current_appcontainer_identity()[0] is not None:
        raise CheckpointError("process token is not the owner signer")


def _require_writer_token(trust: ChainTrust) -> None:
    _assert_no_thread_impersonation()
    if current_sid() != trust.writer_sid:
        raise CheckpointError("writable admission requires the pinned writer token user SID")
    package_sid, capability_count = current_appcontainer_identity()
    if trust.writer_boundary == "WINDOWS_APPCONTAINER":
        if package_sid != trust.writer_appcontainer_sid or capability_count != 0:
            raise CheckpointError("writable admission requires the pinned zero-capability AppContainer")
    elif package_sid is not None:
        raise CheckpointError("account writer cannot use an unpinned AppContainer")


def root_identity(root: Path) -> str:
    """Bind a root to a held native NTFS directory handle, not a pathname alone."""
    path = Path(root)
    if not path.is_absolute():
        raise CheckpointError("absolute root required")
    check_ancestors(path)
    with pin_parent_directories(path / "_identity_") as pins:
        volume, file_id = pins.identity_for(path)
    return f"{volume:016x}:{file_id.hex()}"


@contextmanager
def _hold_roots(custody_root: Path, evidence_root: Path, trust: ChainTrust):
    """Keep NTFS directory handles open across a complete verification or sign."""
    request_root = custody_root / "requests"
    with pin_parent_directories(
        custody_root / "_hold_", request_root / "_hold_",
        evidence_root / "_hold_",
    ) as pins:
        expected = (
            (custody_root, trust.custody_root_identity),
            (request_root, trust.request_root_identity),
            (evidence_root, trust.evidence_root_identity),
        )
        for path, pinned in expected:
            volume, file_id = pins.identity_for(path)
            if f"{volume:016x}:{file_id.hex()}" != pinned:
                raise CheckpointError("held root differs from owner pin")
        yield

def _evidence_files(root: Path) -> tuple[Path, ...]:
    paths = StoragePaths(root)
    files = [root / "store_header.json"]
    for area in ("h", "records", "manifests", "registry", "staging"):
        files.extend(IntegrityVerifier._files_under(paths, root / area))
    return tuple(sorted(files, key=lambda path: str(path).casefold()))


@contextmanager
def _hold_evidence_snapshot(root: Path):
    """Hold existing evidence files against direct writes across all validation passes.

    This protects byte stability of already opened files. ACL qualification is
    still required for append and owner-custody claims.
    """
    files = _evidence_files(root)
    with pin_parent_directories(*files) as pins, ExitStack() as held:
        for path in files:
            handle = native_ntfs.open_file(
                pins.handle_for(path.parent), path.name, read=True, share=1,
            )
            held.callback(native_ntfs.close_handle, handle)
        if _evidence_files(root) != files:
            raise CheckpointError("evidence inventory changed while pinning snapshot")
        yield
        if _evidence_files(root) != files:
            raise CheckpointError("evidence inventory changed during custody operation")

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _checkpoint_id(sequence: int) -> str:
    if type(sequence) is not int or not 1 <= sequence <= 999999:
        raise CheckpointError("checkpoint sequence outside ID range")
    return f"CHK-{sequence:06d}"


def make_sign_request(
    trust: ChainTrust, *, sequence: int,
    previous_checkpoint_id: str | None,
    previous_checkpoint_sha256: str | None,
    manifest_count: int, payload_sha256: str | None,
    sign_request_id: str | None = None,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    """Writer-side candidate construction; no private signing capability."""
    checkpoint_id = _checkpoint_id(sequence)
    if (sequence == 1) != (previous_checkpoint_id is None and previous_checkpoint_sha256 is None):
        raise CheckpointError("previous checkpoint pair mismatch")
    if sequence > 1:
        if previous_checkpoint_id != _checkpoint_id(sequence - 1):
            raise CheckpointError("previous checkpoint ID mismatch")
        validate_sha256(previous_checkpoint_sha256)
    if type(manifest_count) is not int or manifest_count < 0:
        raise CheckpointError("invalid manifest count")
    if (manifest_count == 0) != (payload_sha256 is None):
        raise CheckpointError("manifest count and hash mismatch")
    if payload_sha256 is not None:
        validate_sha256(payload_sha256)
    created = created_at_utc or _utc_now()
    if not _UTC.fullmatch(created):
        raise CheckpointError("creation UTC required")
    request_id = sign_request_id or "REQ-" + secrets.token_hex(16)
    if not re.fullmatch(r"REQ-[0-9a-f]{32}", request_id):
        raise CheckpointError("invalid sign request ID")
    return {
        "sign_request_id": request_id,
        "checkpoint": {
            "checkpoint_id": checkpoint_id,
            "sequence": sequence,
            "root_id": trust.root_id,
            "genesis_checkpoint": sequence == 1,
            "previous_checkpoint_id": previous_checkpoint_id,
            "previous_checkpoint_sha256": previous_checkpoint_sha256,
            "payload_sha256": payload_sha256,
            "manifest_count": manifest_count,
            "signer_actor_id": trust.signer_actor_id,
            "signing_key_id": trust.signing_key_id,
            "created_at_utc": created,
            "source_lineage_id": trust.lineage_id,
            "source_version_id": trust.version_id,
            "store_id": trust.store_id,
            "evidence_root_identity": trust.evidence_root_identity,
            "store_header_sha256": trust.store_header_sha256,
        },
    }


def _read_checkpoint(root: Path, name: str) -> bytes:
    path = root / name
    with pin_parent_directories(path) as pins:
        return native_ntfs.read_file(pins.handle_for(root), name)


def _read_request(request_root: Path, request_id: str) -> bytes:
    if not re.fullmatch(r"REQ-[0-9a-f]{32}", request_id):
        raise CheckpointError("invalid sign request ID")
    with pin_parent_directories(request_root / "_scan_") as pins:
        names = {name for name, _ in native_ntfs.list_directory(pins.handle_for(request_root))}
    if request_id + ".partial" in names:
        raise CheckpointError("ambiguous partial sign request")
    raw = _read_checkpoint(request_root, request_id + ".json")
    parsed = strict_json_loads(raw)
    if not isinstance(parsed, dict) or set(parsed) != _REQUEST_KEYS or canonical_json(parsed) != raw:
        raise CheckpointError("noncanonical sign request")
    if parsed["sign_request_id"] != request_id:
        raise CheckpointError("sign request filename mismatch")
    return raw


def write_sign_request(custody_root: Path, trust: ChainTrust, request: Mapping[str, Any]) -> Path:
    """Create-new writer inbox publication; a partial remains visible after a crash."""
    root = Path(custody_root) / "requests"
    if root_identity(root) != trust.request_root_identity:
        raise CheckpointError("request root identity changed")
    if not isinstance(request, Mapping) or set(request) != _REQUEST_KEYS:
        raise CheckpointError("invalid sign request")
    request_id = request["sign_request_id"]
    if not isinstance(request_id, str) or not re.fullmatch(r"REQ-[0-9a-f]{32}", request_id):
        raise CheckpointError("invalid sign request ID")
    raw = canonical_json(request)
    stage = root / (request_id + ".partial")
    destination = root / (request_id + ".json")
    try:
        with pin_parent_directories(stage, destination) as pins:
            parent = pins.handle_for(root)
            volume, file_id = pins.identity_for(root)
            if f"{volume:016x}:{file_id.hex()}" != trust.request_root_identity:
                raise CheckpointError("held request root differs from owner pin")
            handle = native_ntfs.open_file(parent, stage.name, create=True, write=True)
            with native_ntfs.file_object(handle, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if native_ntfs.read_file(parent, stage.name) != raw:
                raise CheckpointError("staged request readback mismatch")
            native_ntfs.rename_no_replace(parent, stage.name, parent, destination.name)
            if native_ntfs.read_file(parent, destination.name) != raw:
                raise CheckpointError("request publication readback mismatch")
    except FileExistsError as exc:
        raise CheckpointError("duplicate sign request") from exc
    return destination

class CheckpointVerifier:
    """Read-only chain verifier. It cannot publish, repair, or choose a trust key."""

    def __init__(self, custody_root: Path, evidence_root: Path, trust: ChainTrust) -> None:
        self.root = Path(custody_root)
        self.evidence_root = Path(evidence_root)
        self.trust = trust
        if self.root == self.evidence_root or self.root in self.evidence_root.parents or self.evidence_root in self.root.parents:
            raise CheckpointError("custody and evidence roots overlap")

    def _scan(self, allowed_pending_stage: str | None = None) -> list[tuple[dict[str, Any], bytes]]:
        if root_identity(self.root) != self.trust.custody_root_identity:
            raise CheckpointError("custody root identity changed")
        if root_identity(self.evidence_root) != self.trust.evidence_root_identity:
            raise CheckpointError("evidence root identity changed")
        if root_identity(self.root / "requests") != self.trust.request_root_identity:
            raise CheckpointError("request root identity changed")
        if sha256_bytes(_read_checkpoint(self.evidence_root, "store_header.json")) != self.trust.store_header_sha256:
            raise CheckpointError("store header changed from owner pin")
        with pin_parent_directories(self.root / "_scan_") as pins:
            names = native_ntfs.list_directory(pins.handle_for(self.root))
        files = []
        for name, attributes in names:
            if name == allowed_pending_stage:
                if attributes & 0x410:
                    raise CheckpointError("pending checkpoint is not a plain file")
                continue
            if name == "signer.lock":
                if attributes & 0x410:
                    raise CheckpointError("signer lock is a directory")
                continue
            if name == "requests":
                if not attributes & 0x10 or attributes & 0x400:
                    raise CheckpointError("request root is not a plain directory")
                continue
            if attributes & 0x410:
                raise CheckpointError("reparse or directory in custody root")
            match = _CHECKPOINT_NAME.fullmatch(name)
            if match is None:
                raise CheckpointError("unexpected or interrupted custody member")
            files.append((int(match.group(1)), name))
        files.sort()
        rows: list[tuple[dict[str, Any], bytes]] = []
        previous_id = None
        previous_sha = None
        previous_manifest_count = -1
        seen_requests: set[str] = set()
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.trust.public_key_hex))
        for position, (number, name) in enumerate(files, 1):
            if number != position or name != f"{_checkpoint_id(position)}.json":
                raise CheckpointError("missing or duplicate checkpoint sequence")
            raw = _read_checkpoint(self.root, name)
            row = strict_json_loads(raw)
            if not isinstance(row, dict) or set(row) != _RECEIPT_KEYS or canonical_json(row) != raw:
                raise CheckpointError("noncanonical checkpoint receipt")
            checkpoint = row["checkpoint"]
            if not isinstance(checkpoint, dict) or set(checkpoint) != _CHECKPOINT_KEYS:
                raise CheckpointError("checkpoint payload shape mismatch")
            if checkpoint["checkpoint_id"] != _checkpoint_id(position) or checkpoint["sequence"] != position:
                raise CheckpointError("checkpoint ID or sequence mismatch")
            if checkpoint["root_id"] != self.trust.root_id or checkpoint["genesis_checkpoint"] is not (position == 1):
                raise CheckpointError("checkpoint root or genesis mismatch")
            if row["checkpoint_payload_sha256"] != sha256_bytes(canonical_json(checkpoint)):
                raise CheckpointError("checkpoint payload digest mismatch")
            if checkpoint["previous_checkpoint_id"] != previous_id or checkpoint["previous_checkpoint_sha256"] != previous_sha:
                raise CheckpointError("broken previous checkpoint link")
            if checkpoint["manifest_count"] <= previous_manifest_count:
                raise CheckpointError("manifest count did not advance")
            if (checkpoint["manifest_count"] == 0) != (checkpoint["payload_sha256"] is None):
                raise CheckpointError("manifest payload mismatch")
            if checkpoint["payload_sha256"] is not None:
                validate_sha256(checkpoint["payload_sha256"])
            if not _UTC.fullmatch(checkpoint["created_at_utc"]):
                raise CheckpointError("invalid creation UTC")
            expected = {
                "signer_actor_id": self.trust.signer_actor_id,
                "signing_key_id": self.trust.signing_key_id,
                "source_lineage_id": self.trust.lineage_id,
                "source_version_id": self.trust.version_id,
                "store_id": self.trust.store_id,
                "evidence_root_identity": self.trust.evidence_root_identity,
                "store_header_sha256": self.trust.store_header_sha256,
            }
            if any(checkpoint[field] != value for field, value in expected.items()):
                raise CheckpointError("wrong signer, key, lineage, or evidence root")
            if not re.fullmatch(r"REQ-[0-9a-f]{32}", row["sign_request_id"]):
                raise CheckpointError("invalid sign request ID")
            if row["sign_request_id"] in seen_requests:
                raise CheckpointError("duplicate sign request ID")
            seen_requests.add(row["sign_request_id"])
            if not re.fullmatch(r"RCP-[0-9a-f]{32}", row["sign_receipt_id"]):
                raise CheckpointError("invalid sign receipt ID")
            if not re.fullmatch(r"SIG-[0-9a-f]{32}", row["signature_id"]):
                raise CheckpointError("invalid signature ID")
            # The writer inbox is a candidate transport, not an authority store.
            # Once published, signed receipt bytes alone retain the exact request.
            source_request = {
                "sign_request_id": row["sign_request_id"],
                "checkpoint": checkpoint,
            }
            if sha256_bytes(canonical_json(source_request)) != row["sign_request_sha256"]:
                raise CheckpointError("signed request digest differs from checkpoint")
            signed = {key: value for key, value in row.items() if key != "signature_hex"}
            admission = checkpoint_payload(
                checkpoint["store_id"], checkpoint["source_lineage_id"],
                checkpoint["manifest_count"], checkpoint["payload_sha256"],
            )
            try:
                public.verify(bytes.fromhex(row["admission_signature_hex"]), admission)
                public.verify(bytes.fromhex(row["signature_hex"]), canonical_json(signed))
            except (ValueError, InvalidSignature) as exc:
                raise CheckpointError("invalid owner signature") from exc
            previous_id = checkpoint["checkpoint_id"]
            previous_sha = sha256_bytes(raw)
            previous_manifest_count = checkpoint["manifest_count"]
            rows.append((row, raw))
        self._assert_retained_prefixes(rows)
        return rows

    def _assert_retained_prefixes(self, rows: list[tuple[dict[str, Any], bytes]]) -> None:
        manifest_root = self.evidence_root / "manifests"
        with pin_parent_directories(manifest_root / "_scan_") as pins:
            parent = pins.handle_for(manifest_root)
            names = native_ntfs.list_directory(parent)
            manifest_names = []
            for name, attributes in names:
                match = _MANIFEST_NAME.fullmatch(name)
                if attributes & 0x410 or match is None:
                    raise CheckpointError("invalid evidence manifest entry")
                manifest_names.append((int(match.group(1)), name))
            manifest_names.sort()
            for number, name in enumerate(manifest_names, 1):
                if number != name[0]:
                    raise CheckpointError("evidence manifest sequence gap")
            for row, _ in rows:
                checkpoint = row["checkpoint"]
                count = checkpoint["manifest_count"]
                if count == 0:
                    continue
                if count > len(manifest_names):
                    raise CheckpointError("retained checkpoint manifest is missing")
                manifest_name = manifest_names[count - 1][1]
                if sha256_bytes(native_ntfs.read_file(parent, manifest_name)) != checkpoint["payload_sha256"]:
                    raise CheckpointError("evidence prefix differs from retained checkpoint")

    def reconstruct_head(self) -> dict[str, Any]:
        """Derive the head from the validated chain, never from a latest pointer.

        A separately retained expected head is still needed to detect a fully
        rolled-back valid prefix when the evidence root is also rolled back.
        """
        try:
            with _hold_roots(self.root, self.evidence_root, self.trust), _hold_evidence_snapshot(self.evidence_root):
                rows = self._scan()
                if not rows:
                    raise CheckpointError("no authoritative checkpoint")
                head_id = rows[-1][0]["checkpoint"]["checkpoint_id"]
                head_sha = sha256_bytes(rows[-1][1])
                result = self._verify_held(
                    expected_head_id=head_id,
                    expected_head_sha256=head_sha,
                    _held_writer_lock_handle=None,
                )
                result["head_source"] = "VALIDATED_CHAIN"
                return result
        except (OSError, ValueError, TypeError, KeyError, CheckpointError) as exc:
            return {
                "result": "FAIL", "checkpoint_count": 0,
                "head_checkpoint_id": None, "head_sha256": None,
                "head_source": "VALIDATED_CHAIN", "custody_qualified": False,
                "finding": str(exc),
            }

    def verify(
        self, *, expected_head_id: str | None,
        expected_head_sha256: str | None,
        _held_writer_lock_handle: Any | None = None,
    ) -> dict[str, Any]:
        try:
            with _hold_roots(self.root, self.evidence_root, self.trust), _hold_evidence_snapshot(self.evidence_root):
                return self._verify_held(
                    expected_head_id=expected_head_id,
                    expected_head_sha256=expected_head_sha256,
                    _held_writer_lock_handle=_held_writer_lock_handle,
                )
        except (OSError, ValueError, TypeError, KeyError, CheckpointError) as exc:
            material = canonical_json({
                "custody_root_identity": self.trust.custody_root_identity,
                "expected_head_id": expected_head_id,
                "expected_head_sha256": expected_head_sha256,
            })
            return {
                "result": "FAIL", "checkpoint_count": 0,
                "head_checkpoint_id": None, "head_sha256": None,
                "verification_event_id": "VEV-" + sha256_bytes(material)[:32],
                "custody_qualified": False, "finding": str(exc),
            }

    def _verify_held(
        self, *, expected_head_id: str | None,
        expected_head_sha256: str | None,
        _held_writer_lock_handle: Any | None,
    ) -> dict[str, Any]:
        event_material = canonical_json({
            "custody_root_identity": self.trust.custody_root_identity,
            "expected_head_id": expected_head_id,
            "expected_head_sha256": expected_head_sha256,
        })
        event_id = "VEV-" + sha256_bytes(event_material)[:32]
        try:
            rows = self._scan()
            head = rows[-1] if rows else None
            actual_id = head[0]["checkpoint"]["checkpoint_id"] if head else None
            actual_sha = sha256_bytes(head[1]) if head else None
            if actual_id != expected_head_id or actual_sha != expected_head_sha256:
                raise CheckpointError("missing checkpoint or rollback against pinned head")
            if head:
                report = IntegrityVerifier(self.evidence_root).verify(
                    _held_writer_lock_handle=_held_writer_lock_handle,
                )
                checkpoint = head[0]["checkpoint"]
                if report["result"] != "PASS":
                    raise CheckpointError(f"evidence root integrity failed: {report['findings']}")
                if (
                    report["store_id"] != self.trust.store_id
                    or report["lineage_id"] != self.trust.lineage_id
                    or report["manifest_count"] != checkpoint["manifest_count"]
                    or report["manifest_root_sha256"] != checkpoint["payload_sha256"]
                ):
                    raise CheckpointError("checkpoint does not bind current evidence root")
            return {
                "result": "PASS", "checkpoint_count": len(rows),
                "head_checkpoint_id": actual_id, "head_sha256": actual_sha,
                "verification_event_id": event_id,
                "custody_qualified": False,
            }
        except (OSError, ValueError, TypeError, KeyError, CheckpointError) as exc:
            return {
                "result": "FAIL", "checkpoint_count": 0,
                "head_checkpoint_id": None, "head_sha256": None,
                "verification_event_id": event_id,
                "custody_qualified": False, "finding": str(exc),
            }


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


@contextmanager
def _custody_lock(root: Path, filename: str = "signer.lock"):
    """Serialize signer processes; the owner provisions signer.lock beforehand."""
    key = (str(root) + "/" + filename).casefold()
    with _LOCKS_GUARD:
        local = _LOCKS.setdefault(key, threading.Lock())
    with local:
        lock_path = root / filename
        with pin_parent_directories(lock_path) as pins:
            handle = native_ntfs.open_file(
                pins.handle_for(root), lock_path.name, read=True, write=True,
            )
            with native_ntfs.file_object(handle, "r+b") as lock:
                deadline = time.monotonic() + 10
                while True:
                    lock.seek(0)
                    try:
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise CheckpointError("custody lock timed out")
                        time.sleep(0.025)
                try:
                    yield lock
                finally:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


class OwnerSigner:
    """Owner-token signer; provisioning/ACL qualification is external to this API."""

    def __init__(
        self, custody_root: Path, evidence_root: Path,
        trust: ChainTrust, private_key_path: Path,
    ) -> None:
        _require_signer_token(trust)
        self.root = Path(custody_root)
        self.evidence_root = Path(evidence_root)
        self.trust = trust
        if self.root == self.evidence_root or self.root in self.evidence_root.parents or self.evidence_root in self.root.parents:
            raise CheckpointError("custody and evidence roots overlap")
        self.key_path = Path(private_key_path)
        if not self.key_path.is_absolute():
            raise CheckpointError("absolute owner key path required")
        check_ancestors(self.key_path)
        for forbidden in (self.root, self.evidence_root):
            if self.key_path == forbidden or forbidden in self.key_path.parents:
                raise CheckpointError("private key inside custody or evidence root")
        if root_identity(self.root) != trust.custody_root_identity:
            raise CheckpointError("custody root identity changed")
        if root_identity(self.evidence_root) != trust.evidence_root_identity:
            raise CheckpointError("evidence root identity changed")
        if root_identity(self.root / "requests") != trust.request_root_identity:
            raise CheckpointError("request root identity changed")
        with pin_parent_directories(self.key_path) as pins:
            handle = native_ntfs.open_file(
                pins.handle_for(self.key_path.parent), self.key_path.name, read=True,
            )
            try:
                self._key_identity = native_ntfs.inspect_handle(handle, directory=False)
            finally:
                native_ntfs.close_handle(handle)

    def _private_key(self) -> Ed25519PrivateKey:
        with pin_parent_directories(self.key_path) as pins:
            handle = native_ntfs.open_file(
                pins.handle_for(self.key_path.parent), self.key_path.name, read=True,
            )
            with native_ntfs.file_object(handle, "rb") as source:
                if native_ntfs.inspect_handle(handle, directory=False) != self._key_identity:
                    raise CheckpointError("owner key file identity changed")
                key_bytes = source.read()
                if native_ntfs.inspect_handle(handle, directory=False) != self._key_identity:
                    raise CheckpointError("owner key file changed during read")
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise CheckpointError("Ed25519 owner key required")
        actual = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        if actual != self.trust.public_key_hex:
            raise CheckpointError("private key differs from pinned public key")
        return key

    def _publish(
        self, row: Mapping[str, Any], request_id: str,
        fault: Callable[[str], None] | None,
    ) -> None:
        destination = self.root / f"{row['checkpoint']['checkpoint_id']}.json"
        stage = self.root / f"{request_id}.partial"
        raw = canonical_json(row)
        with pin_parent_directories(stage, destination) as pins:
            parent = pins.handle_for(self.root)
            handle = native_ntfs.open_file(parent, stage.name, create=True, write=True)
            with native_ntfs.file_object(handle, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if native_ntfs.read_file(parent, stage.name) != raw:
                raise CheckpointError("staged checkpoint readback mismatch")
            if fault:
                fault("during_publication")
            native_ntfs.rename_no_replace(parent, stage.name, parent, destination.name)
            if native_ntfs.read_file(parent, destination.name) != raw:
                raise CheckpointError("published checkpoint readback mismatch")
        if fault:
            fault("after_publication")

    def recover_publication(
        self, request_id: str, *,
        expected_head_id: str | None, expected_head_sha256: str | None,
    ) -> dict[str, Any]:
        """Owner-only recovery of one fully signed staged receipt; never repairs bytes."""
        if not re.fullmatch(r"REQ-[0-9a-f]{32}", request_id):
            raise CheckpointError("invalid recovery request ID")
        stage = self.root / (request_id + ".partial")
        with _custody_lock(self.root), _custody_lock(self.evidence_root, "writer.lock") as evidence_lock, _hold_roots(self.root, self.evidence_root, self.trust), _hold_evidence_snapshot(self.evidence_root):
            verifier = CheckpointVerifier(self.root, self.evidence_root, self.trust)
            rows = verifier._scan(allowed_pending_stage=stage.name)
            head = rows[-1] if rows else None
            head_id = head[0]["checkpoint"]["checkpoint_id"] if head else None
            head_sha = sha256_bytes(head[1]) if head else None
            if (head_id, head_sha) != (expected_head_id, expected_head_sha256):
                raise CheckpointError("recovery head differs from owner pin")
            raw = _read_checkpoint(self.root, stage.name)
            row = strict_json_loads(raw)
            if not isinstance(row, dict) or set(row) != _RECEIPT_KEYS or canonical_json(row) != raw:
                raise CheckpointError("staged receipt is not exact canonical bytes")
            if row["sign_request_id"] != request_id:
                raise CheckpointError("staged receipt request ID mismatch")
            if row["checkpoint_payload_sha256"] != sha256_bytes(canonical_json(row["checkpoint"])):
                raise CheckpointError("staged payload digest mismatch")
            request_bytes = _read_request(self.root / "requests", request_id)
            if sha256_bytes(request_bytes) != row["sign_request_sha256"]:
                raise CheckpointError("staged receipt request hash mismatch")
            checkpoint = row["checkpoint"]
            if not isinstance(checkpoint, dict) or set(checkpoint) != _CHECKPOINT_KEYS:
                raise CheckpointError("staged checkpoint payload shape mismatch")
            evidence = IntegrityVerifier(self.evidence_root).verify(_held_writer_lock_handle=evidence_lock)
            if evidence["result"] != "PASS":
                raise CheckpointError("evidence root invalid during recovery")
            expected = make_sign_request(
                self.trust, sequence=len(rows) + 1,
                previous_checkpoint_id=head_id,
                previous_checkpoint_sha256=head_sha,
                manifest_count=evidence["manifest_count"],
                payload_sha256=evidence["manifest_root_sha256"],
                sign_request_id=request_id,
                created_at_utc=checkpoint["created_at_utc"],
            )
            if strict_json_loads(request_bytes) != expected or checkpoint != expected["checkpoint"]:
                raise CheckpointError("staged candidate no longer matches owner and evidence state")
            signed = {key: value for key, value in row.items() if key != "signature_hex"}
            admission = checkpoint_payload(
                checkpoint["store_id"], checkpoint["source_lineage_id"],
                checkpoint["manifest_count"], checkpoint["payload_sha256"],
            )
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.trust.public_key_hex))
            try:
                public.verify(bytes.fromhex(row["admission_signature_hex"]), admission)
                public.verify(bytes.fromhex(row["signature_hex"]), canonical_json(signed))
            except (ValueError, InvalidSignature) as exc:
                raise CheckpointError("staged owner signature invalid") from exc
            destination = self.root / (checkpoint["checkpoint_id"] + ".json")
            with pin_parent_directories(stage, destination) as pins:
                parent = pins.handle_for(self.root)
                native_ntfs.rename_no_replace(parent, stage.name, parent, destination.name)
                if native_ntfs.read_file(parent, destination.name) != raw:
                    raise CheckpointError("recovered checkpoint readback mismatch")
            digest = sha256_bytes(raw)
            result = verifier.verify(
                expected_head_id=checkpoint["checkpoint_id"],
                expected_head_sha256=digest,
                _held_writer_lock_handle=evidence_lock,
            )
            if result["result"] != "PASS":
                raise CheckpointError("published recovery checkpoint failed verification")
            return row
    def sign_and_publish(
        self, request: Mapping[str, Any], *,
        expected_head_id: str | None, expected_head_sha256: str | None,
        fault: Callable[[str], None] | None = None,
        import_candidate: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(request, Mapping) or set(request) != _REQUEST_KEYS:
            raise CheckpointError("invalid signing request")
        checkpoint = request["checkpoint"]
        if not isinstance(checkpoint, Mapping) or set(checkpoint) != _CHECKPOINT_KEYS:
            raise CheckpointError("invalid checkpoint candidate")
        request_id = request["sign_request_id"]
        if not isinstance(request_id, str) or not re.fullmatch(r"REQ-[0-9a-f]{32}", request_id):
            raise CheckpointError("invalid sign request ID")
        # The Engineering importer completes under the same checkpoint lock
        # used for signing. It must create the writer.lock before admission.
        with _custody_lock(self.root):
            if import_candidate is not None:
                if _read_request(self.root / "requests", request_id) != canonical_json(request):
                    raise CheckpointError("sign request differs before candidate import")
                import_candidate()
            with _custody_lock(self.evidence_root, "writer.lock") as evidence_lock, _hold_roots(self.root, self.evidence_root, self.trust), _hold_evidence_snapshot(self.evidence_root):
                request_bytes = _read_request(self.root / "requests", request_id)
                if request_bytes != canonical_json(request):
                    raise CheckpointError("sign request file differs from supplied candidate")
                verifier = CheckpointVerifier(self.root, self.evidence_root, self.trust)
                rows = verifier._scan()
                head = rows[-1] if rows else None
                head_id = head[0]["checkpoint"]["checkpoint_id"] if head else None
                head_sha = sha256_bytes(head[1]) if head else None
                if (head_id, head_sha) != (expected_head_id, expected_head_sha256):
                    if (
                        head and head[0]["sign_request_id"] == request_id
                        and head[0]["checkpoint"] == checkpoint
                        and head[0]["checkpoint"]["previous_checkpoint_id"] == expected_head_id
                        and head[0]["checkpoint"]["previous_checkpoint_sha256"] == expected_head_sha256
                    ):
                        checked = verifier.verify(
                            expected_head_id=head_id, expected_head_sha256=head_sha,
                            _held_writer_lock_handle=evidence_lock,
                        )
                        if checked["result"] != "PASS":
                            raise CheckpointError("published retry failed current-root verification")
                        return head[0]
                    raise CheckpointError("stale custodian head or duplicate sequence")
                if fault:
                    fault("before_sign")
                evidence = IntegrityVerifier(self.evidence_root).verify(_held_writer_lock_handle=evidence_lock)
                if evidence["result"] != "PASS":
                    raise CheckpointError(f"evidence root integrity failed: {evidence['findings']}")
                expected = make_sign_request(
                    self.trust, sequence=len(rows) + 1,
                    previous_checkpoint_id=head_id,
                    previous_checkpoint_sha256=head_sha,
                    manifest_count=evidence["manifest_count"],
                    payload_sha256=evidence["manifest_root_sha256"],
                    sign_request_id=request_id,
                    created_at_utc=checkpoint["created_at_utc"],
                )
                if dict(request) != expected:
                    raise CheckpointError("stale or substituted checkpoint candidate")
                if rows and checkpoint["manifest_count"] <= rows[-1][0]["checkpoint"]["manifest_count"]:
                    raise CheckpointError("checkpoint does not advance evidence")
                if fault:
                    fault("during_sign")
                signed = {
                    "checkpoint": dict(checkpoint),
                    "checkpoint_payload_sha256": sha256_bytes(canonical_json(checkpoint)),
                    "sign_request_id": request_id,
                    "sign_request_sha256": sha256_bytes(request_bytes),
                    "sign_receipt_id": "RCP-" + secrets.token_hex(16),
                    "signature_id": "SIG-" + secrets.token_hex(16),
                }
                owner_key = self._private_key()
                signed["admission_signature_hex"] = owner_key.sign(checkpoint_payload(
                    checkpoint["store_id"], checkpoint["source_lineage_id"],
                    checkpoint["manifest_count"], checkpoint["payload_sha256"],
                )).hex()
                signed["signature_hex"] = owner_key.sign(canonical_json(signed)).hex()
                if fault:
                    fault("after_sign")
                self._publish(signed, request_id, fault)
                digest = sha256_bytes(canonical_json(signed))
                checked = verifier.verify(
                    expected_head_id=checkpoint["checkpoint_id"],
                    expected_head_sha256=digest,
                    _held_writer_lock_handle=evidence_lock,
                )
                if checked["result"] != "PASS":
                    raise CheckpointError("published checkpoint failed current-root verification")
                return signed

def provision_engineering_binding(custody_root: Path, evidence_root: Path, trust: ChainTrust) -> Path:
    """Owner-only create-new binding beside an existing Engineering evidence root.

    The parent directory and this member require custodian-owned ACLs. A caller
    must qualify those effective ACLs separately before claiming custody.
    """
    _require_signer_token(trust)
    custody = Path(custody_root)
    evidence = Path(evidence_root)
    if not custody.is_absolute() or not evidence.is_absolute():
        raise CheckpointError("absolute custody and evidence roots required")
    check_ancestors(custody)
    check_ancestors(evidence)
    if (root_identity(custody) != trust.custody_root_identity
            or root_identity(custody / "requests") != trust.request_root_identity
            or root_identity(evidence) != trust.evidence_root_identity):
        raise CheckpointError("custody or evidence root differs from owner pin")
    from .append_only import _custody_binding_path
    destination = _custody_binding_path(evidence)
    raw = canonical_json({
        "ROOT_CLASS": "ENGINEERING_CUSTODY",
        "ROOT_ID": trust.root_id,
        "evidence_root_identity": trust.evidence_root_identity,
        "trust_sha256": sha256_bytes(canonical_json(asdict(trust))),
        "custody_root": str(custody.resolve()),
        "trust": asdict(trust),
    })
    with pin_parent_directories(destination) as pins:
        parent = pins.handle_for(destination.parent)
        try:
            handle = native_ntfs.open_file(parent, destination.name, create=True, write=True)
        except FileExistsError as exc:
            raise CheckpointError("engineering custody binding already exists") from exc
        with native_ntfs.file_object(handle, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if native_ntfs.read_file(parent, destination.name) != raw:
            raise CheckpointError("engineering custody binding readback mismatch")
    return destination


def validate_bound_writable(
    evidence_root: Path, binding: Mapping[str, Any], *,
    expected_head_id: str | None = None,
    expected_head_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate protected public trust and the live owner-signed chain.

    Every bound writable constructor runs this, including legacy callers.
    An expected head is optional for direct callers but the head is always
    independently reconstructed from the validated chain.
    """
    evidence = Path(evidence_root)
    if not evidence.is_absolute():
        raise CheckpointError("absolute evidence root required")
    check_ancestors(evidence)
    if not isinstance(binding.get("trust"), dict):
        raise CheckpointError("custodian trust record missing")
    trust = ChainTrust(**binding["trust"])
    if (binding["ROOT_ID"] != trust.root_id
            or binding["evidence_root_identity"] != trust.evidence_root_identity
            or binding["trust_sha256"] != sha256_bytes(canonical_json(asdict(trust)))):
        raise CheckpointError("engineering binding differs from custodian trust")
    _require_writer_token(trust)
    custody = Path(binding["custody_root"])
    if not custody.is_absolute():
        raise CheckpointError("absolute custody root required")
    check_ancestors(custody)
    if root_identity(evidence) != trust.evidence_root_identity:
        raise CheckpointError("evidence root differs from owner pin")
    report = CheckpointVerifier(custody, evidence, trust).reconstruct_head()
    if report["result"] != "PASS":
        raise CheckpointError("owner checkpoint chain did not verify for writable admission")
    head_id = report["head_checkpoint_id"]
    head_sha = report["head_sha256"]
    if expected_head_id is not None and (head_id, head_sha) != (expected_head_id, expected_head_sha256):
        raise CheckpointError("selected owner checkpoint head differs from validated chain")
    raw = _read_checkpoint(custody, head_id + ".json")
    if sha256_bytes(raw) != head_sha:
        raise CheckpointError("owner checkpoint changed after chain verification")
    receipt = strict_json_loads(raw)
    checkpoint = receipt["checkpoint"]
    legacy_pin = {
        "payload": {
            "store_id": trust.store_id,
            "lineage_id": trust.lineage_id,
            "sequence": checkpoint["manifest_count"],
            "manifest_sha256": checkpoint["payload_sha256"],
        },
        "signature_hex": receipt["admission_signature_hex"],
    }
    return {
        "trust": trust, "custody_root": custody,
        "head_checkpoint_id": head_id, "head_sha256": head_sha,
        "legacy_pin": legacy_pin,
    }


def open_writable_with_custody(
    custody_root: Path, evidence_root: Path, trust: ChainTrust,
    writer_private_key: Ed25519PrivateKey, *,
    expected_head_id: str, expected_head_sha256: str,
):
    """Admit an existing bound I1 writer through protected trust and live chain."""
    root = Path(custody_root)
    evidence = Path(evidence_root)
    if not root.is_absolute() or not evidence.is_absolute():
        raise CheckpointError("absolute custody and evidence roots required")
    check_ancestors(root)
    check_ancestors(evidence)
    root = root.resolve()
    evidence = evidence.resolve()
    from .append_only import _read_custody_binding
    binding = _read_custody_binding(evidence)
    if binding is None:
        raise CheckpointError("engineering custody binding is missing")
    with _hold_roots(root, evidence, trust), _hold_evidence_snapshot(evidence):
        admission = validate_bound_writable(
            evidence, binding,
            expected_head_id=expected_head_id,
            expected_head_sha256=expected_head_sha256,
        )
        if admission["trust"] != trust or admission["custody_root"] != root:
            raise CheckpointError("caller trust differs from protected engineering trust")
        from .append_only import _CUSTODY_WRAPPER
        from .evidence_store import EvidenceStore
        token = _CUSTODY_WRAPPER.set(True)
        try:
            return EvidenceStore(
                evidence, writer_private_key=writer_private_key,
                store_id=trust.store_id, lineage_id=trust.lineage_id,
                trusted_checkpoint=admission["legacy_pin"],
                trusted_checkpoint_public_key_hex=trust.public_key_hex,
            )
        finally:
            _CUSTODY_WRAPPER.reset(token)

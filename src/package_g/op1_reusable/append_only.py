"""Synthetic I1 create-new object publication and immutable manifest chain."""
from __future__ import annotations

import json
import contextvars
import msvcrt
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .identity import canonical_json, generate_id, sha256_bytes, strict_json_loads, validate_id
from . import native_ntfs
from .schema_registry import SchemaRegistry
from .storage_paths import Scope, StoragePaths, check_ancestors, pin_parent_directories

FaultHook = Callable[[str, Path], None]
_MANIFEST_NAME = re.compile(r"([0-9]{12})-(PG-ART-[0-9a-f]{32})\.json\Z")
_CUSTODY_WRAPPER = contextvars.ContextVar("op1_custody_wrapper", default=False)
def _custody_binding_path(root: Path) -> Path:
    return root.parent / ("." + root.name + ".engineering-custody.json")


def _read_custody_binding(root: Path) -> dict[str, Any] | None:
    """Read the custodian-owned sibling binding for an Engineering evidence root."""
    path = _custody_binding_path(root)
    check_ancestors(path, include_final=False)
    with pin_parent_directories(path) as pins:
        parent = pins.handle_for(path.parent)
        names = {name for name, _ in native_ntfs.list_directory(parent)}
        if path.name not in names:
            if "ENGINEERING_CUSTODY_PROFILE.json" in names:
                raise StoreQuarantined("engineering custody binding missing")
            return None
        raw = native_ntfs.read_file(parent, path.name)
    value = strict_json_loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "ROOT_CLASS", "ROOT_ID", "evidence_root_identity", "trust_sha256",
        "custody_root", "trust",
    } or canonical_json(value) != raw:
        raise StoreQuarantined("invalid engineering custody binding")
    if value["ROOT_CLASS"] != "ENGINEERING_CUSTODY":
        raise StoreQuarantined("unsupported custody root class")
    return value


class StoreError(RuntimeError):
    """A synthetic I1 store operation failed closed."""


class ObjectExists(StoreError):
    """The authoritative destination or identity already exists."""


class IntegrityFailure(StoreError):
    """Readback or append-only integrity is uncertain."""


class StoreQuarantined(StoreError):
    """No new writes are allowed while store integrity is incomplete."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_no_replace(source: Path, destination: Path) -> None:
    """Publish one staged file through held NTFS parent handles without replacement."""
    if os.name != "nt":
        raise StoreError("Windows native no-replace publication required")
    with pin_parent_directories(source, destination) as pins:
        try:
            native_ntfs.rename_no_replace(
                pins.handle_for(source.parent), source.name,
                pins.handle_for(destination.parent), destination.name,
            )
        except FileExistsError as exc:
            raise ObjectExists("atomic no-replace destination collision") from exc


class AppendOnlyStore:
    """Synthetic local-NTFS writer. No session/run authority is issued here."""

    def __init__(
        self,
        root: Path,
        *,
        create: bool = False,
        store_id: str | None = None,
        lineage_id: str | None = None,
        actor_id: str | None = None,
        writer_private_key: Ed25519PrivateKey | None = None,
        trusted_checkpoint: Mapping[str, Any] | None = None,
        trusted_checkpoint_public_key_hex: str | None = None,
        store_mode: str = "SYNTHETIC_I1_NONAUTHORITATIVE",
    ) -> None:
        root = Path(root)
        if not root.is_absolute():
            raise StoreError("absolute store root required")
        check_ancestors(root, include_final=not create)
        root = root.resolve()
        if create and any((parent / "ENGINEERING_CUSTODY_PROFILE.json").exists()
                          for parent in root.parents):
            raise StoreQuarantined("engineering store creation requires custodian bootstrap")
        binding = _read_custody_binding(root) if not create else None
        parameters = {
            "create": create, "store_id": store_id, "lineage_id": lineage_id,
            "actor_id": actor_id, "writer_private_key": writer_private_key,
            "trusted_checkpoint": trusted_checkpoint,
            "trusted_checkpoint_public_key_hex": trusted_checkpoint_public_key_hex,
            "store_mode": store_mode,
        }
        if writer_private_key is not None and binding is not None:
            if not _CUSTODY_WRAPPER.get():
                raise StoreQuarantined("engineering writable entrypoint requires custody wrapper")
            # The routing flag is forgeable. Hold both pinned roots and all
            # existing evidence files through admission and initialization.
            from .checkpoint_custody import (
                ChainTrust, _hold_evidence_snapshot, _hold_roots,
                validate_bound_writable,
            )
            protected_trust = ChainTrust(**binding["trust"])
            custody = Path(binding["custody_root"])
            with _hold_roots(custody, root, protected_trust), _hold_evidence_snapshot(root):
                try:
                    admission = validate_bound_writable(root, binding)
                except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
                    raise StoreQuarantined("engineering custody admission failed") from exc
                if (trusted_checkpoint != admission["legacy_pin"]
                        or trusted_checkpoint_public_key_hex != admission["trust"].public_key_hex):
                    raise StoreQuarantined("writer checkpoint differs from owner custody head")
                self._initialize(root, **parameters)
            return
        self._initialize(root, **parameters)

    def _initialize(
        self, root: Path, *, create: bool, store_id: str | None,
        lineage_id: str | None, actor_id: str | None,
        writer_private_key: Ed25519PrivateKey | None,
        trusted_checkpoint: Mapping[str, Any] | None,
        trusted_checkpoint_public_key_hex: str | None,
        store_mode: str,
    ) -> None:
        if store_mode not in {"SYNTHETIC_I1_NONAUTHORITATIVE", "I3_NATIVE_ENGINEERING_NONAUTHORITATIVE"}:
            raise StoreError("unsupported evidence-store mode")
        if create and not isinstance(writer_private_key, Ed25519PrivateKey):
            raise StoreError("synthetic writer signing key required")
        if create or writer_private_key is not None:
            if trusted_checkpoint is None or trusted_checkpoint_public_key_hex is None:
                raise StoreQuarantined("external trusted checkpoint required for writable admission")
            if store_id is None or lineage_id is None:
                raise StoreQuarantined("expected store and lineage IDs required for writable admission")
            from .integrity import checkpoint_payload
            try:
                payload = trusted_checkpoint["payload"]
                signature = bytes.fromhex(trusted_checkpoint["signature_hex"])
                owner_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_checkpoint_public_key_hex))
                owner_key.verify(signature, checkpoint_payload(
                    payload["store_id"], payload["lineage_id"],
                    payload["sequence"], payload["manifest_sha256"],
                ))
                if payload["store_id"] != store_id or payload["lineage_id"] != lineage_id:
                    raise StoreQuarantined("checkpoint identity mismatch")
                if create and (payload["sequence"] != 0 or payload["manifest_sha256"] is not None):
                    raise StoreQuarantined("signed genesis checkpoint required for creation")
            except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
                raise StoreQuarantined("external checkpoint invalid") from exc
        if create:
            if root.exists():
                raise ObjectExists("store root already exists")
            try:
                with pin_parent_directories(root) as pins:
                    native_ntfs.create_directory_new(pins.handle_for(root.parent), root.name)
            except FileExistsError as exc:
                raise ObjectExists("store root already exists") from exc
        self.paths = StoragePaths(root)
        self.root = self.paths.root
        self.schemas = SchemaRegistry()
        self._identity_schema = self.schemas.find_document("OP1_IDENTITY_ENVELOPE_SCHEMA.json")
        self._local_mutex = threading.Lock()
        self._quarantined = False
        self._writer_private_key = writer_private_key
        self._trusted_checkpoint = trusted_checkpoint
        self._trusted_checkpoint_public_key_hex = trusted_checkpoint_public_key_hex
        self._observed_sequence = 0
        self._observed_manifest_sha256 = None
        if create:
            if store_id is None or lineage_id is None or actor_id is None:
                raise StoreError("store, lineage and actor IDs required")
            validate_id(store_id, "RESOURCE")
            validate_id(lineage_id, "LINEAGE")
            validate_id(actor_id, "ACTOR")
            for relative in ("staging/x", "manifests/x", "registry/locators/x", "records/evidence/x"):
                self.paths.ensure_parents(relative)
            header = {
                "identity": self._envelope(store_id, "RESOURCE", actor_id, status="I3_ENGINEERING" if store_mode == "I3_NATIVE_ENGINEERING_NONAUTHORITATIVE" else "SYNTHETIC_I1"),
                "store_id": store_id, "lineage_id": lineage_id,
                "writer_public_key_hex": writer_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                "mode": store_mode, "created_at_utc": utc_now(),
            }
            self._write_exclusive("store_header.json", canonical_json(header))
            self._write_exclusive("writer.lock", b"\x00")
        header = strict_json_loads(self._readback(self.paths.checked_path("store_header.json", require_existing=True)))
        validate_id(header["store_id"], "RESOURCE")
        validate_id(header["lineage_id"], "LINEAGE")
        if header.get("mode") != store_mode:
            raise StoreError("unqualified store header")
        shape = self.schemas.validate(self._identity_schema.schema_id, self._identity_schema.version, header["identity"])
        if not shape.valid or header["identity"]["entity_id"] != header["store_id"]:
            raise StoreError("invalid store identity envelope")
        self.store_id = header["store_id"]
        self.lineage_id = header["lineage_id"]
        self.actor_id = header["identity"]["actor_id"]
        try:
            self.writer_public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(header["writer_public_key_hex"]))
        except (ValueError, KeyError) as exc:
            raise StoreError("invalid synthetic writer public key") from exc
        self.writer_authentication_ref = sha256_bytes(bytes.fromhex(header["writer_public_key_hex"]))
        if writer_private_key is not None and writer_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != header["writer_public_key_hex"]:
            raise StoreError("writer private key does not match store")
        if store_id is not None and self.store_id != store_id:
            raise StoreError("store ID mismatch")
        if lineage_id is not None and self.lineage_id != lineage_id:
            raise StoreError("lineage ID mismatch")
        if self._readback(self.paths.checked_path("writer.lock", require_existing=True)) != b"\x00":
            raise StoreError("writer lock file tampered")
        chain = self._manifest_chain()
        if not create:
            from .integrity import IntegrityVerifier
            if writer_private_key is not None:
                verdict = IntegrityVerifier(self.root).verify(
                    trusted_checkpoint=trusted_checkpoint,
                    trusted_checkpoint_public_key_hex=trusted_checkpoint_public_key_hex,
                )
                if verdict["result"] != "PASS" or verdict["checkpoint_status"] != "VERIFIED":
                    raise StoreQuarantined("writable reopen failed trusted checkpoint verification")
            else:
                verdict = IntegrityVerifier(self.root).verify()
                if verdict["result"] != "PASS":
                    self._quarantined = True
        if writer_private_key is not None:
            self._observed_sequence = trusted_checkpoint["payload"]["sequence"]
            self._observed_manifest_sha256 = trusted_checkpoint["payload"]["manifest_sha256"]
        else:
            self._observed_sequence = len(chain)
            self._observed_manifest_sha256 = sha256_bytes(chain[-1][1]) if chain else None

    def _envelope(self, entity_id: str, kind: str, actor_id: str, *, status: str = "COMMITTED") -> dict[str, Any]:
        validate_id(entity_id, kind)
        validate_id(actor_id, "ACTOR")
        return {
            "entity_id": entity_id, "entity_type": kind,
            "schema_id": self._identity_schema.schema_id,
            "schema_version": self._identity_schema.version,
            "actor_id": actor_id, "created_at_utc": utc_now(), "status": status,
        }

    def _write_exclusive(self, relative: str, data: bytes) -> None:
        path = self.paths.ensure_parents(relative)
        check_ancestors(path, include_final=False)
        with self.paths.guard_paths(path) as pins:
            parent = pins.handle_for(path.parent)
            try:
                handle = native_ntfs.open_file(parent, path.name, create=True, write=True)
                with native_ntfs.file_object(handle, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
            except FileExistsError as exc:
                raise ObjectExists("create-new destination exists") from exc
            if native_ntfs.read_file(parent, path.name) != data:
                raise IntegrityFailure("exclusive write readback mismatch")

    @contextmanager
    def writer(self):
        if self._quarantined:
            raise StoreQuarantined("store is quarantined")
        if self._writer_private_key is None:
            raise StoreError("read-only store handle cannot write")
        with self._local_mutex:
            try:
                lock_path = self.paths.checked_path("writer.lock", require_existing=True)
                with self.paths.guard_paths(lock_path) as pins:
                    native = native_ntfs.open_file(
                        pins.handle_for(lock_path.parent), lock_path.name,
                        read=True, write=True,
                    )
                    with native_ntfs.file_object(native, "r+b") as handle:
                        deadline = time.monotonic() + 10
                        while True:
                            handle.seek(0)
                            try:
                                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                                break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    raise StoreQuarantined("writer lock uncertain or timed out")
                                time.sleep(0.025)
                        try:
                            if self._quarantined:
                                raise StoreQuarantined("store is quarantined")
                            chain = self._manifest_chain()
                            if len(chain) < self._observed_sequence:
                                raise StoreQuarantined("observed manifest prefix truncated")
                            if self._observed_sequence:
                                if sha256_bytes(chain[self._observed_sequence - 1][1]) != self._observed_manifest_sha256:
                                    raise StoreQuarantined("observed manifest prefix replaced")
                            from .integrity import IntegrityVerifier
                            preflight = IntegrityVerifier(self.root).verify(
                                _held_writer_lock_handle=handle,
                            )
                            if preflight["result"] != "PASS":
                                raise StoreQuarantined("pretransaction store integrity failed")
                            yield handle
                            chain = self._manifest_chain()
                            self._observed_sequence = len(chain)
                            self._observed_manifest_sha256 = sha256_bytes(chain[-1][1]) if chain else None
                        except BaseException:
                            self._quarantined = True
                            raise
                        finally:
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except BaseException:
                self._quarantined = True
                raise

    def _fault(self, hook: FaultHook | None, name: str, path: Path) -> None:
        if hook is not None:
            hook(name, path)

    def _readback(self, path: Path) -> bytes:
        with self.paths.guard_paths(path) as pins:
            return native_ntfs.read_file(pins.handle_for(path.parent), path.name)

    def _publish_bytes(self, relative: str, data: bytes, *, phase: str, fault: FaultHook | None = None) -> dict[str, Any]:
        if not isinstance(data, bytes):
            raise StoreError("exact byte payload required")
        final = self.paths.ensure_parents(relative)
        check_ancestors(final, include_final=False)
        self._fault(fault, f"{phase}.before_create", final)
        stage_rel = f"staging/{generate_id('ARTIFACT')}.partial"
        staged = self.paths.ensure_parents(stage_rel)
        with self.paths.guard_paths(final, staged) as pins:
            try:
                handle = native_ntfs.open_file(
                    pins.handle_for(staged.parent), staged.name,
                    create=True, write=True,
                )
                with native_ntfs.file_object(handle, "wb") as output:
                    self._fault(fault, f"{phase}.after_partial_create", staged)
                    pivot = max(1, len(data) // 2)
                    output.write(data[:pivot])
                    self._fault(fault, f"{phase}.mid_write", staged)
                    output.write(data[pivot:])
                    self._fault(fault, f"{phase}.after_write", staged)
                    output.flush()
                    os.fsync(output.fileno())
                self._fault(fault, f"{phase}.after_flush", staged)
                expected = sha256_bytes(data)
                staged_bytes = self._readback(staged)
                if len(staged_bytes) != len(data) or sha256_bytes(staged_bytes) != expected:
                    raise IntegrityFailure("staged readback length/hash mismatch")
                self._fault(fault, f"{phase}.before_publish", final)
                atomic_no_replace(staged, final)
                self._fault(fault, f"{phase}.after_publish", final)
                committed = self._readback(final)
                if len(committed) != len(data) or sha256_bytes(committed) != expected:
                    raise IntegrityFailure("final readback length/hash mismatch")
                return {"relative_path": relative, "byte_length": len(data), "sha256": expected}
            except FileExistsError as exc:
                raise ObjectExists("staging or destination collision") from exc

    def _manifest_chain(self) -> tuple[tuple[dict[str, Any], bytes], ...]:
        directory = self.paths.checked_path("manifests", require_existing=True)
        with self.paths.guard_paths(directory / "_scan_") as pins:
            rows = []
            prior = None
            seen_ids: set[str] = set()
            seen_paths: set[str] = set()
            parent = pins.handle_for(directory)
            files = native_ntfs.list_directory(parent)
            for index, (name, attributes) in enumerate(files, 1):
                if attributes & 0x410:  # reparse point or directory
                    raise IntegrityFailure("foreign manifest entry type")
                match = _MANIFEST_NAME.fullmatch(name)
                if match is None or int(match.group(1)) != index:
                    raise IntegrityFailure("manifest name/sequence gap or foreign file")
                raw = native_ntfs.read_file(parent, name)
                try:
                    row = strict_json_loads(raw)
                except ValueError as exc:
                    raise IntegrityFailure("malformed manifest") from exc
                if not isinstance(row, dict) or raw != canonical_json(row) or row.get("sequence") != index or row.get("previous_manifest_sha256") != prior:
                    raise IntegrityFailure("manifest chain mismatch")
                if row.get("store_id") != self.store_id or row.get("manifest_id") != match.group(2):
                    raise IntegrityFailure("manifest store or ID mismatch")
                signed = dict(row)
                signature_hex = signed.pop("writer_signature_hex", None)
                try:
                    self.writer_public_key.verify(bytes.fromhex(signature_hex), canonical_json(signed))
                except (ValueError, TypeError, InvalidSignature) as exc:
                    raise IntegrityFailure("manifest writer signature invalid") from exc
                identity = row.get("identity")
                shape = self.schemas.validate(self._identity_schema.schema_id, self._identity_schema.version, identity)
                if not shape.valid or identity["entity_id"] != row["manifest_id"] or identity["entity_type"] != "ARTIFACT":
                    raise IntegrityFailure("manifest identity invalid")
                object_id = row.get("object_id")
                object_path = row.get("object_relative_path")
                validate_id(object_id)
                self.paths.checked_path(object_path)
                if object_id in seen_ids or object_path.casefold() in seen_paths:
                    raise IntegrityFailure("duplicate immutable object identity or path")
                seen_ids.add(object_id)
                seen_paths.add(object_path.casefold())
                rows.append((row, raw))
                prior = sha256_bytes(raw)
            return tuple(rows)

    def _append_manifest(self, actor_id: str, body: Mapping[str, Any], *, fault: FaultHook | None = None) -> dict[str, Any]:
        chain = self._manifest_chain()
        sequence = len(chain) + 1
        manifest_id = generate_id("ARTIFACT")
        row = {
            "identity": self._envelope(manifest_id, "ARTIFACT", actor_id),
            "manifest_id": manifest_id, "store_id": self.store_id,
            "sequence": sequence,
            "previous_manifest_sha256": sha256_bytes(chain[-1][1]) if chain else None,
            **body,
        }
        if self._writer_private_key is None:
            raise StoreError("manifest signing key unavailable")
        row["writer_signature_hex"] = self._writer_private_key.sign(canonical_json(row)).hex()
        raw = canonical_json(row)
        relative = f"manifests/{sequence:012d}-{manifest_id}.json"
        self._publish_bytes(relative, raw, phase="manifest", fault=fault)
        self._fault(fault, "manifest.after_commit", self.root / relative)
        return {"manifest_id": manifest_id, "sequence": sequence, "relative_path": relative, "sha256": sha256_bytes(raw)}

    def manifest_rows(self) -> tuple[dict[str, Any], ...]:
        return tuple(row for row, _ in self._manifest_chain())

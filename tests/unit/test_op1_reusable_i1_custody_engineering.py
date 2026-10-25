"""Engineering-only custody-chain behavior; same-user fixtures are not ACL proof."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)

from op1_reusable_i1_helpers import event_record, publish, signed_checkpoint, synthetic_store
from package_g.op1_reusable.checkpoint_custody import (
    ChainTrust, CheckpointError, CheckpointVerifier, OwnerSigner,
    _hold_evidence_snapshot,
    current_sid, make_sign_request, open_writable_with_custody,
    root_identity, write_sign_request, provision_engineering_binding,
)
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes, strict_json_loads
from package_g.op1_reusable.integrity import IntegrityVerifier


def _setup(base: Path, store):
    custody = base / "custody"
    custody.mkdir()
    (custody / "signer.lock").write_bytes(b"\x00")
    (custody / "requests").mkdir()
    owner_key = Ed25519PrivateKey.generate()
    key_path = base / "owner-key.pem"
    key_path.write_bytes(owner_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
    ))
    public = owner_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sid = current_sid()
    trust = ChainTrust(
        signer_actor_id=generate_id("ACTOR"),
        signing_key_id="KEY-" + sha256_bytes(bytes.fromhex(public))[:32],
        public_key_hex=public,
        signer_sid=sid,
        writer_sid="S-1-5-21-1-2-3-9999",
        custody_root_identity=root_identity(custody),
        request_root_identity=root_identity(custody / "requests"),
        evidence_root_identity=root_identity(store.root),
        store_header_sha256=sha256_bytes((store.root / "store_header.json").read_bytes()),
        store_id=store.store_id,
        lineage_id=store.lineage_id,
        version_id=generate_id("VERSION"),
    )
    provision_engineering_binding(custody, store.root, trust)
    return custody, key_path, trust


def _request(trust, store, seq, prev_id=None, prev_sha=None):
    report = IntegrityVerifier(store.root).verify()
    assert report["result"] == "PASS"
    return make_sign_request(
        trust, sequence=seq, previous_checkpoint_id=prev_id,
        previous_checkpoint_sha256=prev_sha,
        manifest_count=report["manifest_count"],
        payload_sha256=report["manifest_root_sha256"],
    )


def test_signed_chain_and_read_only_verification():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            receipt = signer.sign_and_publish(request, expected_head_id=None, expected_head_sha256=None)
            digest = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            assert receipt["checkpoint"]["checkpoint_id"] == "CHK-000001"
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "PASS"
            publish(store, scope, actor, b"next")
            request2 = _request(trust, store, 2, "CHK-000001", digest)
            write_sign_request(custody, trust, request2)
            signer.sign_and_publish(request2, expected_head_id="CHK-000001", expected_head_sha256=digest)
            head2 = sha256_bytes((custody / "CHK-000002.json").read_bytes())
            report = CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000002", expected_head_sha256=head2,
            )
            assert report["result"] == "PASS" and report["checkpoint_count"] == 2
            reconstructed = CheckpointVerifier(custody, store.root, trust).reconstruct_head()
            assert reconstructed["result"] == "PASS"
            assert reconstructed["head_source"] == "VALIDATED_CHAIN"
            assert (reconstructed["head_checkpoint_id"], reconstructed["head_sha256"]) == ("CHK-000002", head2)


def test_rollback_missing_mutation_and_wrong_key_fail_closed():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            signer.sign_and_publish(request, expected_head_id=None, expected_head_sha256=None)
            first = custody / "CHK-000001.json"
            digest = sha256_bytes(first.read_bytes())
            verifier = CheckpointVerifier(custody, store.root, trust)
            assert verifier.verify(expected_head_id="CHK-000001", expected_head_sha256=digest)["result"] == "PASS"
            wrong_public = "00" * 32
            wrong = ChainTrust(**{
                **trust.__dict__,
                "public_key_hex": wrong_public,
                "signing_key_id": "KEY-" + sha256_bytes(bytes.fromhex(wrong_public))[:32],
            })
            assert CheckpointVerifier(custody, store.root, wrong).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "FAIL"
            first.write_bytes(first.read_bytes() + b" ")
            assert verifier.verify(expected_head_id="CHK-000001", expected_head_sha256=digest)["result"] == "FAIL"
            first.unlink()
            assert verifier.verify(expected_head_id="CHK-000001", expected_head_sha256=digest)["result"] == "FAIL"


def test_owner_signer_refuses_writer_identity():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            with pytest.raises(CheckpointError):
                ChainTrust(**{**trust.__dict__, "writer_sid": current_sid()})


def test_duplicate_request_is_idempotent_and_stale_candidate_fails():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            first = signer.sign_and_publish(request, expected_head_id=None, expected_head_sha256=None)
            retry = signer.sign_and_publish(request, expected_head_id=None, expected_head_sha256=None)
            assert retry == first
            stale = _request(trust, store, 1)
            write_sign_request(custody, trust, stale)
            with pytest.raises(CheckpointError):
                signer.sign_and_publish(stale, expected_head_id=None, expected_head_sha256=None)
            assert len(list(custody.glob("CHK-*.json"))) == 1


def test_concurrent_publication_has_one_winner():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request_a = _request(trust, store, 1)
            request_b = _request(trust, store, 1)
            write_sign_request(custody, trust, request_a)
            write_sign_request(custody, trust, request_b)
            def submit(request):
                return OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                    request, expected_head_id=None, expected_head_sha256=None,
                )
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(submit, request) for request in (request_a, request_b)]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result())
                    except CheckpointError:
                        outcomes.append("FAIL_CLOSED")
            assert sum(isinstance(item, dict) for item in outcomes) == 1
            assert outcomes.count("FAIL_CLOSED") == 1
            head = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=head,
            )["result"] == "PASS"

def test_concurrent_non_genesis_candidates_have_one_signed_successor():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-next-race-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            first_request = _request(trust, store, 1)
            write_sign_request(custody, trust, first_request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                first_request, expected_head_id=None, expected_head_sha256=None,
            )
            first = custody / "CHK-000001.json"
            first_sha = sha256_bytes(first.read_bytes())
            publish(store, scope, actor, b"non-genesis candidate")
            request_a = _request(trust, store, 2, "CHK-000001", first_sha)
            request_b = _request(trust, store, 2, "CHK-000001", first_sha)
            assert request_a["sign_request_id"] != request_b["sign_request_id"]
            write_sign_request(custody, trust, request_a)
            write_sign_request(custody, trust, request_b)

            def submit(request):
                return OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                    request, expected_head_id="CHK-000001", expected_head_sha256=first_sha,
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(submit, item) for item in (request_a, request_b)]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result())
                    except CheckpointError:
                        outcomes.append("FAIL_CLOSED")
            assert sum(isinstance(item, dict) for item in outcomes) == 1
            assert outcomes.count("FAIL_CLOSED") == 1
            assert sha256_bytes(first.read_bytes()) == first_sha
            assert len(list(custody.glob("CHK-*.json"))) == 2
            second = custody / "CHK-000002.json"
            second_sha = sha256_bytes(second.read_bytes())
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )["result"] == "PASS"


@pytest.mark.parametrize("phase", ["before_sign", "during_sign", "after_sign"])
def test_prepublication_crash_keeps_request_and_allows_exact_retry(phase):
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            request_path = write_sign_request(custody, trust, request)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            def crash(point):
                if point == phase:
                    raise RuntimeError("synthetic crash")
            with pytest.raises(RuntimeError):
                signer.sign_and_publish(
                    request, expected_head_id=None,
                    expected_head_sha256=None, fault=crash,
                )
            assert request_path.read_bytes() == canonical_json(request)
            assert not list(custody.glob("CHK-*.json"))
            signer.sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            digest = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "PASS"


def test_publication_crashes_fail_closed_or_retry_idempotently():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            def during(point):
                if point == "during_publication":
                    raise RuntimeError("synthetic crash")
            with pytest.raises(RuntimeError):
                signer.sign_and_publish(
                    request, expected_head_id=None,
                    expected_head_sha256=None, fault=during,
                )
            assert list(custody.glob("*.partial"))
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id=None, expected_head_sha256=None,
            )["result"] == "FAIL"
            recovered = signer.recover_publication(
                request["sign_request_id"],
                expected_head_id=None, expected_head_sha256=None,
            )
            assert recovered["checkpoint"]["checkpoint_id"] == "CHK-000001"
            assert not list(custody.glob("*.partial"))
            digest = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "PASS"


def test_after_publication_before_ack_exact_retry_returns_receipt():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            def after(point):
                if point == "after_publication":
                    raise RuntimeError("synthetic crash")
            with pytest.raises(RuntimeError):
                signer.sign_and_publish(
                    request, expected_head_id=None,
                    expected_head_sha256=None, fault=after,
                )
            receipt = signer.sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            assert receipt == strict_json_loads((custody / "CHK-000001.json").read_bytes())
            assert len(list(custody.glob("CHK-*.json"))) == 1


def test_header_mutation_fails_and_candidate_mutation_cannot_change_signed_history():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            request_path = write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            head = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            verifier = CheckpointVerifier(custody, store.root, trust)
            header = store.root / "store_header.json"
            header_bytes = header.read_bytes()
            header.write_bytes(header_bytes + b" ")
            assert verifier.verify(
                expected_head_id="CHK-000001", expected_head_sha256=head,
            )["result"] == "FAIL"
            assert header.read_bytes() == header_bytes + b" "
            header.write_bytes(header_bytes)
            request_bytes = request_path.read_bytes()
            request_path.write_bytes(request_bytes + b" ")
            assert verifier.verify(
                expected_head_id="CHK-000001", expected_head_sha256=head,
            )["result"] == "PASS"
            assert request_path.read_bytes() == request_bytes + b" "
            request_path.unlink()
            assert verifier.verify(
                expected_head_id="CHK-000001", expected_head_sha256=head,
            )["result"] == "PASS"
            assert sha256_bytes((custody / "CHK-000001.json").read_bytes()) == head


def test_signed_previous_link_and_rollback_are_checked():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            first_request = _request(trust, store, 1)
            write_sign_request(custody, trust, first_request)
            signer.sign_and_publish(
                first_request, expected_head_id=None, expected_head_sha256=None,
            )
            first_path = custody / "CHK-000001.json"
            first_sha = sha256_bytes(first_path.read_bytes())
            publish(store, scope, actor, b"later")
            second_request = _request(trust, store, 2, "CHK-000001", first_sha)
            write_sign_request(custody, trust, second_request)
            signer.sign_and_publish(
                second_request, expected_head_id="CHK-000001",
                expected_head_sha256=first_sha,
            )
            second_path = custody / "CHK-000002.json"
            second_sha = sha256_bytes(second_path.read_bytes())
            verifier = CheckpointVerifier(custody, store.root, trust)
            assert verifier.verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )["result"] == "PASS"
            second_path.unlink()
            assert verifier.verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )["result"] == "FAIL"
            assert first_path.exists()

def test_invalid_partial_is_preserved_and_blocks_recovery():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            def crash(point):
                if point == "during_publication":
                    raise RuntimeError("synthetic crash")
            with pytest.raises(RuntimeError):
                signer.sign_and_publish(
                    request, expected_head_id=None,
                    expected_head_sha256=None, fault=crash,
                )
            stage = custody / (request["sign_request_id"] + ".partial")
            stage.write_bytes(b"bad partial")
            with pytest.raises((CheckpointError, ValueError)):
                signer.recover_publication(
                    request["sign_request_id"],
                    expected_head_id=None, expected_head_sha256=None,
                )
            assert stage.read_bytes() == b"bad partial"
            assert not list(custody.glob("CHK-*.json"))


def test_signed_but_broken_previous_hash_and_duplicate_sequence_fail():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            first_request = _request(trust, store, 1)
            write_sign_request(custody, trust, first_request)
            signer.sign_and_publish(first_request, expected_head_id=None, expected_head_sha256=None)
            first = custody / "CHK-000001.json"
            first_sha = sha256_bytes(first.read_bytes())
            publish(store, scope, actor, b"second")
            second_request = _request(trust, store, 2, "CHK-000001", first_sha)
            write_sign_request(custody, trust, second_request)
            signer.sign_and_publish(
                second_request, expected_head_id="CHK-000001",
                expected_head_sha256=first_sha,
            )
            second = custody / "CHK-000002.json"
            second_bytes = second.read_bytes()
            second_sha = sha256_bytes(second_bytes)
            verifier = CheckpointVerifier(custody, store.root, trust)
            assert verifier.verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )["result"] == "PASS"
            row = strict_json_loads(second_bytes)
            row["checkpoint"]["previous_checkpoint_sha256"] = "0" * 64
            request_path = custody / "requests" / (second_request["sign_request_id"] + ".json")
            request_bytes = request_path.read_bytes()
            altered_request = canonical_json({
                "sign_request_id": second_request["sign_request_id"],
                "checkpoint": row["checkpoint"],
            })
            request_path.write_bytes(altered_request)
            row["sign_request_sha256"] = sha256_bytes(altered_request)
            row["checkpoint_payload_sha256"] = sha256_bytes(canonical_json(row["checkpoint"]))
            owner_key = load_pem_private_key(key_path.read_bytes(), password=None)
            signed = {name: value for name, value in row.items() if name != "signature_hex"}
            row["signature_hex"] = owner_key.sign(canonical_json(signed)).hex()
            second.write_bytes(canonical_json(row))
            mutated_sha = sha256_bytes(second.read_bytes())
            broken = verifier.verify(
                expected_head_id="CHK-000002", expected_head_sha256=mutated_sha,
            )
            assert broken["result"] == "FAIL"
            assert "broken previous checkpoint link" in broken["finding"]
            second.write_bytes(second_bytes)
            request_path.write_bytes(request_bytes)
            (custody / "CHK-000003.json").write_bytes(second_bytes)
            assert verifier.verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )["result"] == "FAIL"


def test_wrong_signer_signature_and_key_label_fail_closed():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            first = custody / "CHK-000001.json"
            raw = first.read_bytes()
            digest = sha256_bytes(raw)
            wrong_signer = ChainTrust(**{
                **trust.__dict__, "signer_actor_id": generate_id("ACTOR"),
            })
            assert CheckpointVerifier(custody, store.root, wrong_signer).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "FAIL"
            with pytest.raises(CheckpointError):
                ChainTrust(**{**trust.__dict__, "signing_key_id": "KEY-" + "0" * 32})
            row = strict_json_loads(raw)
            row["signature_hex"] = "00" * 64
            first.write_bytes(canonical_json(row))
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=digest,
            )["result"] == "FAIL"


def test_actual_writer_token_cannot_construct_owner_signer():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            other_owner = ChainTrust(**{
                **trust.__dict__,
                "signer_sid": "S-1-5-21-1-2-3-9998",
                "writer_sid": current_sid(),
            })
            with pytest.raises(CheckpointError):
                OwnerSigner(custody, store.root, other_owner, key_path)

def test_writable_admission_refuses_signer_token_even_with_valid_chain():
    with synthetic_store() as (store, scope, actor, writer_key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            head_sha = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=head_sha,
            )["result"] == "PASS"
            with pytest.raises(CheckpointError, match="pinned writer token"):
                open_writable_with_custody(
                    custody, store.root, trust, writer_key,
                    expected_head_id="CHK-000001", expected_head_sha256=head_sha,
                )

def test_owner_refuses_valid_writer_signed_fork_of_checkpointed_prefix():
    with synthetic_store() as (store, scope, actor, writer_key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            first_request = _request(trust, store, 1)
            write_sign_request(custody, trust, first_request)
            signer.sign_and_publish(
                first_request, expected_head_id=None, expected_head_sha256=None,
            )
            head_sha = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            manifest = next((store.root / "manifests").iterdir())
            original = strict_json_loads(manifest.read_bytes())
            forked = dict(original)
            forked["identity"] = dict(original["identity"])
            forked["identity"]["status"] = "FORKED"
            forked.pop("writer_signature_hex")
            forked["writer_signature_hex"] = writer_key.sign(canonical_json(forked)).hex()
            manifest.write_bytes(canonical_json(forked))
            store._observed_manifest_sha256 = sha256_bytes(manifest.read_bytes())
            store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
            assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=head_sha,
            )["result"] == "FAIL"
            second_request = _request(trust, store, 2, "CHK-000001", head_sha)
            write_sign_request(custody, trust, second_request)
            with pytest.raises(CheckpointError, match="evidence prefix differs"):
                signer.sign_and_publish(
                    second_request, expected_head_id="CHK-000001",
                    expected_head_sha256=head_sha,
                )
            assert not (custody / "CHK-000002.json").exists()


def test_verifier_returns_failure_without_repair_for_corrupt_evidence_object():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            record, _ = publish(store, scope, actor, b"original")
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            head_path = custody / "CHK-000001.json"
            head_bytes = head_path.read_bytes()
            object_path = store.root / record["relative_path"]
            object_path.write_bytes(b"corrupt")
            report = CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001",
                expected_head_sha256=sha256_bytes(head_bytes),
            )
            assert report["result"] == "FAIL"
            assert "evidence root integrity failed" in report["finding"]
            assert head_path.read_bytes() == head_bytes
            assert object_path.read_bytes() == b"corrupt"


def test_duplicate_request_id_preserves_first_bytes_and_blocks_signing():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            path = write_sign_request(custody, trust, request)
            original = path.read_bytes()
            conflicting = {**request, "checkpoint": {
                **request["checkpoint"], "payload_sha256": "0" * 64,
            }}
            with pytest.raises(CheckpointError, match="duplicate sign request"):
                write_sign_request(custody, trust, conflicting)
            assert path.read_bytes() == original
            assert (custody / "requests" / (request["sign_request_id"] + ".partial")).exists()
            with pytest.raises(CheckpointError):
                OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                    request, expected_head_id=None, expected_head_sha256=None,
                )
            assert not (custody / "CHK-000001.json").exists()


def test_foreign_checkpoint_destination_collision_preserves_existing_bytes():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            target = custody / "CHK-000001.json"
            target.write_bytes(b"foreign checkpoint")
            with pytest.raises((CheckpointError, ValueError)):
                OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                    request, expected_head_id=None, expected_head_sha256=None,
                )
            assert target.read_bytes() == b"foreign checkpoint"


def test_owner_key_file_replacement_after_instantiation_blocks_signing():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            old_key = key_path.with_suffix(".old")
            key_path.rename(old_key)
            key_path.write_bytes(old_key.read_bytes())
            with pytest.raises(CheckpointError, match="owner key file identity changed"):
                signer.sign_and_publish(
                    request, expected_head_id=None, expected_head_sha256=None,
                )
            assert not (custody / "CHK-000001.json").exists()


def test_owner_snapshot_denies_separate_process_direct_historical_writes():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            record, _ = publish(store, scope, actor, b"immutable object")
            custody, key_path, trust = _setup(Path(temp), store)
            manifest = next((store.root / "manifests").iterdir())
            evidence_object = store.root / record["relative_path"]
            original_manifest = manifest.read_bytes()
            original_object = evidence_object.read_bytes()
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            child_code = (
                "import sys\n"
                "from pathlib import Path\n"
                "for name in sys.argv[1:]:\n"
                "    try:\n"
                "        Path(name).write_bytes(b'tamper')\n"
                "    except OSError:\n"
                "        print('DENIED')\n"
                "    else:\n"
                "        print('WRITTEN')\n"
            )
            def attempt(point):
                if point == "before_sign":
                    child = subprocess.run(
                        [sys.executable, "-c", child_code, str(manifest), str(evidence_object)],
                        capture_output=True, text=True, check=True,
                    )
                    assert child.stdout.splitlines() == ["DENIED", "DENIED"]
                    assert manifest.read_bytes() == original_manifest
                    assert evidence_object.read_bytes() == original_object
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
                fault=attempt,
            )
            head = custody / "CHK-000001.json"
            assert CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001",
                expected_head_sha256=sha256_bytes(head.read_bytes()),
            )["result"] == "PASS"


def test_engineering_profile_without_binding_quarantines_writable_entrypoint():
    from package_g.op1_reusable.append_only import StoreQuarantined
    from package_g.op1_reusable.evidence_store import EvidenceStore

    with synthetic_store() as (store, scope, actor, writer_key):
        (store.root.parent / "ENGINEERING_CUSTODY_PROFILE.json").write_bytes(
            canonical_json({"ROOT_CLASS": "ENGINEERING_CUSTODY"}),
        )
        with pytest.raises(StoreQuarantined, match="binding missing"):
            EvidenceStore(store.root, writer_private_key=writer_key)


def test_owner_import_hook_failure_prevents_checkpoint_publication():
    with synthetic_store() as (store, scope, actor, writer_key):
        with tempfile.TemporaryDirectory(prefix="custody-import-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            calls = []

            def fail_import():
                calls.append("under_custody_lock")
                raise RuntimeError("synthetic import fault")

            with pytest.raises(RuntimeError, match="synthetic import fault"):
                OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                    request, expected_head_id=None, expected_head_sha256=None,
                    import_candidate=fail_import,
                )
            assert calls == ["under_custody_lock"]
            assert not list(custody.glob("CHK-*.json"))


def test_engineering_profile_blocks_direct_create_before_store_directory():
    from package_g.op1_reusable.append_only import StoreQuarantined
    from package_g.op1_reusable.evidence_store import EvidenceStore

    with tempfile.TemporaryDirectory(prefix="custody-create-", dir=Path.home()) as temp:
        root = Path(temp)
        (root / "ENGINEERING_CUSTODY_PROFILE.json").write_bytes(
            canonical_json({"ROOT_CLASS": "ENGINEERING_CUSTODY"}),
        )
        evidence = root / "evidence"
        evidence.mkdir()
        store = evidence / "store"
        with pytest.raises(StoreQuarantined, match="custodian bootstrap"):
            EvidenceStore(store, create=True, writer_private_key=Ed25519PrivateKey.generate())
        assert not store.exists()


def test_writable_admission_holds_header_bytes_through_constructor(monkeypatch):
    from package_g.op1_reusable import checkpoint_custody as custody_module
    from package_g.op1_reusable import evidence_store as evidence_module

    with synthetic_store() as (store, scope, actor, writer_key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            head_sha = sha256_bytes((custody / "CHK-000001.json").read_bytes())
            header_path = store.root / "store_header.json"
            header_bytes = header_path.read_bytes()
            original_store = evidence_module.EvidenceStore
            from package_g.op1_reusable import append_only as append_module
            from package_g.op1_reusable.append_only import StoreQuarantined
            assert original_store(store.root).manifest_rows() == store.manifest_rows()
            monkeypatch.setattr(custody_module, "current_sid", lambda: trust.writer_sid)
            attacker_pin, attacker_public = signed_checkpoint(store)
            def legacy_attempt():
                return original_store(
                    store.root, writer_private_key=writer_key,
                    store_id=store.store_id, lineage_id=store.lineage_id,
                    trusted_checkpoint=attacker_pin,
                    trusted_checkpoint_public_key_hex=attacker_public,
                )
            with pytest.raises(StoreQuarantined, match="custody wrapper"):
                legacy_attempt()
            forged = append_module._CUSTODY_WRAPPER.set(True)
            try:
                with pytest.raises(StoreQuarantined, match="differs from owner custody head"):
                    legacy_attempt()
            finally:
                append_module._CUSTODY_WRAPPER.reset(forged)

            def checked_constructor(*args, **kwargs):
                child = subprocess.run(
                    [sys.executable, "-c",
                     "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'tamper')",
                     str(header_path)],
                    capture_output=True, text=True,
                )
                assert child.returncode != 0
                assert header_path.read_bytes() == header_bytes
                return original_store(*args, **kwargs)

            monkeypatch.setattr(evidence_module, "EvidenceStore", checked_constructor)
            reopened = open_writable_with_custody(
                custody, store.root, trust, writer_key,
                expected_head_id="CHK-000001", expected_head_sha256=head_sha,
            )
            assert isinstance(reopened, original_store)
            assert header_path.read_bytes() == header_bytes



def test_appcontainer_writer_pins_package_sid_and_zero_capabilities(monkeypatch):
    from package_g.op1_reusable import checkpoint_custody as custody_module

    with synthetic_store() as (store, scope, actor, writer_key):
        with tempfile.TemporaryDirectory(prefix="custody-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            package_sid = "S-1-15-2-1-2-3-4-5-6-7"
            app_trust = ChainTrust(**{
                **trust.__dict__,
                "writer_sid": trust.signer_sid,
                "writer_boundary": "WINDOWS_APPCONTAINER",
                "writer_appcontainer_sid": package_sid,
            })
            assert custody_module.current_appcontainer_identity() == (None, 0)
            custody_module._require_signer_token(app_trust)
            with pytest.raises(CheckpointError, match="pinned zero-capability AppContainer"):
                custody_module._require_writer_token(app_trust)
            monkeypatch.setattr(
                custody_module, "current_appcontainer_identity", lambda: (package_sid, 0),
            )
            custody_module._require_writer_token(app_trust)
            with pytest.raises(CheckpointError, match="owner signer"):
                custody_module._require_signer_token(app_trust)
            monkeypatch.setattr(
                custody_module, "current_appcontainer_identity", lambda: (package_sid, 1),
            )
            with pytest.raises(CheckpointError, match="zero-capability AppContainer"):
                custody_module._require_writer_token(app_trust)
            monkeypatch.setattr(
                custody_module, "current_appcontainer_identity",
                lambda: ("S-1-15-2-7-6-5-4-3-2-1", 0),
            )
            with pytest.raises(CheckpointError, match="pinned zero-capability AppContainer"):
                custody_module._require_writer_token(app_trust)
            with pytest.raises(CheckpointError, match="distinct Windows account"):
                ChainTrust(**{
                    **app_trust.__dict__,
                    "writer_boundary": "WINDOWS_ACCOUNT",
                })


def test_copied_signature_on_changed_checkpoint_payload_fails_closed():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-copy-sig-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            checkpoint_path = custody / "CHK-000001.json"
            original = checkpoint_path.read_bytes()
            copied = strict_json_loads(original)
            copied["checkpoint"]["created_at_utc"] = "2030-01-01T00:00:00Z"
            copied["checkpoint_payload_sha256"] = sha256_bytes(canonical_json(copied["checkpoint"]))
            copied["sign_request_sha256"] = sha256_bytes(canonical_json({
                "sign_request_id": copied["sign_request_id"],
                "checkpoint": copied["checkpoint"],
            }))
            # Both signature values are copied verbatim from the genuine receipt.
            checkpoint_path.write_bytes(canonical_json(copied))
            changed_hash = sha256_bytes(checkpoint_path.read_bytes())
            result = CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000001", expected_head_sha256=changed_hash,
            )
            assert result["result"] == "FAIL"
            assert "invalid owner signature" in result["finding"]


def test_unsigned_checkpoint_object_never_becomes_head():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-unsigned-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            unsigned = {"checkpoint": request["checkpoint"],
                        "sign_request_id": request["sign_request_id"]}
            path = custody / "CHK-000001.json"
            path.write_bytes(canonical_json(unsigned))
            verifier = CheckpointVerifier(custody, store.root, trust)
            assert verifier.reconstruct_head()["result"] == "FAIL"
            assert verifier.verify(
                expected_head_id="CHK-000001",
                expected_head_sha256=sha256_bytes(path.read_bytes()),
            )["result"] == "FAIL"
            assert path.read_bytes() == canonical_json(unsigned)


def test_verifier_interruption_mid_chain_scan_fails_without_repair(monkeypatch):
    import package_g.op1_reusable.checkpoint_custody as custody_module

    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-scan-fault-", dir=Path.home()) as temp:
            custody, key_path, trust = _setup(Path(temp), store)
            signer = OwnerSigner(custody, store.root, trust, key_path)
            first_request = _request(trust, store, 1)
            write_sign_request(custody, trust, first_request)
            signer.sign_and_publish(first_request, expected_head_id=None, expected_head_sha256=None)
            first = custody / "CHK-000001.json"
            first_sha = sha256_bytes(first.read_bytes())
            publish(store, scope, actor, b"second")
            second_request = _request(trust, store, 2, "CHK-000001", first_sha)
            write_sign_request(custody, trust, second_request)
            signer.sign_and_publish(second_request, expected_head_id="CHK-000001", expected_head_sha256=first_sha)
            second = custody / "CHK-000002.json"
            second_sha = sha256_bytes(second.read_bytes())
            original_read = custody_module._read_checkpoint

            def interrupted(root, name):
                if name == "CHK-000002.json":
                    raise OSError("synthetic verifier interruption")
                return original_read(root, name)

            monkeypatch.setattr(custody_module, "_read_checkpoint", interrupted)
            result = CheckpointVerifier(custody, store.root, trust).verify(
                expected_head_id="CHK-000002", expected_head_sha256=second_sha,
            )
            assert result["result"] == "FAIL"
            assert "synthetic verifier interruption" in result["finding"]
            assert sha256_bytes(first.read_bytes()) == first_sha
            assert sha256_bytes(second.read_bytes()) == second_sha
            assert not list(custody.glob("*.partial"))


def test_partial_import_hook_crash_preserves_blocker_without_checkpoint():
    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-import-crash-", dir=Path.home()) as temp:
            base = Path(temp)
            custody, key_path, trust = _setup(base, store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            marker = base / "IMPORT_STARTED_000001.json"
            partial = store.root / "staging" / "synthetic-import.partial"

            def crash_after_partial_import():
                marker.write_bytes(b"import started")
                partial.write_bytes(b"incomplete candidate copy")
                raise RuntimeError("synthetic import interruption")

            signer = OwnerSigner(custody, store.root, trust, key_path)
            with pytest.raises(RuntimeError, match="synthetic import interruption"):
                signer.sign_and_publish(request, expected_head_id=None,
                    expected_head_sha256=None, import_candidate=crash_after_partial_import)
            assert marker.read_bytes() == b"import started"
            assert partial.read_bytes() == b"incomplete candidate copy"
            assert not list(custody.glob("CHK-*.json"))
            assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"
            with pytest.raises(CheckpointError):
                signer.sign_and_publish(request, expected_head_id=None, expected_head_sha256=None)
            assert not list(custody.glob("CHK-*.json"))


def test_custody_root_reparse_alias_cannot_verify_or_open_writer():
    import os

    with synthetic_store() as (store, scope, actor, key):
        with tempfile.TemporaryDirectory(prefix="custody-root-alias-", dir=Path.home()) as temp:
            base = Path(temp)
            custody, key_path, trust = _setup(base, store)
            request = _request(trust, store, 1)
            write_sign_request(custody, trust, request)
            OwnerSigner(custody, store.root, trust, key_path).sign_and_publish(
                request, expected_head_id=None, expected_head_sha256=None,
            )
            alias = base / "custody-alias"
            try:
                os.symlink(custody, alias, target_is_directory=True)
            except OSError:
                if os.name != "nt":
                    pytest.skip("directory symlink unavailable")
                linked = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(custody)],
                    capture_output=True, text=True, check=False,
                )
                if linked.returncode != 0 or not alias.exists():
                    pytest.skip("directory junction unavailable")
            try:
                result = CheckpointVerifier(alias, store.root, trust).reconstruct_head()
                assert result["result"] == "FAIL"
                assert (custody / "CHK-000001.json").exists()
            finally:
                if alias.exists() or alias.is_symlink():
                    if os.path.isjunction(alias):
                        alias.rmdir()
                    else:
                        alias.unlink()

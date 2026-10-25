"""Local append-only continuity adapter; no signature or independent custody.

An existing journal and its lock must remain under caller control. This detects
corrupt/truncated history, not malicious rollback or replacement of all bytes.
A stale lock fails closed and requires separately reviewed recovery.
"""
import hashlib
import json
import os
from pathlib import Path

from integration import ReceiptRegistry, canonical
from loader import MODULES

HEADER = {'schema': 'I7_LOCAL_RECEIPT_JOURNAL_V1', 'custody': 'LOCAL_UNAUTHENTICATED'}


class DurableRegistry:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = self.path.with_name(self.path.name + '.lock')

    @classmethod
    def create(cls, path):
        registry = cls(path)
        with registry.path.open('xb') as stream:
            stream.write(canonical(HEADER) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        return registry

    def _load(self):
        body = self.path.read_bytes()
        if not body.endswith(b'\n'):
            raise ValueError('interrupted or truncated journal; recovery deferred')
        lines = body.splitlines()
        if not lines or lines[0] != canonical(HEADER):
            raise ValueError('journal header missing or invalid')
        state = ReceiptRegistry()
        event_ids = set()
        previous = hashlib.sha256(lines[0]).hexdigest()
        for line in lines[1:]:
            row = json.loads(line)
            if canonical(row) != line or type(row) is not dict or set(row) != {'previous', 'operation'} or row['previous'] != previous:
                raise ValueError('journal chain invalid')
            operation = row['operation']
            if type(operation) is not dict:
                raise ValueError('journal operation invalid')
            if set(operation) == {'action', 'receipt', 'outputs_hex'} and operation['action'] == 'ADMIT':
                outputs = operation['outputs_hex']
                if type(outputs) is not dict or any(type(k) is not str or type(v) is not str for k, v in outputs.items()):
                    raise ValueError('journal output mapping invalid')
                decoded = {k: bytes.fromhex(v) for k, v in outputs.items()}
                if any(decoded[k].hex() != outputs[k] for k in outputs):
                    raise ValueError('journal noncanonical output bytes')
                state.admit(operation['receipt'], decoded)
                ids = {event['id'] for event in operation['receipt']['events']}
                if ids & event_ids:
                    raise ValueError('cross-receipt event replay')
                event_ids.update(ids)
            elif set(operation) == {'action', 'run_id'} and operation['action'] == 'REVOKE':
                if not state.revoke_run(operation['run_id']):
                    raise ValueError('journal duplicate revocation')
            else:
                raise ValueError('journal operation invalid')
            previous = hashlib.sha256(line).hexdigest()
        return state, previous, event_ids

    def _perform(self, action, receipt=None, outputs=None, run_id=None):
        # Exclusive creation serializes load, validation and append. Never steal
        # an existing lock or silently restart a possibly interrupted operation.
        with self.lock.open('xb') as lock_stream:
            lock_stream.write(b'LOCAL_EXCLUSIVE_OPERATION\n')
        try:
            state, previous, event_ids = self._load()
            if action == 'SNAPSHOT':
                return state.snapshot()
            if action == 'ADMIT':
                # Exact builtin snapshot and validation are delegated to the
                # accepted component before touching the journal.
                snapshot = MODULES['security.receipt_registry']._plain_snapshot
                receipt, outputs = snapshot(receipt), snapshot(outputs)
                result = state.admit(receipt, outputs)
                if {event['id'] for event in receipt['events']} & event_ids:
                    raise ValueError('cross-receipt event replay')
                operation = {'action': 'ADMIT', 'receipt': receipt,
                             'outputs_hex': {k: v.hex() for k, v in outputs.items()}}
            else:
                result = state.revoke_run(run_id)
                if not result:
                    return False
                operation = {'action': 'REVOKE', 'run_id': run_id}
            row = canonical({'previous': previous, 'operation': operation}) + b'\n'
            with self.path.open('ab') as stream:
                stream.write(row)
                stream.flush()
                os.fsync(stream.fileno())
            return result
        finally:
            self.lock.unlink()

    def admit(self, receipt, outputs):
        return self._perform('ADMIT', receipt=receipt, outputs=outputs)

    def revoke_run(self, run_id):
        return self._perform('REVOKE', run_id=run_id)

    def snapshot(self):
        return self._perform('SNAPSHOT')

"""I7 Engineering context engine. Stored evidence grants no operational authority."""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from contextlib import contextmanager, closing
from copy import deepcopy
from pathlib import Path

RELATIONSHIPS = {'VERIFIED_CAUSAL', 'VERIFIED_ASSOCIATION', 'DERIVED_ASSOCIATION', 'HYPOTHESIS', 'UNKNOWN'}
SCOPES = {'AUTHORIZED_METADATA', 'ENGINEERING_RESULT', 'SYNTHETIC', 'HISTORICAL_COMPATIBILITY'}


class EngineError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json_loads(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EngineError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw,
                      object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(EngineError('nonfinite JSON')))


def pointer(value, path):
    if path == '':
        return value
    if not isinstance(path, str) or not path.startswith('/'):
        raise EngineError('invalid evidence pointer')
    try:
        for part in path[1:].split('/'):
            if re.search(r'~(?![01])', part):
                raise EngineError('invalid pointer escape')
            key = part.replace('~1', '/').replace('~0', '~')
            if isinstance(value, list):
                if not re.fullmatch(r'0|[1-9][0-9]*', key):
                    raise EngineError('invalid array pointer')
                value = value[int(key)]
            else:
                value = value[key]
        return value
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise EngineError('unresolved evidence pointer') from exc


def _identity(value):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise EngineError('invalid identity')
    return value


class Engine:
    """Authoritative immutable JSON and exact bytes; SQLite is a disposable index.

    admit_source is an explicit caller grant for one exact path/hash/scope. It
    never follows source references or reads any referenced original bodies.
    """
    def __init__(self, root, grants=()):
        self.root = Path(root).resolve()
        self.grants = {(str(Path(g['path']).resolve()).casefold(), g['sha256'], g['scope']) for g in grants}
        for name in ('objects', 'sources', 'versions'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.metrics = {'REPEATED_SOURCE_READS': 0, 'SOURCE_READS': 0, 'RECONSTRUCTION_REQUIRED': False}
        self._raw_cache = {}
        self._parsed_cache = {}
        self._index_stat = None
        self._graph = None
        self._manifest = None
        self.verify()
        self._ensure_index()

    @contextmanager
    def _lock(self):
        path = self.root / 'writer.lock'
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise EngineError('writer lock exists; concurrent write or interrupted writer requires explicit recovery') from exc
        try:
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            yield
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def _immutable(path, raw):
        if path.exists():
            if path.read_bytes() != raw:
                raise EngineError('immutable object collision or mutation')
            return
        try:
            with path.open('xb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if path.read_bytes() != raw:
                raise EngineError('immutable object collision')

    def _sources(self):
        rows = {}
        for path in sorted((self.root / 'sources').glob('*.json')):
            raw = path.read_bytes()
            if sha256_bytes(raw) != path.stem:
                raise EngineError('source descriptor tampering')
            row = strict_json_loads(raw)
            if row['source_id'] in rows and rows[row['source_id']] != row:
                raise EngineError('source identity rebound')
            rows[row['source_id']] = row
        return rows

    def admit_source(self, path, sha256, scope='AUTHORIZED_METADATA', source_id=None):
        """Read exactly the caller-authorized file once, preserving its raw bytes."""
        if scope not in SCOPES:
            raise EngineError('unauthorized read scope')
        if not re.fullmatch('[0-9a-f]{64}', sha256 or ''):
            raise EngineError('malformed source SHA-256')
        source_id = _identity(source_id or sha256)
        original = Path(path)
        if original.is_symlink():
            raise EngineError('symlink source rejected')
        absolute = original.resolve(strict=True)
        owned = absolute.is_relative_to(self.root) and scope in {'ENGINEERING_RESULT', 'SYNTHETIC'}
        if not owned and (str(absolute).casefold(), sha256, scope) not in self.grants:
            raise EngineError('exact source read grant missing; no content read performed')
        for component in [original.absolute(), *original.absolute().parents]:
            if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
                raise EngineError('source reparse component rejected')
        if any(part.lower() in {'holdout', 'secrets', '.aws'} for part in absolute.parts):
            raise EngineError('excluded source path')
        row = {'source_id': source_id, 'sha256': sha256, 'path': str(absolute), 'scope': scope}
        with self._lock():
            existing = self._sources().get(source_id)
            if existing:
                if any(existing[k] != row[k] for k in row):
                    raise EngineError('source identity cannot be rebound')
                self._object(existing)
                return deepcopy(existing)
            raw = absolute.read_bytes()
            self.metrics['SOURCE_READS'] += 1
            if sha256_bytes(raw) != sha256:
                raise EngineError('incorrect source hash')
            row['byte_length'] = len(raw)
            self._immutable(self.root / 'objects' / sha256, raw)
            encoded = canonical_json(row)
            self._immutable(self.root / 'sources' / (sha256_bytes(encoded) + '.json'), encoded)
        return deepcopy(row)

    def read_source(self, source_id):
        row = self._sources().get(source_id)
        if row is None:
            raise EngineError('source not admitted; no read performed')
        return self._object(row)

    def _object(self, row):
        path = self.root / 'objects' / row['sha256']
        stat = path.stat()
        signature = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
        cached = self._raw_cache.get(row['sha256'])
        if cached and cached[0] == signature:
            return cached[1]
        raw = path.read_bytes()
        if sha256_bytes(raw) != row['sha256'] or len(raw) != row['byte_length']:
            raise EngineError('source object tampering')
        self._raw_cache[row['sha256']] = (signature, raw)
        return raw

    def _binding(self, binding, sources):
        row = sources.get(binding.get('source_id'))
        if row is None:
            raise EngineError('unadmitted evidence source')
        if binding.get('sha256', row['sha256']) != row['sha256']:
            raise EngineError('incorrect evidence source hash')
        result = {'source_id': row['source_id'], 'sha256': row['sha256'], 'pointer': binding.get('pointer', '')}
        raw = self._object(row)
        if row['sha256'] not in self._parsed_cache:
            self._parsed_cache[row['sha256']] = strict_json_loads(raw)
        value = pointer(self._parsed_cache[row['sha256']], result['pointer'])
        result['value_sha256'] = sha256_bytes(canonical_json(value))
        if binding.get('value_sha256', result['value_sha256']) != result['value_sha256']:
            raise EngineError('evidence value commitment differs')
        return result, value

    def _validate(self, graph):
        sources = {row['source_id']: row for row in graph['sources']}
        admitted = self._sources()
        for key, row in sources.items():
            if admitted.get(key) != row:
                raise EngineError('graph source descriptor mismatch')
            self._object(row)
        nodes = {row['id']: row for row in graph['observations']}
        if len(nodes) != len(graph['observations']):
            raise EngineError('duplicate observation identity')
        successor = {}
        event_ids = set()
        for row in nodes.values():
            _identity(row['id'])
            bound, value = self._binding(row['evidence_binding'], sources)
            if bound != row['evidence_binding']:
                raise EngineError('observation evidence binding differs')
            if 'value' in row and row['value'] != value:
                raise EngineError('observation differs from source value')
            if row.get('event_id'):
                if row['event_id'] in event_ids:
                    raise EngineError('duplicate event identity')
                event_ids.add(row['event_id'])
            previous = row.get('supersedes')
            if previous:
                if previous not in nodes or previous == row['id']:
                    raise EngineError('invalid supersession target')
                if nodes[previous].get('kind') != row.get('kind') or nodes[previous].get('task_id') != row.get('task_id'):
                    raise EngineError('supersession scope conflict')
                if previous in successor:
                    raise EngineError('conflicting supersession')
                successor[previous] = row['id']
        for start in successor:
            seen = set()
            while start in successor:
                if start in seen:
                    raise EngineError('supersession cycle')
                seen.add(start)
                start = successor[start]
        edge_ids = set()
        for edge in graph['edges']:
            if edge['id'] in edge_ids:
                raise EngineError('duplicate edge identity')
            edge_ids.add(_identity(edge['id']))
            if edge['from'] not in nodes or edge['to'] not in nodes or edge['relationship'] not in RELATIONSHIPS:
                raise EngineError('invalid graph relationship')
            values = []
            for binding in edge['evidence_bindings']:
                normalized, value = self._binding(binding, sources)
                if normalized != binding:
                    raise EngineError('edge binding differs')
                values.append(value)
            if edge['relationship'].startswith('VERIFIED_'):
                assertion = {key: edge[key] for key in ('from', 'to', 'relationship')}
                if not any(isinstance(value, dict) and all(value.get(k) == v for k, v in assertion.items()) for value in values):
                    raise EngineError('verified relationship lacks exact source assertion')

    def latest(self):
        self._refresh()
        return deepcopy(self._manifest)

    def _refresh(self):
        """Observe another writer's atomic commit without rescanning old bodies."""
        names = sorted(p.name for p in (self.root / 'versions').iterdir()
                       if p.is_dir() and not p.name.startswith('.'))
        known = (f'{self._manifest["version"]:08d}-{self._manifest["graph_sha256"]}'
                 if self._manifest else None)
        if (names[-1] if names else None) != known:
            self.verify()
            self._index_stat = None

    def verify(self):
        previous = None
        graph = None
        manifest = None
        all_sources = self._sources()
        for row in all_sources.values():
            self._object(row)
        directories = sorted(p for p in (self.root / 'versions').iterdir() if p.is_dir() and not p.name.startswith('.'))
        for number, directory in enumerate(directories, 1):
            manifest = strict_json_loads((directory / 'manifest.json').read_bytes())
            graph_raw = (directory / 'graph.json').read_bytes()
            prov_raw = (directory / 'provenance.json').read_bytes()
            graph = strict_json_loads(graph_raw)
            prov = strict_json_loads(prov_raw)
            if manifest['version'] != number or directory.name != f'{number:08d}-{manifest["graph_sha256"]}':
                raise EngineError('version order conflict')
            if manifest['parent_sha256'] != previous or sha256_bytes(graph_raw) != manifest['graph_sha256'] or sha256_bytes(prov_raw) != manifest['provenance_sha256']:
                raise EngineError('version cryptographic binding mismatch')
            if graph['version'] != number or graph['parent_sha256'] != previous or prov['graph_version'] != number or prov['graph_sha256'] != manifest['graph_sha256']:
                raise EngineError('provenance rebound to incorrect graph')
            if canonical_json(graph) != graph_raw or canonical_json(prov) != prov_raw:
                raise EngineError('noncanonical authoritative record')
            self._validate(graph)
            if {r['observation_id'] for r in prov['records']} != {r['id'] for r in graph['observations']}:
                raise EngineError('incomplete provenance')
            if len(prov['records']) != len(graph['observations']):
                raise EngineError('duplicate provenance observation identity')
            source_rows = {r['source_id']: r for r in graph['sources']}
            for item in prov['records']:
                node = next(r for r in graph['observations'] if r['id'] == item['observation_id'])
                if item['graph_version'] != number or item['graph_sha256'] != manifest['graph_sha256'] or item['evidence_binding'] != node['evidence_binding']:
                    raise EngineError('provenance record graph/source binding differs')
                source_id = node['evidence_binding']['source_id']
                if item['source_artifact_identity'] != source_id or item['authority_read_scope'] != source_rows[source_id]['scope']:
                    raise EngineError('provenance source identity/read scope differs')
                if any(item[key] != node.get(key, 'UNKNOWN') for key in ('task_id', 'run_id', 'session_id')):
                    raise EngineError('provenance task/run/session differs')
                if item['provider_identity'] != 'UNKNOWN' or item['process_identity'] != 'UNKNOWN' or item['independent_custody'] != 'NOT_PROVEN':
                    raise EngineError('provenance fabricates established identity or custody')
            previous = manifest['graph_sha256']
        self._graph, self._manifest = graph, manifest
        return {'status': 'PASS', 'versions': len(directories), 'sources': len(all_sources)}

    def ingest(self, observations, edges=(), expected_parent=None, provenance=None):
        start = time.perf_counter()
        with self._lock():
            self.verify()
            parent = self._manifest['graph_sha256'] if self._manifest else None
            if expected_parent is not None and expected_parent != parent:
                raise EngineError('conflicting parent version')
            graph = deepcopy(self._graph) if self._graph else {'schema': 'I4-NEXT-v0.1', 'sources': [], 'observations': [], 'edges': []}
            sources = self._sources()
            nodes = {r['id']: r for r in graph['observations']}
            links = {r['id']: r for r in graph['edges']}
            for observation in observations:
                row = deepcopy(observation)
                _identity(row['id'])
                binding = row.pop('evidence_binding', None) or {'source_id': row.pop('source_id'), 'pointer': row.pop('evidence_pointer', '')}
                row['evidence_binding'], _ = self._binding(binding, sources)
                if row['id'] in nodes and nodes[row['id']] != row:
                    raise EngineError('conflicting duplicate observation/event')
                nodes[row['id']] = row
            for original in edges:
                row = deepcopy(original)
                row['evidence_bindings'] = [self._binding(b, sources)[0] for b in row.get('evidence_bindings', [])]
                if row['id'] in links and links[row['id']] != row:
                    raise EngineError('conflicting duplicate edge')
                links[row['id']] = row
            graph['observations'] = [nodes[k] for k in sorted(nodes)]
            graph['edges'] = [links[k] for k in sorted(links)]
            used = {r['evidence_binding']['source_id'] for r in nodes.values()} | {b['source_id'] for e in links.values() for b in e['evidence_bindings']}
            graph['sources'] = [sources[k] for k in sorted(used)]
            self._validate(graph)
            if self._graph and all(graph[k] == self._graph[k] for k in ('sources', 'observations', 'edges')):
                return deepcopy(self._manifest)
            number = self._manifest['version'] + 1 if self._manifest else 1
            graph.update(version=number, parent_sha256=parent)
            graph_raw = canonical_json(graph)
            digest = sha256_bytes(graph_raw)
            declarations = deepcopy(provenance or {})
            if declarations.get('provider_identity', 'UNKNOWN') != 'UNKNOWN' or declarations.get('process_identity', 'UNKNOWN') != 'UNKNOWN':
                raise EngineError('provider/process identity needs independent establishment; declaration alone rejected')
            records = []
            old_records = {}
            if self._manifest:
                old_path = self.root / 'versions' / f'{self._manifest["version"]:08d}-{parent}' / 'provenance.json'
                old_records = {r['observation_id']: r for r in strict_json_loads(old_path.read_bytes())['records']}
            for node in graph['observations']:
                record = {'observation_id': node['id'], 'graph_version': number, 'graph_sha256': digest,
                                'evidence_binding': node['evidence_binding'], 'source_artifact_identity': node['evidence_binding']['source_id'],
                                'authority_read_scope': sources[node['evidence_binding']['source_id']]['scope'],
                                'task_id': node.get('task_id', 'UNKNOWN'), 'run_id': node.get('run_id', 'UNKNOWN'),
                                'session_id': node.get('session_id', 'UNKNOWN'), 'declared_actor_identity': declarations.get('declared_actor_identity', 'UNKNOWN'),
                                'provider_identity': 'UNKNOWN', 'process_identity': 'UNKNOWN', 'tool_identity': declarations.get('tool_identity', 'UNKNOWN'),
                                'timestamp': declarations.get('timestamp', 'UNKNOWN'), 'invocation_evidence': declarations.get('invocation_evidence', 'UNKNOWN'),
                                'independent_custody': 'NOT_PROVEN'}
                if node['id'] in old_records:
                    old = old_records[node['id']]
                    for key in ('declared_actor_identity', 'provider_identity', 'process_identity', 'tool_identity', 'timestamp', 'invocation_evidence'):
                        record[key] = deepcopy(old[key])
                records.append(record)
            prov = {'schema': 'I5-NEXT-v0.1', 'graph_version': number, 'graph_sha256': digest, 'records': records}
            prov_raw = canonical_json(prov)
            manifest = {'version': number, 'parent_sha256': parent, 'graph_sha256': digest, 'provenance_sha256': sha256_bytes(prov_raw)}
            staging = Path(tempfile.mkdtemp(prefix='.staging-', dir=self.root / 'versions'))
            try:
                for name, raw in (('graph.json', graph_raw), ('provenance.json', prov_raw), ('manifest.json', canonical_json(manifest))):
                    self._immutable(staging / name, raw)
                staging.rename(self.root / 'versions' / f'{number:08d}-{digest}')
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
            self._graph, self._manifest = graph, manifest
            self.rebuild_index()
        self.metrics['INCREMENTAL_UPDATE_TIME'] = time.perf_counter() - start
        return deepcopy(manifest)

    def _index_rows(self):
        superseded = {r['supersedes'] for r in (self._graph or {}).get('observations', []) if r.get('supersedes')}
        return [(r['id'], r.get('task_id'), r.get('kind'), r.get('finding_id'), r.get('event_id'), r.get('artifact_id'), r.get('dependency_id'), int(r['id'] not in superseded), canonical_json(r).decode()) for r in (self._graph or {}).get('observations', [])]

    def rebuild_index(self):
        self._refresh()
        path = self.root / 'index.sqlite'
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('DROP TABLE IF EXISTS observations')
            db.execute('CREATE TABLE observations(id TEXT PRIMARY KEY, task_id TEXT, kind TEXT, finding_id TEXT,event_id TEXT,artifact_id TEXT,dependency_id TEXT,active INTEGER,body TEXT)')
            db.executemany('INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?)', self._index_rows())
            for field in ('task_id', 'kind', 'finding_id', 'event_id', 'artifact_id', 'dependency_id'):
                db.execute(f'CREATE INDEX idx_{field} ON observations({field})')
        self._index_stat = self._index_signature()
        return {'status': 'PASS', 'rows': len(self._index_rows())}

    def _ensure_index(self):
        if self._index_stat is not None and self._index_stat == self._index_signature():
            return
        try:
            with closing(sqlite3.connect(self.root / 'index.sqlite')) as db:
                actual = db.execute('SELECT * FROM observations ORDER BY id').fetchall()
            if actual != sorted(self._index_rows()):
                raise EngineError('index differs')
        except (sqlite3.Error, EngineError):
            self.metrics['RECONSTRUCTION_REQUIRED'] = True
            self.rebuild_index()
        self._index_stat = self._index_signature()

    def _index_signature(self):
        path = self.root / 'index.sqlite'
        if not path.exists():
            return None
        stat = path.stat()
        return (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)

    def query(self, task_id=None, kind=None, identifier=None, limit=50, include_superseded=False):
        start = time.perf_counter()
        self._refresh()
        if not 1 <= limit <= 1000:
            raise EngineError('query limit out of bounds')
        self._ensure_index()
        clauses, args = [], []
        for key, value in (('task_id', task_id), ('kind', kind)):
            if value is not None:
                clauses.append(key + '=?')
                args.append(value)
        if identifier is not None:
            clauses.append('(id=? OR finding_id=? OR event_id=? OR artifact_id=? OR dependency_id=?)')
            args.extend([identifier] * 5)
        if not include_superseded:
            clauses.append('active=1')
        with closing(sqlite3.connect(self.root / 'index.sqlite')) as db:
            sql = 'SELECT body FROM observations' + (' WHERE ' + ' AND '.join(clauses) if clauses else '') + ' ORDER BY id LIMIT ?'
            rows = [strict_json_loads(r[0]) for r in db.execute(sql, args + [limit])]
        authoritative = {r['id']: r for r in (self._graph or {}).get('observations', [])}
        if any(authoritative.get(r['id']) != r for r in rows):
            raise EngineError('index query record tampering')
        self.metrics['CONTEXT_QUERY_TIME'] = time.perf_counter() - start
        return rows

    def packet(self, task_id, max_bytes=16384, identifier=None):
        self._refresh()
        if not self._manifest:
            raise EngineError('no graph version')
        result = {'schema': 'OP1-CONTEXT-PACKET-v0.1', 'task_id': task_id, 'graph_binding': self.latest(), 'observations': [], 'source_bindings': [], 'truncated': False,
                  'authority': 'ENGINEERING_ONLY; retrieval does not prove operational execution or independent authority'}
        for row in self.query(task_id=task_id, identifier=identifier, limit=1000):
            candidate = deepcopy(result)
            candidate['observations'].append(row)
            source_id = row['evidence_binding']['source_id']
            if source_id not in {r['source_id'] for r in candidate['source_bindings']}:
                candidate['source_bindings'].append(next(s for s in self._graph['sources'] if s['source_id'] == source_id))
            if len(canonical_json(candidate)) > max_bytes:
                result['truncated'] = True
                break
            result = candidate
        clauses, args = ['task_id=?', 'active=1'], [task_id]
        if identifier is not None:
            clauses.append('(id=? OR finding_id=? OR event_id=? OR artifact_id=? OR dependency_id=?)')
            args.extend([identifier] * 5)
        with closing(sqlite3.connect(self.root / 'index.sqlite')) as db:
            count = db.execute('SELECT COUNT(*) FROM observations WHERE ' + ' AND '.join(clauses), args).fetchone()[0]
        if count > len(result['observations']):
            result['truncated'] = True
        if len(canonical_json(result)) > max_bytes:
            raise EngineError('packet byte budget too small for bindings')
        self.metrics['CONTEXT_PACKET_BYTES'] = len(canonical_json(result))
        return result

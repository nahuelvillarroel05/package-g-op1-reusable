"""I5 serialized persistence through unchanged I1 writer/publication primitives.

A pinned source manifest binds exact byte custody and evidence classifications.
Its writer signature authenticates custody, never the truth of authored claims.
"""
from __future__ import annotations
from pathlib import Path
from .i4_i1 import event
from .i4_graph import SourceCorpus
from .identity import canonical_json, generate_id, sha256_bytes, strict_json_loads
from .i5_provenance import ProvenanceLedger, ProvenanceError, I4_FINGERPRINT

class I1ProvenanceJournal:
    def __init__(self, store, scope, actor_id, corpus, i4_bytes, i4_contexts, *, recovery_root=None):
        self.store,self.scope,self.actor_id=store,scope,actor_id
        self.corpus,self.i4_bytes,self.i4_contexts=corpus,i4_bytes,i4_contexts
        self.recovery_root=Path(recovery_root) if recovery_root else store.root.parent/(store.root.name+'-i5-source-recovery')
        if self.recovery_root.resolve().drive.lower()!='d:':
            raise ProvenanceError('I5 source recovery requires D:')

    def _event(self,role,evidence_ids=()):
        value=event(self.store,self.scope,self.actor_id,role,evidence_ids=evidence_ids)
        value['event_kind']='I5_PROVENANCE_'+role
        return value

    def _publish_locked(self,raw,evidence_class,*,sources=()):
        store,scope=self.store,self.scope
        action=self._event('ACTION')
        store._commit_event_locked(action,scope,'ACTION',None)
        entity=generate_id('EVIDENCE')
        entry=store.schemas.find_document('OP1_EVIDENCE_SCHEMA.json')
        identity={'entity_id':entity,'entity_type':'EVIDENCE','schema_id':entry.schema_id,
                  'schema_version':entry.version,'actor_id':self.actor_id,
                  'created_at_utc':action['occurred_at_utc'],'status':'COMMITTED',
                  'content_sha256':sha256_bytes(raw),
                  **{k:getattr(scope,k) for k in ('project_id','product_id','lineage_id','version_id','session_id','run_id')}}
        record={'identity':identity,'evidence_id':entity,'run_id':scope.run_id,
                'attempt_id':scope.attempt_id,'event_id':action['event_id'],'actor_id':self.actor_id,
                'relative_path':store.paths.object_relative(scope,'derived' if sources else 'raw',entity,'bin'),
                'byte_length':len(raw),'sha256':sha256_bytes(raw),'producer':'I5 source-bound provenance validator',
                'created_at_utc':action['occurred_at_utc'],'evidence_class':evidence_class,
                'derivation_class':'DERIVED_IMMUTABLE' if sources else 'RAW_IMMUTABLE'}
        if sources:record['source_evidence_ids']=sorted(set(sources))
        return store._publish_evidence_locked(record,raw,self._event('PUBLICATION',[entity]),scope,producer_kind='ACTOR',fault=None)

    def _objects(self,klass,*,manifest_rows=None):
        rows=self.store.manifest_rows() if manifest_rows is None else manifest_rows
        published={entity for row in rows if row.get('event_role')=='PUBLICATION' for entity in row.get('referenced_evidence_ids',[])}
        result=[]
        for row in rows:
            if row.get('evidence_class')==klass:
                if row['object_id'] not in published:
                    raise ProvenanceError('ambiguous durable provenance publication')
                raw=(self.store.root/row['object_relative_path']).read_bytes()
                if len(raw)!=row['object_byte_length'] or sha256_bytes(raw)!=row['object_sha256']:
                    raise ProvenanceError('durable provenance integrity lost','REJECT_AND_QUARANTINE_IF_INTEGRITY_LOST')
                result.append((row,raw))
        return result

    def seed_sources(self):
        if self.corpus is None or sha256_bytes(self.i4_bytes)!=I4_FINGERPRINT:
            raise ProvenanceError('exact source corpus and I4 graph required')
        with self.store.writer():
            if self._objects('I5_SOURCE_MANIFEST'):
                raise ProvenanceError('source corpus already seeded')
            mapping=[]
            for name in sorted(self.corpus.files):
                row=self.corpus.files[name]
                receipt=self._publish_locked(self.corpus.read(name),'I5_SOURCE_BYTES')
                mapping.append({**row,'evidence_id':receipt['evidence_id']})
            graph=self._publish_locked(self.i4_bytes,'I5_FROZEN_I4_GRAPH')
            manifest={'corpus_manifest':self.corpus.manifest,
                      'corpus_manifest_bytes_hex':(self.corpus.root/'SOURCE_CORPUS_MANIFEST.json').read_bytes().hex() if (self.corpus.root/'SOURCE_CORPUS_MANIFEST.json').exists() else canonical_json(self.corpus.manifest).hex(),'corpus_manifest_sha256':self.corpus.manifest_sha256,
                      'source_objects':mapping,'i4_graph_evidence_id':graph['evidence_id'],
                      'i4_graph_sha256':I4_FINGERPRINT,'i4_contexts':self.i4_contexts}
            self._publish_locked(canonical_json(manifest),'I5_SOURCE_MANIFEST')

    def _recover(self,manifest_rows=None):
        rows=self.store.manifest_rows() if manifest_rows is None else manifest_rows
        manifests=self._objects('I5_SOURCE_MANIFEST',manifest_rows=rows)
        if len(manifests)!=1:raise ProvenanceError('exactly one pinned source manifest required')
        manifest_row,raw=manifests[0];m=strict_json_loads(raw)
        if self.corpus is not None and self.corpus.manifest_sha256!=m['corpus_manifest_sha256']:
            raise ProvenanceError('external corpus differs from durable pin')
        by_id={r['object_id']:(r,b) for klass in ('I5_SOURCE_BYTES','I5_FROZEN_I4_GRAPH') for r,b in self._objects(klass,manifest_rows=rows)}
        declared={x['corpus_path']:x for x in m['corpus_manifest']['files']}
        if len(m['source_objects'])!=len(declared):raise ProvenanceError('source manifest mapping incomplete')
        mapping={};seen=set()
        for row in m['source_objects']:
            name=row['corpus_path']
            if name in seen or name not in declared or {k:v for k,v in row.items() if k!='evidence_id'}!=declared[name]:
                raise ProvenanceError('source manifest mapping mismatch')
            seen.add(name)
            if row['evidence_id'] not in by_id:raise ProvenanceError('durable source missing')
            source_row,content=by_id[row['evidence_id']]
            if source_row.get('evidence_class')!='I5_SOURCE_BYTES' or sha256_bytes(content)!=row['sha256'] or len(content)!=row['byte_length']:
                raise ProvenanceError('durable source differs')
            path=self.recovery_root/name
            if not path.resolve().is_relative_to(self.recovery_root.resolve()) or path.is_symlink():
                raise ProvenanceError('source recovery path escape')
            if path.exists():
                if path.read_bytes()!=content:raise ProvenanceError('recovery cache integrity lost')
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb') as stream:stream.write(content)
            mapping[name]=row['evidence_id']
        graph=by_id[m['i4_graph_evidence_id']][1]
        if sha256_bytes(graph)!=I4_FINGERPRINT:raise ProvenanceError('durable I4 graph differs')
        corpus=SourceCorpus(self.recovery_root,m['corpus_manifest'],m['corpus_manifest_sha256'],manifest_bytes=bytes.fromhex(m['corpus_manifest_bytes_hex']))
        return corpus,graph,m['i4_contexts'],mapping,manifest_row['object_id']

    @staticmethod
    def _binding_names(candidate):
        result=set()
        def visit(value):
            if isinstance(value,dict):
                if 'corpus_path' in value and 'sha256' in value:result.add(value['corpus_path'])
                for v in value.values():visit(v)
            elif isinstance(value,list):
                for v in value:visit(v)
        visit(candidate)
        return result

    def records(self):return tuple(b for _,b in self._objects('I5_COMMITTED_PROVENANCE'))

    def rebuild(self):
        from .integrity import IntegrityVerifier
        if IntegrityVerifier(self.store.root).verify()['result']!='PASS':
            raise ProvenanceError('I1 provenance integrity lost','REJECT_AND_QUARANTINE_IF_INTEGRITY_LOST')
        rows=self.store.manifest_rows()
        corpus,graph,contexts,_,_=self._recover(rows)
        records=tuple(b for _,b in self._objects('I5_COMMITTED_PROVENANCE',manifest_rows=rows))
        return ProvenanceLedger.rebuild(corpus,graph,contexts,records)

    def append(self,candidate):
        error=None;result=None
        with self.store.writer():
            # One validated snapshot after the unchanged I1 writer preflight.
            # Discard it before unlocking; never reuse across transactions.
            rows=self.store.manifest_rows()
            corpus,graph,contexts,mapping,manifest_id=self._recover(rows)
            names=self._binding_names(candidate)
            sources=[mapping[x] for x in sorted(names & mapping.keys())]+[manifest_id]
            records=tuple(b for _,b in self._objects('I5_COMMITTED_PROVENANCE',manifest_rows=rows))
            ledger=ProvenanceLedger.rebuild(corpus,graph,contexts,records)
            ledger.publisher=lambda raw:self._publish_locked(raw,'I5_COMMITTED_PROVENANCE',sources=sources)
            try:
                if names-mapping.keys():raise ProvenanceError('candidate references unseeded source')
                result=ledger.append(candidate)
            except ProvenanceError as exc:
                self._publish_locked(canonical_json({'candidate':candidate,'outcome':exc.outcome,'reason':str(exc)}),'I5_REJECTED_PROVENANCE',sources=sources)
                error=exc
        if error:raise error
        return result
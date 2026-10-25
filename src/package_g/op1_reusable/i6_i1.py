"""I6 receipts through frozen I1 writer and evidence publication APIs."""
from pathlib import Path
from .i4_i1 import event
from .identity import generate_id,canonical_json,sha256_bytes,strict_json_loads
from .i6_compiler import ImmutableSources,DatasetCompiler,CompilationError
from .integrity import IntegrityVerifier

class I1DatasetJournal:
    def __init__(self,store,scope,actor_id,*,recovery_root):
        self.store,self.scope,self.actor_id=store,scope,actor_id
        self.recovery_root=Path(recovery_root).resolve()
        if self.recovery_root.drive.lower()!='d:':raise CompilationError('D-only I6 source recovery required')

    def _event(self,role,evidence_ids=()):
        record=event(self.store,self.scope,self.actor_id,role,evidence_ids=evidence_ids)
        record['event_kind']='I6_DATASET_'+role
        return record

    def _publish(self,raw,klass,sources=()):
        store,scope=self.store,self.scope
        action=self._event('ACTION');store._commit_event_locked(action,scope,'ACTION',None)
        entity=generate_id('EVIDENCE');schema=store.schemas.find_document('OP1_EVIDENCE_SCHEMA.json')
        identity={'entity_id':entity,'entity_type':'EVIDENCE','schema_id':schema.schema_id,'schema_version':schema.version,
          'actor_id':self.actor_id,'created_at_utc':action['occurred_at_utc'],'status':'COMMITTED','content_sha256':sha256_bytes(raw),
          **{k:getattr(scope,k) for k in ('project_id','product_id','lineage_id','version_id','session_id','run_id')}}
        record={'identity':identity,'evidence_id':entity,'run_id':scope.run_id,'attempt_id':scope.attempt_id,
          'event_id':action['event_id'],'actor_id':self.actor_id,
          'relative_path':store.paths.object_relative(scope,'derived' if sources else 'raw',entity,'bin'),
          'byte_length':len(raw),'sha256':sha256_bytes(raw),'producer':'I6 offline deterministic Dataset Compiler',
          'created_at_utc':action['occurred_at_utc'],'evidence_class':klass,
          'derivation_class':'DERIVED_IMMUTABLE' if sources else 'RAW_IMMUTABLE'}
        if sources:record['source_evidence_ids']=sorted(set(sources))
        return store._publish_evidence_locked(record,raw,self._event('PUBLICATION',[entity]),scope,producer_kind='ACTOR',fault=None)

    def _objects(self,klass,rows):
        publications={e for row in rows if row.get('event_role')=='PUBLICATION' for e in row.get('referenced_evidence_ids',[])}
        objects=[]
        for row in rows:
            if row.get('evidence_class')!=klass:continue
            if row['object_id'] not in publications:raise CompilationError('uncertain durable I6 publication',state='QUARANTINED')
            raw=(self.store.root/row['object_relative_path']).read_bytes()
            if sha256_bytes(raw)!=row['object_sha256'] or len(raw)!=row['object_byte_length']:
                raise CompilationError('durable I6 integrity lost',state='QUARANTINED')
            objects.append((row,raw))
        return objects

    def seed(self,sources):
        with self.store.writer():
            rows=self.store.manifest_rows()
            if self._objects('I6_SOURCE_MANIFEST',rows):raise CompilationError('prior source pin already committed')
            files={}
            for entry in sources.entries.values():
                sources._permission(entry)
                for binding in (entry['record'],entry.get('payload')):
                    if binding:files[binding['path']]=binding
            if sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
                admission=sources.manifest['prospective_admission']
                for binding in [admission['checkpoint_binding'],admission['path_a_finding_binding'],*admission['store_files']]:
                    files[binding['path']]=binding
            files['SOURCE_CORPUS_MANIFEST.json']={'path':'SOURCE_CORPUS_MANIFEST.json',
              'sha256':sources.manifest_sha256,'bytes':(sources.root/'SOURCE_CORPUS_MANIFEST.json').stat().st_size}
            if sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
                # A single RAW source capture preserves every exact member and
                # its original digest. It avoids quadratic I1 publication of
                # hundreds of already committed source-store files.
                members=[{**binding,'bytes_hex':sources.read(binding).hex()}
                         for _,binding in sorted(files.items())]
                capture=self._publish(canonical_json({'format':'I6_EXACT_SOURCE_CAPTURE_V1','files':members}),
                                      'I6_PRIOR_SOURCE_CAPTURE')
                return self._publish(canonical_json({'source_manifest_sha256':sources.manifest_sha256,
                  'source_capture_evidence_id':capture['evidence_id'],'files':[b for _,b in sorted(files.items())]}),
                  'I6_SOURCE_MANIFEST',[capture['evidence_id']])
            mapping=[]
            for name,binding in sorted(files.items()):
                receipt=self._publish(sources.read(binding),'I6_PRIOR_SOURCE_BYTES')
                mapping.append({**binding,'evidence_id':receipt['evidence_id']})
            return self._publish(canonical_json({'source_manifest_sha256':sources.manifest_sha256,'files':mapping}),
                                 'I6_SOURCE_MANIFEST',[x['evidence_id'] for x in mapping])

    def _recover(self,rows):
        pins=self._objects('I6_SOURCE_MANIFEST',rows)
        if len(pins)!=1:raise CompilationError('exactly one prior immutable source pin required')
        pin_row,raw=pins[0];pin=strict_json_loads(raw)
        capture_id=pin.get('source_capture_evidence_id')
        if capture_id:
            captures={row['object_id']:content for row,content in self._objects('I6_PRIOR_SOURCE_CAPTURE',rows)}
            if set(captures)!={capture_id}:raise CompilationError('durable source capture membership mismatch')
            capture=strict_json_loads(captures[capture_id])
            if capture.get('format')!='I6_EXACT_SOURCE_CAPTURE_V1' or not isinstance(capture.get('files'),list):
                raise CompilationError('invalid durable source capture')
            if [{k:v for k,v in b.items() if k!='bytes_hex'} for b in capture['files']]!=pin['files']:
                raise CompilationError('durable source capture member inventory mismatch')
            objects={}
            for binding in capture['files']:
                try:content=bytes.fromhex(binding['bytes_hex'])
                except (ValueError,KeyError,TypeError) as error:raise CompilationError('invalid source capture bytes') from error
                if binding['path'] in objects:raise CompilationError('duplicate durable capture path')
                objects[binding['path']]=content
            raw_source_ids=[capture_id]
        else:
            objects={row['object_id']:content for row,content in self._objects('I6_PRIOR_SOURCE_BYTES',rows)}
            raw_source_ids=[x['evidence_id'] for x in pin['files']]
        seen=set()
        for binding in pin['files']:
            name=binding['path'];path=self.recovery_root/name
            if name.casefold() in seen or not path.resolve().is_relative_to(self.recovery_root) or path.is_symlink():
                raise CompilationError('invalid durable source membership')
            seen.add(name.casefold())
            raw=objects.get(name if capture_id else binding['evidence_id'])
            if raw is None or sha256_bytes(raw)!=binding['sha256'] or len(raw)!=binding['bytes']:
                raise CompilationError('missing/corrupt durable source')
            if path.exists():
                if path.read_bytes()!=raw:raise CompilationError('recovery view modified',state='QUARANTINED')
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb') as stream:stream.write(raw)
        # Frozen I1 DERIVED evidence must name original RAW objects, not a derived pin.
        return ImmutableSources(self.recovery_root,pin['source_manifest_sha256']),raw_source_ids

    def rebuild(self):
        if IntegrityVerifier(self.store.root).verify()['result']!='PASS':raise CompilationError('I1 integrity rejected',state='QUARANTINED')
        rows=self.store.manifest_rows();sources,_=self._recover(rows)
        return DatasetCompiler.reconstruct(sources,[raw for _,raw in self._objects('I6_ACCEPTED_COMPILATION',rows)])

    def compile(self,plan,*,rebuild=False):
        error=None;result=None
        with self.store.writer():
            rows=self.store.manifest_rows();sources,raw_source_ids=self._recover(rows)
            compiler=DatasetCompiler.reconstruct(sources,[raw for _,raw in self._objects('I6_ACCEPTED_COMPILATION',rows)])
            compiler.publisher=lambda raw,klass:self._publish(raw,klass,raw_source_ids)
            try:result=compiler.compile(plan,rebuild=rebuild)
            except CompilationError as exc:error=exc
        if error:raise error
        return result

    def records(self):
        return tuple(raw for _,raw in self._objects('I6_ACCEPTED_COMPILATION',self.store.manifest_rows()))

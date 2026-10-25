"""Deterministic derived dataset compilation over prior immutable registry records.

The trusted corpus pin is a caller's custody anchor, not permission or label truth.
Only pinned source selectors and supported interpretations generate content/labels.
Nothing here executes native cases, trains models, or changes source evidence.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import stat
from .identity import (canonical_json, sha256_bytes, strict_json_loads, validate_id,
                       validate_sha256, parse_id, IdentityError)
from .registry import IdentityRegistry, IdentityRecord
from .schema_registry import SchemaError
from .schema_registry import SchemaRegistry
from .i4_graph import pointer

I4_FINGERPRINT='4a574976eaa7443505eaa4850ff9c000e5f1077fb636920a701d4da1e9b9a1b5'
I5_FINGERPRINT='744911bcd721750497b467cdcadce8eab6daa601606cdee1bd936c72c0a572e5'
CONTRACT_HASHES={
 'OP1_DATASET_COMPILER_IMPLEMENTATION_DESIGN.json':'056c1ae979d9b4d570de94d8268e1c0f54213b3ec1a5627fee5e39d3ab43294a',
 'OP1_DATASET_COMPILATION_POLICY.json':'3ba8f79094c5b4a2b4c10c1b57bac35bfeac5ba14774f4c90104f6c1a42f0319'}
SOURCE_FIELDS={
 'source_session_ids':'SESSION','source_run_ids':'RUN','source_attempt_ids':'ATTEMPT',
 'source_event_ids':'EVENT','source_finding_ids':'FINDING','source_decision_ids':'DECISION',
 'source_artifact_ids':'ARTIFACT','source_evidence_ids':'EVIDENCE','source_actor_ids':'ACTOR',
 'source_report_ids':'REPORT','source_review_ids':'REVIEW'}
ROLES={
 'source_snapshot_artifact_id':'source_snapshot_sha256',
 'source_manifest_artifact_id':'source_manifest_sha256',
 'graph_root_artifact_id':'source_graph_root_sha256',
 'closure_certificate_artifact_id':'closure_certificate_sha256'}
SPLITS=frozenset({'TRAIN','VALIDATION','TEST','HOLDOUT','UNASSIGNED'})
PROTECTED=frozenset({'HOLDOUT','HIDDEN_CHALLENGE','SEALED_GOLD','SEALED_EVALUATION'})

class CompilationError(ValueError):
    def __init__(self,reason,outcome='REJECT_PROVENANCE',state='MISSING'):
        super().__init__(reason);self.outcome=outcome;self.state=state

def _reject(reason,outcome='REJECT_PROVENANCE',state='MISSING'):
    raise CompilationError(reason,outcome,state)

def compiler_digest(mode):
    """Pin every module implementing prospective admission/interpretation."""
    if mode!='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':return sha256_bytes(Path(__file__).read_bytes())
    names=('i6_compiler.py','i6_admission.py')
    return sha256_bytes(canonical_json({name:sha256_bytes(Path(__file__).with_name(name).read_bytes()) for name in names}))

def _typed_refs(value):
    """Explicit typed ID fields; arbitrary strings in RAW/content are not links."""
    refs=set()
    def visit(v,field=''):
        if isinstance(v,dict):
            if 'entity_type' in v and 'entity_id' in v:validate_id(v['entity_id'],v['entity_type'])
            for k,item in v.items():
                if k=='entity_id' and field=='identity':continue
                if k in {'schema_id','dataset_id','dataset_version_id','dataset_example_id','transformation_id'}:continue
                if k.endswith('_id') or k.endswith('_ids') or k in {'parent_ids','caused_by_ids','subject_ids'}:
                    visit(item,k)
                elif k in {'identity','descriptor','metadata'}:visit(item,k)
        elif isinstance(v,list):
            for item in v:visit(item,field)
        elif isinstance(v,str) and v.startswith('PG-'):
            try:parse_id(v)
            except ValueError:_reject('malformed typed source reference: '+v)
            refs.add(v)
    visit(value)
    return refs

class ImmutableSources:
    """Exact immutable record and payload custody with transitive typed closure."""
    def __init__(self,root:Path,manifest_sha256:str):
        self.root=Path(root).resolve();validate_sha256(manifest_sha256);self.schemas=SchemaRegistry()
        if any(part.upper() in PROTECTED for part in self.root.parts):_reject('protected source root','REJECT_AUTHORITY','EXCLUDED')
        raw=(self.root/'SOURCE_CORPUS_MANIFEST.json').read_bytes()
        if sha256_bytes(raw)!=manifest_sha256:_reject('source corpus manifest commitment differs')
        self._manifest=strict_json_loads(raw);self.manifest_sha256=manifest_sha256
        if self._manifest.get('mode') not in {'ACCEPTED_FROZEN_EVIDENCE','SYNTHETIC_TEST_ONLY','PROSPECTIVE_SOURCE_CLOSURE_BRIDGE'}:
            _reject('unqualified source corpus')
        self._entries={};paths={}
        for entry in self._manifest['entries']:
            entity=entry['entity_id'];validate_id(entity,entry['entity_type'])
            if entity.casefold() in {x.casefold() for x in self._entries}:
                _reject('duplicate provenance identity','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
            self._entries[entity]=deepcopy(entry)
            for binding in (entry['record'],entry.get('payload')):
                if not binding:continue
                validate_sha256(binding['sha256'])
                name=binding['path'];folded=name.casefold()
                if folded in paths and paths[folded]!=(name,binding['sha256']):
                    _reject('case-fold or mutable source alias')
                paths[folded]=(name,binding['sha256'])
        self._reads=[]
        if self._manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
            from .i6_admission import admit
            try:admit(self)
            except (KeyError,ValueError,TypeError,OSError) as exc:
                if isinstance(exc,CompilationError):raise
                _reject('prospective source admission rejected: '+str(exc))

    @property
    def manifest(self):return deepcopy(self._manifest)

    @property
    def entries(self):return deepcopy(self._entries)

    def _permission(self,entry,*,export=False):
        gates=entry['permission']
        for field,allowed in {'license_state':{'CLEARED','RESTRICTED','UNKNOWN'},'access_state':{'AUTHORIZED','RESTRICTED','UNKNOWN'},
                              'supervised_eligibility':{'ELIGIBLE','INELIGIBLE','UNKNOWN'}}.items():
            if gates.get(field) not in allowed:_reject('invalid permission state: '+field,'REJECT_AUTHORITY','UNKNOWN')
        if gates.get('protected_class') in PROTECTED or gates.get('compilation_allowed') is not True:
            _reject('protected or unauthorized source: '+entry['entity_id'],'REJECT_AUTHORITY','EXCLUDED')
        if gates.get('access_state')!='AUTHORIZED':
            _reject('restricted/UNKNOWN access: '+entry['entity_id'],'REJECT_AUTHORITY',gates.get('access_state','UNKNOWN'))
        if export and gates.get('disclosure_authorized') is not True:
            _reject('source disclosure not authorized','REJECT_AUTHORITY','INELIGIBLE')

    def read(self,binding):
        name=binding['path'];path=self.root/name
        if Path(name).is_absolute() or not path.resolve().is_relative_to(self.root):_reject('source path escape')
        if any(part.upper() in PROTECTED for part in Path(name).parts):_reject('protected path','REJECT_AUTHORITY','EXCLUDED')
        current=path
        while current!=self.root:
            if current.exists() and (current.is_symlink() or getattr(current.lstat(),'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT):
                _reject('source reparse boundary')
            current=current.parent
        try:raw=path.read_bytes()
        except OSError as exc:_reject('source read failed '+str(path)+': '+str(exc))
        self._reads.append(name)
        if sha256_bytes(raw)!=binding['sha256'] or len(raw)!=binding['bytes']:_reject('RAW/record hash binding differs: '+name)
        return raw

    def resolve(self,entity,kind=None,*,export=False):
        validate_id(entity,kind)
        if entity not in self._entries:_reject('unresolved prior committed '+entity)
        entry=self._entries[entity];self._permission(entry,export=export)
        record=strict_json_loads(self.read(entry['record']))
        identity=record.get('identity',record)
        if identity['entity_id']!=entity or identity['entity_type']!=entry['entity_type']:_reject('wrong registry record identity')
        envelope_schema=self.schemas.find_document('OP1_IDENTITY_ENVELOPE_SCHEMA.json')
        validation=self.schemas.validate(envelope_schema.schema_id,envelope_schema.version,identity)
        if not validation.valid:_reject('source identity schema rejected: '+'; '.join(validation.errors))
        if identity['status']!='COMMITTED':_reject('source is not prior committed')
        schema=self.schemas.lookup(identity['schema_id'],identity['schema_version'])
        if schema.document_id=='OP1_IDENTITY_ENVELOPE_SCHEMA.json':
            if record!=identity:_reject('envelope source must be exact identity record')
        else:
            validation=self.schemas.validate(schema.schema_id,schema.version,record)
            if not validation.valid:_reject('source core schema rejected: '+'; '.join(validation.errors))
            if record.get(entry['entity_type'].lower()+'_id')!=entity:_reject('source top-level typed identity differs')
        if identity.get('content_sha256') and not entry.get('payload'):_reject('committed content bytes missing')
        if entry.get('payload'):
            payload=self.read(entry['payload'])
            if identity.get('content_sha256')!=sha256_bytes(payload):_reject('original payload differs from committed identity digest')
        if entry.get('payload'):
            if entry['entity_type']=='EVIDENCE' and (record.get('sha256')!=entry['payload']['sha256'] or record.get('byte_length')!=entry['payload']['bytes']):
                _reject('EVIDENCE core RAW digest/length differs')
            if entry['entity_type']=='EVENT' and record.get('payload_sha256')!=entry['payload']['sha256']:_reject('EVENT payload digest differs')
            if entry['entity_type']=='REPORT' and record.get('content_sha256')!=entry['payload']['sha256']:_reject('REPORT content digest differs')
        return deepcopy(entry),record

    def closure(self,seeds,*,export=False):
        if len(seeds)!=len(set(seeds)):_reject('duplicate closure seed','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
        seen={};active=set();registry=IdentityRegistry(self.schemas)
        def visit(entity):
            if entity in active:_reject('cyclic source closure')
            if entity in seen:return
            entry,record=self.resolve(entity,export=export)
            active.add(entity)
            dependencies=set(entry.get('dependencies',[]))
            required=_typed_refs(record)-{entity}
            if not required<=dependencies:_reject('omitted typed source references: '+repr(sorted(required-dependencies)))
            for dependency in sorted(dependencies):visit(dependency)
            identity=record.get('identity',record)
            payload=self.read(entry['payload']) if entry.get('payload') else None
            try:registry._validate(identity,record if 'identity' in record else None,payload)
            except (IdentityError,SchemaError) as exc:_reject('prior registry relationship rejected: '+str(exc))
            registry._records[entity]=IdentityRecord(entity,entry['entity_type'],entity,entry['record']['sha256'],'',len(seen)+1,canonical_json(record))
            active.remove(entity);seen[entity]=entry
        for entity in sorted(seeds):visit(entity)
        if not seen:_reject('empty source set')
        tuples=sorted((entry['entity_type'],entity,entry['record']['sha256']) for entity,entry in seen.items())
        for row in tuples:
            if any(not x.isascii() or '\t' in x or '\n' in x for x in row):_reject('noncanonical source tuple')
        raw=''.join('\t'.join(row)+'\n' for row in tuples).encode('utf-8')
        return seen,raw,sha256_bytes(raw)

    def value(self,entity,path='',*,export=False):
        entry,record=self.resolve(entity,export=export)
        value=strict_json_loads(self.read(entry['payload'])) if entry.get('payload') else record
        return deepcopy(pointer(value,path))

def _aggregate(entries,field,positive):
    values={e['permission'].get(field,'UNKNOWN') for e in entries.values()}
    negative={'license_state':'RESTRICTED','access_state':'RESTRICTED','supervised_eligibility':'INELIGIBLE'}[field]
    if values-{positive,negative,'UNKNOWN'}:_reject('invalid permission state: '+field,'REJECT_AUTHORITY','UNKNOWN')
    return negative if negative in values else 'UNKNOWN' if 'UNKNOWN' in values or not values else positive

def configuration_bytes(plan):
    specs=[]
    for spec in plan['examples']:
        value={k:deepcopy(v) for k,v in spec.items() if k not in {'identity','dataset_example_id','split','provenance_artifact_id'}}
        value['source_ids']=sorted(value['source_ids'])
        value['selectors']=sorted(value['selectors'],key=lambda x:x['name'])
        value['label_derivations']=sorted(value['label_derivations'],key=lambda x:x['label'])
        specs.append(value)
    return canonical_json({'selectors':sorted(specs,key=canonical_json),
        'order':'task_kind/source_set_sha256/example_content_sha256','seed':plan['seed'],
        'redaction':plan.get('redaction')})

class DatasetCompiler:
    """Create-new versions; read-only retry requires exact prior semantic bytes."""
    def __init__(self,sources:ImmutableSources,*,publisher=None):
        self.sources=sources;self.schemas=SchemaRegistry();self.publisher=publisher
        from importlib import resources
        self.contracts={}
        for name,digest in CONTRACT_HASHES.items():
            raw=resources.files(__package__).joinpath('frozen_i6',name).read_bytes()
            if sha256_bytes(raw)!=digest:_reject('frozen I6 contract differs')
            self.contracts[name]=strict_json_loads(raw)
        self.labels=frozenset(self.contracts['OP1_DATASET_COMPILATION_POLICY.json']['labels'])
        self.records=[];self.versions={};self.identities=set();self.assignments={}
        self.quarantined=False;self.output_records={}

    def _schema(self,name,value):
        entry=self.schemas.find_document(name);result=self.schemas.validate(entry.schema_id,entry.version,value)
        if not result.valid:_reject('frozen schema rejected: '+'; '.join(result.errors))

    def _labels(self,spec,closure,plan):
        supports=[];seen=set();scoped={}
        for proof in spec['label_derivations']:
            label=proof['label'];basis=proof['basis_id'];scope=tuple(sorted(set(proof['subject_ids'])))
            if label not in self.labels or label in seen or not scope or len(scope)!=len(proof['subject_ids']):
                _reject('invalid/duplicate/ambiguous label scope')
            if basis not in closure or not set(proof['evidence_ids'])<=set(closure):_reject('label basis outside complete closure')
            for evidence in proof['evidence_ids']:validate_id(evidence,'EVIDENCE')
            if not proof['evidence_ids']:_reject('label lacks independent evidence')
            entry,record=self.sources.resolve(basis)
            if self.sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE' and entry.get('label_authority')!='FROZEN_SOURCE_INTERPRETATION':
                _reject('prospective labels require exact frozen interpretation verification')
            if entry.get('label_authority')=='SYNTHETIC_ACCEPTED_FIXTURE' and self.sources.manifest['mode']!='SYNTHETIC_TEST_ONLY':
                _reject('synthetic label authority cannot authorize historical source')
            if entry.get('label_authority') not in {'ACCEPTED_I4_FACT','ACCEPTED_ADJUDICATION','SYNTHETIC_ACCEPTED_FIXTURE','FROZEN_SOURCE_INTERPRETATION'}:
                _reject('unsupported label authority')
            rules=entry.get('field_access',{});path=proof['pointer'];ancestors=[path]
            while '/' in path:
                path=path.rsplit('/',1)[0];ancestors.append(path)
            if any(rules.get(x)=='PRIVATE' for x in ancestors) or rules.get(proof['pointer'])!='PUBLIC':
                _reject('label field disclosure not authorized','REJECT_AUTHORITY','INELIGIBLE')
            observed=self.sources.value(basis,proof['pointer'])
            rule=proof['rule']
            historical_scope=None
            if entry['label_authority']=='FROZEN_SOURCE_INTERPRETATION':
                if self.sources.manifest['mode']!='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
                    _reject('historical interpretation requires qualified current admission')
                from .i6_admission import fact
                observed,actual_subjects,actual_evidence,historical_scope=fact(self.sources,basis,proof)
            elif entry['label_authority']=='ACCEPTED_I4_FACT':
                graph=self.sources.value(plan['source_roles']['graph_root_artifact_id'])
                if sha256_bytes(canonical_json(graph))!=I4_FINGERPRINT:_reject('forged I4 graph binding')
                terminal=entry.get('i4_terminal_event_id')
                facts=[x for x in graph['closures'] if x['terminal_event_id']==terminal]
                if rule!='terminal_outcome' or proof['pointer']!='/classification' or len(facts)!=1 or facts[0]['classification']!=observed or scope!=(terminal,):
                    _reject('forged or unsupported I4 causal label')
                actual_subjects={terminal};actual_evidence=set(entry.get('i4_bound_evidence_ids',[]))
                if not actual_evidence<=set(x['identity'] for x in graph['nodes'] if x['type']=='EVIDENCE'):
                    _reject('forged I4 evidence reference')
            else:
                if self.sources.manifest['mode']=='ACCEPTED_FROZEN_EVIDENCE':
                    snapshot=self.sources.value(plan['source_roles']['source_snapshot_artifact_id'])
                    known=[x['record'] for x in snapshot['provenance_records'] if x['record']['identity']['entity_id']==basis]
                    normalized=deepcopy(record);normalized['identity'].pop('created_at_utc',None)
                    normalized.pop('reviewed_at_utc',None);normalized.pop('decided_at_utc',None)
                    if len(known)!=1 or normalized!=known[0]:_reject('forged/unaccepted I5 adjudication source')
                actual_subjects={x['entity_id'] for x in record.get('subject_ids',[])}
                if entry['entity_type']=='REVIEW':actual_subjects={record['report_id']}
                actual_evidence=set(record.get('evidence_ids',[]))
                if entry['entity_type']=='REVIEW':
                    _,decision=self.sources.resolve(record['decision_id'],'DECISION')
                    actual_evidence=set(decision['evidence_ids'])
                    decision_subjects={x['entity_id'] for x in decision['subject_ids']}
                    if decision.get('outcome')!=record['outcome'] or record['report_id'] not in decision_subjects:
                        _reject('REVIEW and linked DECISION outcome/subject disagree')
                if rule in {'terminal_outcome','review_outcome'}:
                    if proof['pointer']!='/outcome' or record.get('outcome')!=observed:_reject('label pointer is not the source outcome')
                    if rule=='terminal_outcome' and entry['entity_type']!='DECISION':_reject('terminal label needs accepted decision or I4 closure')
                    if rule=='review_outcome' and entry['entity_type']!='REVIEW':_reject('review label needs exact REVIEW')
                elif rule=='safe_abort':
                    if proof['pointer']!='/safe_abort' or entry['entity_type']!='DECISION' or not entry.get('payload'):
                        _reject('safe abort needs exact accepted source fact')
                elif rule=='accepted_label':
                    if proof['pointer']!='/outcome' or record.get('outcome')!=label:_reject('accepted label is not the adjudicated outcome')
            # An interpretation maps an accepted source value, never an LLM vote.
            mapping={
             'terminal_outcome':{'PASS':{'SUCCESSFUL_EXECUTION'},'FAIL':{'FAILED_EXECUTION'},
                'AMBIGUOUS':{'AMBIGUOUS_OWNERSHIP','EVIDENCE_INSUFFICIENCY'},
                'AMBIGUOUS_CONSUMPTION':{'AMBIGUOUS_OWNERSHIP','EVIDENCE_INSUFFICIENCY'}},
             'review_outcome':{'ACCEPTED':{'SUPERVISOR_ACCEPTED'},'REJECTED':{'SUPERVISOR_REJECTED'}},
             'frozen_terminal_outcome':{'PASS':{'SUCCESSFUL_EXECUTION'},'FAIL':{'FAILED_EXECUTION'}},
             'frozen_review_outcome':{'ACCEPTED':{'SUPERVISOR_ACCEPTED'},'REJECTED':{'SUPERVISOR_REJECTED'}},
             'safe_abort':{True:{'SAFE_ABORT'}},
             'accepted_label':{x:{x} for x in self.labels}}
            if rule not in mapping or label not in mapping[rule].get(observed,set()):_reject('label is not supported by immutable source semantics')
            if rule=='accepted_label' and entry['entity_type']!='DECISION':_reject('accepted label requires adjudication DECISION')
            # Evidence must occur in the basis's authenticated support, not just somewhere in corpus.
            if not set(proof['evidence_ids'])<=actual_evidence:_reject('label evidence unrelated to basis')
            if not set(proof['subject_ids'])<=actual_subjects:_reject('label scope unrelated to basis')
            if observed!=proof['expected_value']:_reject('label interpretation expectation differs')
            supports.append({'label':label,'evidence_ids':sorted(proof['evidence_ids']),
                'decision_basis_sha256':entry['payload']['sha256'] if entry.get('payload') else entry['record']['sha256']})
            for subject in scope:scoped.setdefault(subject,set()).add(label)
            if historical_scope:scoped.setdefault(historical_scope,set()).add(label)
            seen.add(label)
        opposite=[{'SUCCESSFUL_EXECUTION','FAILED_EXECUTION'},{'SUCCESSFUL_EXECUTION','AMBIGUOUS_OWNERSHIP'},
          {'SUCCESSFUL_REPAIR','UNSUCCESSFUL_REPAIR'},{'MODEL_CORRECT','MODEL_INCORRECT'},
          {'SUBAGENT_CORRECT','SUBAGENT_INCORRECT'},{'SUPERVISOR_ACCEPTED','SUPERVISOR_REJECTED'}]
        if any(pair<=labels for labels in scoped.values() for pair in opposite):_reject('contradictory labels for same immutable scope')
        if not supports:_reject('missing material label support')
        return sorted(supports,key=lambda x:x['label'])

    def _content(self,spec,closure,plan):
        full={};public={}
        redacting=bool(plan.get('redaction'))
        def project(value,path,rules,inherited=None):
            access='PRIVATE' if inherited=='PRIVATE' else rules.get(path,inherited)
            if access not in {'PUBLIC','PRIVATE'}:_reject('missing explicit field disclosure rule','REJECT_AUTHORITY','UNKNOWN')
            if access=='PRIVATE':
                if not redacting:_reject('prohibited private field selected','REJECT_AUTHORITY','INELIGIBLE')
                return False,None
            if isinstance(value,dict):
                result={}
                for name,item in sorted(value.items()):
                    keep,child=project(item,path+'/'+name.replace('~','~0').replace('/','~1'),rules,access)
                    if keep:result[name]=child
                return True,result
            if isinstance(value,list):
                result=[]
                for index,item in enumerate(value):
                    keep,child=project(item,path+'/'+str(index),rules,access)
                    if keep:result.append(child)
                return True,result
            return True,value
        for selector in spec['selectors']:
            entity=selector['entity_id'];name=selector['name']
            if entity not in closure or name in full:_reject('missing/duplicate content source selector')
            entry,_=self.sources.resolve(entity,export=plan['requested_use']=='EXPORT')
            key=selector['pointer']
            if self.sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
                allowed={'/historical_subject','/historical_assertion_scope','/observed_value','/label_target',
                   '/historical_typed_registry_closure_claimed','/current_context_is_original_execution'}
                if not ((entry.get('label_authority')=='FROZEN_SOURCE_INTERPRETATION' and key in allowed and
                         entity in {x['basis_id'] for x in spec['label_derivations']}) or
                        (entry.get('internal_derivation') and key=='')):
                    _reject('only finitely authorized internal derived fields may be compiled','REJECT_AUTHORITY','INELIGIBLE')
            value=self.sources.value(entity,key)
            full[name]=value
            rules=entry.get('field_access',{});ancestor='';inherited=None
            for token in key.lstrip('/').split('/')[:-1] if key else []:
                if rules.get(ancestor)=='PRIVATE':inherited='PRIVATE';break
                if ancestor in rules:inherited=rules[ancestor]
                ancestor+='/'+token
            if inherited!='PRIVATE' and ancestor in rules:inherited=rules[ancestor]
            keep,value=project(value,key,rules,inherited)
            if keep:public[name]=value
        if plan.get('redaction'):
            redaction=plan['redaction']
            if not redaction.get('review_decision_id') or not redaction.get('supersedes_version_id'):
                _reject('missing redaction metadata','REJECT_AUTHORITY','MISSING')
            review=redaction['review_decision_id'];prior=redaction['supersedes_version_id']
            if review not in closure or prior!=plan.get('supersedes_version_id') or prior not in self.versions:
                _reject('redaction review/prior version outside authoritative closure','REJECT_AUTHORITY','MISSING')
            entry,record=self.sources.resolve(review,'DECISION',export=plan['requested_use']=='EXPORT')
            if entry.get('label_authority') not in {'ACCEPTED_ADJUDICATION','SYNTHETIC_ACCEPTED_FIXTURE'} or record.get('outcome')!='ACCEPTED':
                _reject('redaction review not accepted','REJECT_AUTHORITY','INELIGIBLE')
            reviewed=self.sources.value(review)
            selected={x['entity_id'] for x in spec['selectors']}
            if (reviewed.get('transformation_id')!=plan['transformation_id'] or
                reviewed.get('dataset_version_id')!=plan['dataset_version_id'] or
                reviewed.get('supersedes_version_id')!=prior or not selected<=set(reviewed.get('source_ids',[]))):
                _reject('redaction review/transform/source scope differs')
        if not public:_reject('no permitted content fields','REJECT_AUTHORITY','EXCLUDED')
        raw=canonical_json(public)
        # Full selector digest is internal leakage detection; it reveals no private field.
        return raw,sha256_bytes(canonical_json(full))

    def _example(self,spec,plan):
        validate_id(spec['dataset_example_id'],'DATASET_EXAMPLE')
        if spec['split'] not in SPLITS:_reject('unknown split')
        if spec['split']=='HOLDOUT' and self.sources.manifest['mode']!='SYNTHETIC_TEST_ONLY':
            _reject('protected HOLDOUT split requested','REJECT_AUTHORITY','EXCLUDED')
        roots=spec['source_ids'];roles=plan['source_roles']
        if set(roles)!=set(ROLES):_reject('mandatory prior source artifact roles missing')
        seeds=sorted(set(roots)|set(roles.values()))
        if len(roots)!=len(set(roots)):_reject('duplicate provenance key','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
        closure,tuples,digest=self.sources.closure(seeds,export=plan['requested_use']=='EXPORT')
        if self.sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE':
            from .i6_admission import roles as validate_roles
            validate_roles(self.sources,roles,closure)
        if spec.get('source_set_sha256',digest)!=digest:_reject('caller-supplied source digest differs')
        for entity in closure:
            if entity in {plan['dataset_version_id'],spec['dataset_example_id'],plan['transformation_id']}:
                _reject('output ID cannot masquerade as prior source')
        arrays={field:sorted(x for x,e in closure.items() if e['entity_type']==kind) for field,kind in SOURCE_FIELDS.items()}
        for field in ('source_session_ids','source_run_ids','source_event_ids','source_evidence_ids','source_actor_ids'):
            if not arrays[field]:_reject('missing required '+field)
        for entity,entry in closure.items():
            _,record=self.sources.resolve(entity)
            identity=record.get('identity',record)
            for field in ('run_id','session_id'):
                if record.get(field,identity.get(field)) and record.get(field,identity.get(field)) not in arrays['source_'+field[:-3]+'_ids']:
                    _reject('source scope absent from transitive provenance')
        provenance={**arrays,'dataset_id':plan['dataset_id'],'dataset_version_id':plan['dataset_version_id'],
          'interpretation_schema_id':plan['interpretation_schema_id'],'parser_sha256':plan['parser_sha256'],
          'normalization_config_sha256':plan['normalization_config_sha256'],'transformation_ids':[plan['transformation_id']],
          'split_manifest_sha256':sha256_bytes(canonical_json(plan['split_assignments'])),
          'license_state':_aggregate(closure,'license_state','CLEARED'),
          'access_state':_aggregate(closure,'access_state','AUTHORIZED'),
          'supervised_eligibility':_aggregate(closure,'supervised_eligibility','ELIGIBLE')}
        for field,digest_field in ROLES.items():
            role_id=roles[field];entry,_=self.sources.resolve(role_id,'ARTIFACT')
            if not entry.get('payload'):_reject('source artifact role lacks original bytes')
            provenance[field]=role_id;provenance[digest_field]=entry['payload']['sha256']
            if role_id not in provenance['source_artifact_ids']:_reject('source artifact role not in source array')
        training=(provenance['license_state']=='CLEARED' and provenance['access_state']=='AUTHORIZED'
                  and provenance['supervised_eligibility']=='ELIGIBLE'
                  and all(x['permission'].get('training_use_authorized') is True for x in closure.values()))
        if training:
            for entry in closure.values():
                permission_id=entry['permission'].get('training_permission_decision_id')
                if not permission_id or permission_id not in closure:training=False;break
                _,decision=self.sources.resolve(permission_id,'DECISION')
                actor_id=decision.get('decider_actor_id')
                if not actor_id or actor_id not in closure:training=False;break
                actor=self.sources.value(actor_id)
                grant=self.sources.value(permission_id)
                if (decision.get('outcome')!='TRAINING_AUTHORIZED' or actor.get('actor_kind')!='HUMAN' or
                    grant.get('dataset_id')!=plan['dataset_id'] or grant.get('requested_use')!='TRAINING' or
                    grant.get('license_state')!='CLEARED' or grant.get('access_state')!='AUTHORIZED' or
                    grant.get('supervised_eligibility')!='ELIGIBLE' or
                    grant.get('source_records',{}).get(entry['entity_id'])!=entry['record']['sha256']):
                    training=False;break
        if plan['requested_use']=='TRAINING' and not training:
            state='UNKNOWN' if 'UNKNOWN' in (provenance['license_state'],provenance['supervised_eligibility']) else 'INELIGIBLE'
            _reject('UNKNOWN/restricted/ungranted training use','REJECT_TRAINING_USE',state)
        supports=self._labels(spec,closure,plan);content,origin=self._content(spec,closure,plan)
        identity=deepcopy(spec['identity']);identity['content_sha256']=sha256_bytes(content)
        if identity['entity_id']!=spec['dataset_example_id'] or identity['entity_type']!='DATASET_EXAMPLE':_reject('example/envelope identity differs')
        example={'identity':identity,'dataset_example_id':spec['dataset_example_id'],'dataset_version_id':plan['dataset_version_id'],
          'transformation_id':plan['transformation_id'],'provenance':provenance,'task_kind':spec['task_kind'],
          'labels':[x['label'] for x in supports],'label_support':supports,
          'label_evidence_ids':sorted({e for x in supports for e in x['evidence_ids']}),
          'example_content_sha256':sha256_bytes(content),'source_set_sha256':digest,
          'split':spec['split'],'compilation_status':'ACCEPTED'}
        self._schema('OP1_DATASET_PROVENANCE_SCHEMA.json',provenance)
        self._schema('OP1_DATASET_EXAMPLE_SCHEMA.json',example)
        groups={'RUN:'+x for x in arrays['source_run_ids']}
        for entity,entry in closure.items():
            if entry.get('source_family'):groups.add('FAMILY:'+entry['source_family'])
            if entry.get('historical_assertion_scope'):groups.add('HISTORICAL:'+entry['historical_assertion_scope'])
            if entry['entity_type']=='EVIDENCE' and entry.get('payload'):
                groups.add('EVIDENCE_SHA256:'+entry['payload']['sha256'])
        groups.add('CONTENT_SHA256:'+origin)
        validate_id(spec['provenance_artifact_id'],'ARTIFACT')
        companion={'dataset_example_id':spec['dataset_example_id'],'provenance_artifact_id':spec['provenance_artifact_id'],
          'example_record_sha256':sha256_bytes(canonical_json(example)),
          'provenance_record_sha256':sha256_bytes(canonical_json(provenance)),
          'content_bytes_hex':content.hex(),'training_eligible':training if plan['requested_use']=='TRAINING' else False,
          'requested_use':plan['requested_use'],'eligibility_state':provenance['supervised_eligibility'],
          'origin_content_sha256':origin,'source_set_tuples_hex':tuples.hex(),'leakage_groups':sorted(groups)}
        return example,companion

    def _registrations(self,plan,rows,companions):
        """Validate output records through unchanged I0; I1 stores the exact bytes."""
        registry=IdentityRegistry(self.schemas)
        selected={line.split('\t')[1] for item in companions for line in bytes.fromhex(item['source_set_tuples_hex']).decode().splitlines()}
        for entity in sorted(selected):
            entry,record=self.sources.resolve(entity);raw=canonical_json(record)
            registry._records[entity]=IdentityRecord(entity,entry['entity_type'],entity,sha256_bytes(raw),'',0,raw)
        for entity,record in self.output_records.items():
            raw=canonical_json(record);registry._records[entity]=IdentityRecord(entity,record.get('identity',record)['entity_type'],entity,sha256_bytes(raw),'',0,raw)
        result=[];base=rows[0]['identity'];schema=self.schemas.find_document('OP1_IDENTITY_ENVELOPE_SCHEMA.json')
        def envelope(entity,kind,payload):
            return {'entity_id':entity,'entity_type':kind,'schema_id':schema.schema_id,'schema_version':schema.version,
              'actor_id':base['actor_id'],'project_id':base['project_id'],'product_id':base['product_id'],
              'created_at_utc':base['created_at_utc'],'status':'COMMITTED','content_sha256':sha256_bytes(payload)}
        items=[(plan['dataset_id'],'DATASET',canonical_json({'dataset_id':plan['dataset_id']})),
          (plan['dataset_version_id'],'DATASET_VERSION',canonical_json({'dataset_id':plan['dataset_id'],
            'example_record_sha256s':[x['example_record_sha256'] for x in companions],
            'supersedes_version_id':plan.get('supersedes_version_id')})),
          (plan['transformation_id'],'TRANSFORMATION',canonical_json({'parser_sha256':plan['parser_sha256'],
            'normalization_config_sha256':plan['normalization_config_sha256'],'seed':plan['seed']}))]
        for entity,kind,payload in items:
            if entity in self.output_records:
                prior=self.output_records[entity]
                if prior.get('content_sha256')!=sha256_bytes(payload):_reject('existing dataset/transformation semantic bytes differ')
                result.append(deepcopy(prior));continue
            record=envelope(entity,kind,payload);registry.register(record,logical_key=entity,content_bytes=payload);result.append(record)
        for row,companion in zip(rows,companions):
            payload=bytes.fromhex(companion['content_bytes_hex'])
            if row['dataset_example_id'] in self.output_records:registry.retry_lookup(row['dataset_example_id'],sha256_bytes(canonical_json(row)),'DATASET_EXAMPLE')
            else:registry.register(row['identity'],logical_key=row['dataset_example_id'],record=row,content_bytes=payload)
            result.append(deepcopy(row))
            payload=canonical_json(row['provenance']);entity=companion['provenance_artifact_id']
            record=envelope(entity,'ARTIFACT',payload)
            if entity in self.output_records:registry.retry_lookup(entity,sha256_bytes(canonical_json(record)),'ARTIFACT')
            else:registry.register(record,logical_key=entity,content_bytes=payload)
            result.append(record)
        return sorted(result,key=lambda r:r.get('identity',r)['entity_id'])

    @staticmethod
    def semantic_view(publication):
        rows=[]
        for example in publication['examples']:
            row=deepcopy(example);row['identity'].pop('created_at_utc',None)
            # Output identity and hierarchy IDs are separately bound, not semantic content.
            row.pop('dataset_example_id');row.pop('dataset_version_id');row.pop('identity')
            row['provenance'].pop('dataset_version_id')
            rows.append(row)
        return {'examples':sorted(rows,key=lambda x:(x['task_kind'],x['source_set_sha256'],x['example_content_sha256'])),
                'I4_semantic_graph_fingerprint':publication['I4_semantic_graph_fingerprint'],
                'I5_semantic_provenance_fingerprint':publication['I5_semantic_provenance_fingerprint']}

    def compile(self,plan,*,rebuild=False):
        if self.quarantined:_reject('uncertain publication requires independent durable recovery','REJECT_PROVENANCE','QUARANTINED')
        plan=deepcopy(plan)
        try:
            for field,kind in (('dataset_id','DATASET'),('dataset_version_id','DATASET_VERSION'),('transformation_id','TRANSFORMATION'),('interpretation_schema_id','SCHEMA')):
                validate_id(plan[field],kind)
            if plan['requested_use'] not in {'ENGINEERING','EXPORT','TRAINING'}:_reject('unknown requested use')
            if self.sources.manifest['mode']=='PROSPECTIVE_SOURCE_CLOSURE_BRIDGE' and plan['requested_use']=='EXPORT':
                _reject('current authorization permits internal Engineering only; public export requires separately governed redaction/version','REJECT_AUTHORITY','INELIGIBLE')
            schema=self.schemas.find_document('OP1_DATASET_EXAMPLE_SCHEMA.json')
            if plan['interpretation_schema_id']!=schema.schema_id:_reject('unregistered/unsupported interpretation schema')
            if {plan['dataset_id'],plan['dataset_version_id'],plan['transformation_id']}&set(self.sources.entries):
                _reject('output identity collides with prior source','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
            actual_parser=compiler_digest(self.sources.manifest['mode'])
            if plan['parser_sha256']!=actual_parser:_reject('parser bytes differ from pin')
            if plan['normalization_config_sha256']!=sha256_bytes(configuration_bytes(plan)):_reject('normalization/interpretation configuration differs')
            if plan['split_assignments']!={x['dataset_example_id']:x['split'] for x in plan['examples']}:
                _reject('split assignment manifest differs')
            if self.sources.manifest['mode'] in {'ACCEPTED_FROZEN_EVIDENCE','PROSPECTIVE_SOURCE_CLOSURE_BRIDGE'} and (
                self.sources.manifest['I4_semantic_graph_fingerprint']!=I4_FINGERPRINT or
                self.sources.manifest['I5_semantic_provenance_fingerprint']!=I5_FINGERPRINT):_reject('frozen I4/I5 baseline differs')
            if self.sources.manifest['mode']=='ACCEPTED_FROZEN_EVIDENCE':
                roles=plan['source_roles']
                if (sha256_bytes(canonical_json(self.sources.value(roles['graph_root_artifact_id'])))!=I4_FINGERPRINT or
                    sha256_bytes(canonical_json(self.sources.value(roles['source_snapshot_artifact_id'])))!=I5_FINGERPRINT):
                    _reject('accepted I4/I5 commitments require exact frozen semantic bytes')
            ids=set();keys=set();contents=set();rows=[];companions=[];assignments={}
            for spec in plan['examples']:
                entity=spec['dataset_example_id']
                provenance_id=spec['provenance_artifact_id']
                if entity.casefold() in ids or provenance_id.casefold() in ids:
                    _reject('duplicate example/provenance ID','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
                ids.update({entity.casefold(),provenance_id.casefold()})
                example,companion=self._example(spec,plan)
                key=(plan['dataset_version_id'],example['task_kind'],example['source_set_sha256'],plan['transformation_id'])
                if key in keys:_reject('duplicate semantic key','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
                keys.add(key)
                for group in companion['leakage_groups']:
                    prior=assignments.get(group,self.assignments.get(group))
                    if prior is not None and prior!=example['split']:_reject('prohibited split leakage: '+group,'REJECT_SPLIT_LEAKAGE','QUARANTINED')
                    assignments[group]=example['split']
                content_key=(example['task_kind'],example['example_content_sha256'])
                if content_key in contents:_reject('exact duplicate compiled content','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
                contents.add(content_key);rows.append(example);companions.append(companion)
            order={e['dataset_example_id']:(e['task_kind'],e['source_set_sha256'],e['example_content_sha256']) for e in rows}
            rows.sort(key=lambda e:order[e['dataset_example_id']]);companions.sort(key=lambda e:order[e['dataset_example_id']])
            publication={'dataset_id':plan['dataset_id'],'dataset_version_id':plan['dataset_version_id'],
              'plan':plan,'examples':rows,'companions':companions,
              'I4_semantic_graph_fingerprint':self.sources.manifest['I4_semantic_graph_fingerprint'],
              'I5_semantic_provenance_fingerprint':self.sources.manifest['I5_semantic_provenance_fingerprint']}
            if not rows:_reject('empty dataset cannot be accepted')
            publication['registry_records']=self._registrations(plan,rows,companions)
            publication['semantic_dataset_fingerprint']=sha256_bytes(canonical_json(self.semantic_view(publication)))
            version=plan['dataset_version_id']
            raw=canonical_json(publication)
            if version in self.versions:
                old=self.versions[version]
                if not rebuild or old!=raw:_reject('existing version requires read-only exact ID/digest retry','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
                return deepcopy(publication)
            if rebuild:_reject('missing existing version for rebuild')
            if ids&{x.casefold() for x in self.sources.entries}:_reject('output identity collides with prior source','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
            if ids&self.identities:_reject('example ID already committed','REJECT_DUPLICATE_EXAMPLE','QUARANTINED')
            prior=plan.get('supersedes_version_id')
            if prior and prior not in self.versions:_reject('superseded version absent')
            if self.publisher:
                try:self.publisher(raw,'I6_ACCEPTED_COMPILATION')
                except Exception:self.quarantined=True;raise
            self.output_records.update({r.get('identity',r)['entity_id']:deepcopy(r) for r in publication['registry_records']})
            self.records.append(raw);self.versions[version]=raw;self.identities|=ids;self.assignments.update(assignments)
            return deepcopy(publication)
        except (CompilationError,IdentityError,SchemaError,KeyError,TypeError) as error:
            exc=error if isinstance(error,CompilationError) else CompilationError('invalid compilation structure: '+str(error))
            if self.publisher and not rebuild:
                try:self.publisher(canonical_json({'plan':plan,'outcome':exc.outcome,'state':exc.state,'reason':str(exc)}),'I6_REJECTED_COMPILATION')
                except Exception:self.quarantined=True;raise
            raise exc from (error if error is not exc else None)

    @classmethod
    def reconstruct(cls,sources,records):
        compiler=cls(sources)
        for raw in records:
            expected=strict_json_loads(raw);actual=compiler.compile(expected['plan'])
            if canonical_json(actual)!=raw:_reject('deterministic rebuild drift','REJECT_PROVENANCE','QUARANTINED')
        return compiler

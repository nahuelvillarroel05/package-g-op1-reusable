"""Prospective reconstruction admission; signatures prove custody, not truth.

Historical documents remain exact RAW content. Their quoted identities never
become replacements for missing historical registry records.
"""
from .identity import canonical_json, sha256_bytes, strict_json_loads
from .integrity import IntegrityVerifier
from .evidence_store import EvidenceStore

MODE = 'PROSPECTIVE_SOURCE_CLOSURE_BRIDGE'
# The admitted historical corpus is a separately accepted caller authority pin,
# not a digest inferred from a new capture or a replacement registry record.
ORIGINAL_CORPUS_PIN = '4140f5865dcfb1b1f390da41be9ceaeaf867d7ce68cfe9911e8d89564469486d'
USER_REQUEST_CAPTURE_PIN = '50daf3666c6d7a76142021b95219f93771876ed676685436523db56536506c17'
CLASSES = {
    'source_snapshot_artifact_id': 'I6_SOURCE_SNAPSHOT',
    'source_manifest_artifact_id': 'I6_SOURCE_MANIFEST',
    'graph_root_artifact_id': 'I6_SOURCE_GRAPH_ROOT',
    'closure_certificate_artifact_id': 'I6_SOURCE_CLOSURE_CERTIFICATE',
}

def projection_rules(rules,path):
    """Rebase inherited disclosure; a public wrapper cannot erase private rules."""
    ancestors=[''];current=''
    for token in path.lstrip('/').split('/') if path else []:
        current+='/'+token;ancestors.append(current)
    access=None
    for ancestor in ancestors:
        if rules.get(ancestor)=='PRIVATE':access='PRIVATE';break
        if ancestor in rules:access=rules[ancestor]
    return {'':access,**{key[len(path):]:value for key,value in rules.items() if key.startswith(path+'/')}}

def internal_uses(original,snapshot):
    """Finite selectors requested for P/N/R/U; never a public or training grant."""
    uses=[(original['source_roles']['graph_root_artifact_id'],'/closures'),
          (original['case_artifacts']['E112'],'/classification')]
    for item in snapshot['provenance_records']:
        record=item['record'];entity=record['identity']['entity_id']
        if entity in {'PG-REV-834a36c78980d1ebaa0344382031758f','PG-REV-58750859025ed1d1d62e3a0b70e66e74'}:
            uses.append((entity,'/outcome'))
    return sorted(uses)

def internal_use(sources,entity,path):
    from .i6_compiler import _reject
    admission=sources.manifest['prospective_admission']
    old=strict_json_loads(sources.read(admission['original_manifest_binding']))
    original=next(x for x in old['entries'] if x['entity_id']==entity)
    sources._permission(original)
    rules=projection_rules(original['field_access'],path)
    if 'PRIVATE' in rules.values():_reject('explicit private historical selector denied','REJECT_AUTHORITY','INELIGIBLE')
    decision=sources.value(admission['internal_field_use_decision_id'])
    wanted={'original_entry_id':entity,'record_sha256':original['record']['sha256'],'pointer':path}
    if wanted not in decision['field_uses']:_reject('historical selector outside current Engineering authorization','REJECT_AUTHORITY','INELIGIBLE')


def admit(sources):
    from .i6_compiler import _reject, I4_FINGERPRINT, I5_FINGERPRINT
    manifest = sources.manifest
    admission = manifest['prospective_admission']
    trigger=strict_json_loads(sources.read(admission['path_a_finding_binding']))
    if trigger.get('NO_SUFFICIENT_EXISTING_FULLY_CLOSED_REAL_SOURCE_SET') is not True or trigger.get('Sol_Path_B_trigger')!='AUTHORIZED_CONDITIONAL_PATH_B':
        _reject('prospective bridge lacks evidenced Path A trigger')
    old_manifest=strict_json_loads(sources.read(admission['original_manifest_binding']))
    if admission['original_manifest_binding']['sha256']!=admission['previous_corpus_manifest_sha256'] or admission['previous_corpus_manifest_sha256']!=ORIGINAL_CORPUS_PIN:
        _reject('original frozen corpus pin differs')
    old_entries={x['entity_id']:x for x in old_manifest['entries']}
    if admission.get('historical_ids_backfilled_as_prior') is not False:
        _reject('historical identity backfill prohibited')
    if admission.get('temporal_semantics') != 'CURRENT_CAPTURE_OF_IMMUTABLE_HISTORICAL_BYTES':
        _reject('unqualified temporal provenance')
    # Exact pinned membership includes the signed, immutable precompile store.
    for binding in admission['store_files']:
        sources.read(binding)
    checkpoint = strict_json_loads(sources.read(admission['checkpoint_binding']))
    store_root = sources.root / admission['store_relative_path']
    if not store_root.resolve().is_relative_to(sources.root):
        _reject('prospective commitment store path escape')
    report = IntegrityVerifier(store_root).verify(
        trusted_checkpoint=checkpoint['checkpoint'],
        trusted_checkpoint_public_key_hex=checkpoint['public_key_hex'])
    if report['result'] != 'PASS' or report['checkpoint_status'] != 'VERIFIED':
        _reject('prospective I1 commitment/checkpoint rejected')
    if report['manifest_count'] != checkpoint['checkpoint']['payload']['sequence']:
        _reject('unsealed prospective commitment suffix')
    store = EvidenceStore(store_root)
    rows = {row['object_id']: row for row in store.manifest_rows()}
    published = {entity for row in rows.values() if row.get('event_role') == 'PUBLICATION'
                 for entity in row.get('referenced_evidence_ids', [])}
    for entity, entry in sources.entries.items():
        commitment = entry['commitment']
        if commitment.get('classification') != 'CURRENT_PRIOR_TO_COMPILATION':
            _reject('prospective source falsely claims historical commitment')
        row = rows.get(commitment['object_id'])
        if not row or row['record_sha256'] != commitment['record_sha256']:
            _reject('missing exact prior I1 source commitment')
        raw = sources.read(entry['record'])
        if entry['entity_type'] in {'EVENT', 'EVIDENCE'}:
            if row['object_id'] != entity or row['object_type'] != entry['entity_type']:
                _reject('source record is not actual typed I1 object')
            actual = (store_root / row['record_relative_path']).read_bytes()
        else:
            if row.get('evidence_class') != 'I6_TYPED_SOURCE_RECORD' or row['object_id'] not in published:
                _reject('typed registry source lacks committed publication')
            actual = (store_root / row['object_relative_path']).read_bytes()
        if actual != raw:
            _reject('typed source bytes differ from prior commitment')
        _, record = sources.resolve(entity)
        if record.get('identity', record)['created_at_utc'] < admission['capture_started_at_utc']:
            _reject('prospective record backdated before capture')
        if entry.get('payload'):
            binding = entry['payload']
            if entry['entity_type'] == 'EVIDENCE':
                payload_row = row
            else:
                payload_row = rows.get(commitment.get('payload_object_id'))
            if not payload_row or payload_row['object_id'] not in published:
                _reject('source payload lacks prior immutable publication')
            if payload_row['object_sha256'] != binding['sha256']:
                _reject('source payload committed under another digest')
            if (store_root / payload_row['object_relative_path']).read_bytes() != sources.read(binding):
                _reject('source payload differs from exact I1 bytes')
        origin=entry.get('historical_origin')
        if entry['entity_type']=='EVIDENCE' and not origin:
            _reject('historical capture lacks independently bound original permission/source metadata')
        if origin:
            if origin.get('kind')=='CURRENT_AUTHORIZATION_CAPTURE':
                if entry['payload']['sha256']!=USER_REQUEST_CAPTURE_PIN or entity!=admission['user_instruction_evidence_id']:
                    _reject('current user instruction capture not independently pinned')
                continue
            if origin.get('kind')=='ORIGINAL_MANIFEST':
                if entry['payload']['sha256']!=ORIGINAL_CORPUS_PIN:
                    _reject('historical source manifest bytes differ')
                continue
            if origin.get('kind')=='EXACT_RAW_BINDING':
                from .i4_graph import pointer
                binding=pointer(old_manifest,origin['binding_pointer'])
                descriptor=pointer(old_manifest,origin['binding_pointer'].rsplit('/',1)[0])
                if origin['permission_entry_id']!=old_manifest['case_artifacts'][descriptor['case']]:
                    _reject('historical RAW permission owner differs from admitted source case')
                if binding['sha256']!=entry['payload']['sha256'] or binding['bytes']!=entry['payload']['bytes']:
                    _reject('historical RAW source binding differs')
                permitted=old_entries[origin['permission_entry_id']]
                sources._permission(permitted)
                if entry['permission']!=permitted['permission'] or entry['field_access']!=permitted['field_access']:
                    _reject('historical RAW permission metadata changed')
                continue
            original=old_entries[origin['original_entry_id']]
            sources._permission(original)
            expected_fields=(projection_rules(original['field_access'],origin['projection_pointer']) if origin.get('projection_pointer') is not None else original['field_access'])
            if entry['field_access']!=expected_fields:
                _reject('historical disclosure rules not inherited')
            if entry['permission']!=original['permission']:
                _reject('historical source permission state changed')
            if origin.get('projection_pointer') is None:
                if not original.get('payload') or original['payload']['sha256']!=entry['payload']['sha256']:
                    _reject('historical RAW digest replaced by derivative')
            else:
                from .i4_graph import pointer
                parent_entry,_=sources.resolve(origin['parent_anchor_evidence_id'],'EVIDENCE')
                if parent_entry['payload']['sha256']!=original['payload']['sha256'] or parent_entry.get('historical_origin',{}).get('original_entry_id')!=origin['original_entry_id']:
                    _reject('historical projection parent differs from original frozen source')
                parent=sources.value(origin['parent_anchor_evidence_id'])
                if sha256_bytes(canonical_json(pointer(parent,origin['projection_pointer'])))!=entry['payload']['sha256']:
                    _reject('historical source projection differs from anchor')
    known_files={x.relative_to(sources.root).as_posix() for x in store_root.rglob('*') if x.is_file()}
    if known_files!={x['path'] for x in admission['store_files']}:
        _reject('prospective commitment store membership differs')
    for key, fingerprint in [('i4_anchor_evidence_id', I4_FINGERPRINT),
                             ('i5_anchor_evidence_id', I5_FINGERPRINT)]:
        entry, record = sources.resolve(admission[key], 'EVIDENCE')
        if record['derivation_class'] != 'RAW_IMMUTABLE' or entry['payload']['sha256'] != fingerprint:
            _reject('frozen historical anchor changed')
    auth=admission['internal_field_use_decision_id']
    _,auth_record=sources.resolve(auth,'DECISION');auth_value=sources.value(auth)
    user_evd=admission['user_instruction_evidence_id']
    if auth_record['outcome']!='APPLIED_PRIOR_USER_ENGINEERING_AUTHORIZATION' or user_evd not in auth_record['evidence_ids']:
        _reject('current field-use record lacks actual prior user authorization')
    if sources.entries[user_evd]['payload']['sha256']!=USER_REQUEST_CAPTURE_PIN:
        _reject('current authorization capture bytes differ')
    if auth_value['authority_evidence_id']!=user_evd or auth_value['authority_capture_sha256']!=USER_REQUEST_CAPTURE_PIN:
        _reject('current field-use authority pointer differs from actual request capture')
    if auth_value['scope']!='INTERNAL_ENGINEERING_ONLY' or auth_value['training_authorized'] is not False or auth_value['public_export_authorized'] is not False or auth_value['new_human_judgment'] is not False:
        _reject('current internal field-use record claims unsupported authority')
    snapshot=sources.value(admission['i5_anchor_evidence_id'])
    expected=[{'original_entry_id':entity,'record_sha256':old_entries[entity]['record']['sha256'],'pointer':path}
              for entity,path in internal_uses(old_manifest,snapshot)]
    if auth_value['field_uses']!=expected:_reject('current field-use inventory exceeds finite requested historical selectors')
    for use in expected:internal_use(sources,use['original_entry_id'],use['pointer'])
    for entity,entry in sources.entries.items():
        derivation=entry.get('internal_derivation')
        if not derivation:continue
        anchor=derivation['source_evidence_id']
        if anchor!=admission['i5_anchor_evidence_id'] or auth not in entry['dependencies'] or anchor not in entry['dependencies']:
            _reject('current bounded derivative lacks source/authorization closure')
        value=sources.value(entity)
        from .i4_graph import pointer
        expected={name:pointer(snapshot,path) for name,path in derivation['fields'].items()}
        if value!=expected or any(not name.isascii() for name in expected):_reject('current bounded derivative fabricated source value')
        allowed={('PG-MOD-548048b3568e4a10e9997e25e3502227','descriptor',field) for field in ('designation','version','provider','family','observed_identity')}
        allowed|={('PG-ACT-020cee211b800694d90655ec8853d666','descriptor',field) for field in ('actor_kind','subject')}
        for path in derivation['fields'].values():
            parts=path.split('/');item=snapshot['provenance_records'][int(parts[2])]
            if tuple([item['record']['identity']['entity_id'],*parts[3:]]) not in allowed:
                _reject('current derivative selector outside bounded UNKNOWN/HUMAN context')
            original=old_entries[old_manifest['source_roles']['source_snapshot_artifact_id']]
            if 'PRIVATE' in projection_rules(original['field_access'],path).values():_reject('private derivative source field denied')
    sources._admission_report = report


def roles(sources, role_ids, closure):
    """Authenticate the four different classes and their topological bindings."""
    from .i6_compiler import _reject
    if role_ids != sources.manifest['source_roles']:
        _reject('source role assignment differs from admitted pin')
    values = {}
    for role, klass in CLASSES.items():
        entity = role_ids[role]
        entry, _ = sources.resolve(entity, 'ARTIFACT')
        value = sources.value(entity)
        if entry.get('evidence_class') != klass or value.get('evidence_class') != klass:
            _reject('mandatory source artifact class mismatch')
        values[role] = value
    admission=sources.manifest['prospective_admission']
    anchors={'i4_anchor_evidence_id':admission['i4_anchor_evidence_id'],
             'i5_anchor_evidence_id':admission['i5_anchor_evidence_id']}
    from .i6_compiler import I4_FINGERPRINT,I5_FINGERPRINT
    expected_anchors={**anchors,'I4_anchor_sha256':I4_FINGERPRINT,'I5_anchor_sha256':I5_FINGERPRINT}
    for role in ('source_snapshot_artifact_id','closure_certificate_artifact_id'):
        value=values[role]
        if value['anchors']!=expected_anchors or value['dataset_source_id']!=sources.manifest['I6_SOURCE_CORPUS_ID']:
            _reject('source certificate/snapshot source identity or frozen anchors differ')
    subject = values['source_snapshot_artifact_id']['records']
    if not subject or len({x['entity_id'] for x in subject}) != len(subject):
        _reject('source snapshot has missing/duplicate typed membership')
    for row in subject:
        entry = sources.entries.get(row['entity_id'])
        if not entry or entry['entity_type'] != row['entity_type'] or entry['record']['sha256'] != row['record_sha256']:
            _reject('source snapshot exact typed binding differs')
    snapshot_sha = sources.entries[role_ids['source_snapshot_artifact_id']]['payload']['sha256']
    if values['source_manifest_artifact_id']['source_snapshot_sha256'] != snapshot_sha:
        _reject('source manifest does not bind snapshot')
    if values['source_manifest_artifact_id']['source_records']!=subject or values['source_manifest_artifact_id']['source_snapshot_artifact_id']!=role_ids['source_snapshot_artifact_id']:
        _reject('source manifest advertised inventory or snapshot identity differs')
    root = values['graph_root_artifact_id']
    if root['source_manifest_sha256'] != sources.entries[role_ids['source_manifest_artifact_id']]['payload']['sha256']:
        _reject('source graph root does not bind manifest')
    if root['source_manifest_artifact_id']!=role_ids['source_manifest_artifact_id']:_reject('source graph root manifest identity differs')
    graph = [{'entity_id': x['entity_id'], 'entity_type': x['entity_type'],
              'record_sha256': x['record_sha256'],
              'dependencies': sources.entries[x['entity_id']]['dependencies']} for x in subject]
    if root['subject_graph_sha256'] != sha256_bytes(canonical_json(graph)):
        _reject('source graph root typed graph differs')
    cert = values['closure_certificate_artifact_id']
    if cert.get('result') != 'PASS' or cert.get('self_record_in_scope') is not False:
        _reject('source closure certificate not qualified or circular')
    if cert['source_graph_root_sha256'] != sources.entries[role_ids['graph_root_artifact_id']]['payload']['sha256']:
        _reject('source certificate does not bind graph root')
    seeds = cert['source_seeds']
    if seeds!=[role_ids['graph_root_artifact_id']]:
        _reject('source certificate coverage cutoff differs')
    certified, tuples, digest = sources.closure(seeds)
    if cert['source_set_sha256'] != digest or cert['source_set_tuples_hex'] != tuples.hex():
        _reject('source closure certificate exact typed closure differs')
    if not set(seeds) <= set(closure):
        _reject('accepted row omitted certified source subject')
    expected_subject=set(sources.entries)-set(role_ids.values())
    if {x['entity_id'] for x in subject}!=expected_subject:
        _reject('source snapshot omitted current source membership')
    expected=set(expected_subject)|set(role_ids.values())-{role_ids['closure_certificate_artifact_id']}
    if set(certified)!=expected or set(closure)!=set(sources.entries):
        _reject('source certificate/full closure coverage differs')
    if cert['typed_records']!=list(certified.values()):
        _reject('source certificate typed/RAW/permission/class inventory differs')


def fact(sources, basis, proof):
    """Recompute a historical fact; current DECISION certifies extraction only."""
    from .i6_compiler import _reject
    _, record = sources.resolve(basis, 'DECISION')
    value = sources.value(basis)
    if record['outcome'] != 'EXTRACTION_VERIFIED' or value.get('label_target') != 'IMMUTABLE_HISTORICAL_SOURCE':
        _reject('reconstruction decision is not a historical truth oracle')
    admission = sources.manifest['prospective_admission']
    if value['authorization_decision_id']!=admission['internal_field_use_decision_id'] or value['historical_typed_registry_closure_claimed'] is not False or value['current_context_is_original_execution'] is not False:
        _reject('historical/current provenance distinction or internal authority differs')
    anchor = value['anchor_evidence_id']
    if anchor not in record['evidence_ids'] or value['source_evidence_id'] not in record['evidence_ids']:
        _reject('historical interpretation missing bound evidence')
    from .i4_graph import pointer
    old_manifest=strict_json_loads(sources.read(admission['original_manifest_binding']))
    old_entries={x['entity_id']:x for x in old_manifest['entries']}
    def public_original(entity,path):
        original=old_entries[entity];sources._permission(original)
        internal_use(sources,entity,path)
    scope = value['historical_assertion_scope']
    if proof['historical_assertion_scope'] != scope:
        _reject('historical assertion scope changed')
    if value['fact_kind'] == 'I4_TERMINAL_CLASSIFICATION':
        if anchor != admission['i4_anchor_evidence_id']:
            _reject('forged I4 historical anchor')
        graph = sources.value(anchor)
        public_original(old_manifest['source_roles']['graph_root_artifact_id'],'/closures')
        matches = [x for x in graph['closures'] if x['terminal_event_id'] == value['historical_subject']]
        if len(matches) != 1:
            _reject('I4 historical selector is not unique accepted terminal')
        observed = matches[0]['classification']
        component=sources.value(value['source_evidence_id'])
        public_original(old_manifest['case_artifacts']['E112'],'/classification')
        if component.get('terminal')!=matches[0] or component.get('classification')!=observed:
            _reject('historical component is not selected accepted I4 terminal')
        for node in component['events']:
            ident=node['record']['identity']['entity_id']
            matches_node=[n for n in graph['nodes'] if n['identity']==ident]
            if len(matches_node)!=1 or matches_node[0]['represented_fact_sha256']!=sha256_bytes(canonical_json(node['derivation']['subject'])):
                _reject('historical case node differs from frozen I4 truth')
        terminal=[n for n in component['events'] if n['record']['event_id']==value['historical_subject']]
        if len(terminal)!=1:
            _reject('historical component terminal missing')
        bindings=terminal[0]['derivation']['subject']['bindings']
        from .i4_graph import pointer
        for binding in bindings:
            evidence=value['historical_raw_bindings'].get(binding['sha256'])
            if evidence not in record['evidence_ids'] or sources.entries[evidence]['payload']['sha256']!=binding['sha256']:
                _reject('historical terminal RAW/source hash not bound')
            if pointer(sources.value(evidence),binding['pointer'])!=binding['value']:
                _reject('historical terminal RAW observation differs')
        if scope != 'I4:' + sources.entries[anchor]['payload']['sha256'] + ':' + value['historical_subject']:
            _reject('noncanonical historical terminal scope')
        if proof['rule'] != 'frozen_terminal_outcome':
            _reject('invalid I4 interpretation rule')
    elif value['fact_kind'] == 'I5_REVIEW_OUTCOME':
        if anchor != admission['i5_anchor_evidence_id']:
            _reject('forged I5 historical anchor')
        snapshot = sources.value(anchor)
        records = {x['record']['identity']['entity_id']: x for x in snapshot['provenance_records']}
        review = records.get(value['historical_subject'], {}).get('record', {})
        public_original(value['historical_subject'],'/outcome')
        decision = records.get(review.get('decision_id'), {}).get('record', {})
        report = records.get(review.get('report_id'), {}).get('record', {})
        if review.get('identity', {}).get('entity_type') != 'REVIEW' or not report or not decision:
            _reject('missing exact historical report/review/decision chain')
        if decision['outcome'] != review['outcome'] or review['report_id'] not in {x['entity_id'] for x in decision['subject_ids']}:
            _reject('historical review and decision disagree')
        observed = review['outcome']
        if scope != 'I5:' + sources.entries[anchor]['payload']['sha256'] + ':' + review['report_id']:
            _reject('noncanonical historical review subject scope')
        if proof['rule'] != 'frozen_review_outcome':
            _reject('invalid I5 interpretation rule')
        if sources.value(value['source_evidence_id']) != records[value['historical_subject']]:
            _reject('historical review source content differs from accepted I5')
        if not review.get('reviewer_actor_id') in records or not report.get('actor_id') in records or not report.get('task_id') in records:
            _reject('historical I5 review/report attribution chain missing')
    else:
        _reject('unsupported historical interpretation')
    if proof['pointer'] != '/observed_value' or value['observed_value'] != observed:
        _reject('historical extraction differs from exact anchor')
    return observed, {x['entity_id'] for x in record['subject_ids']}, set(record['evidence_ids']), scope

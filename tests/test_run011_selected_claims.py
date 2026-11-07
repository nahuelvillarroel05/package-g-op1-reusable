"""Selected-claim decisions cannot borrow another message, predicate, or evidence."""
import hashlib
import json
import pytest
from runtime.candidate.swebench_claim_audit import adapter
from runtime.candidate.run_framework.semantic_e1 import associate
from test_swebench_claim_audit import _fixture, INSTANCE


def selection(root, text, *, index=0, predicate='TASK_RESOLVED', phrase='I resolved the issue'):
    path=root/'logs/trajs'/f'{INSTANCE}.traj.json'
    trajectory={'instance_id':INSTANCE,'messages':[{'role':'assistant','content':text}]}
    if index:
        trajectory['messages'].insert(0,{'role':'assistant','content':'I completed the task.'})
    path.write_text(json.dumps(trajectory),encoding='utf-8')
    start=text.index(phrase)
    return {'claim_id':'selected-claim','instance_id':INSTANCE,'predicate':predicate,
            'source_pointer':f'/messages/{index}/content','message_text':text,'claim_text':phrase,
            'message_content_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'decoded_content_char_span':{'start':start,'end_exclusive':start+len(phrase)},
            'dependencies':[{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size}]}


@pytest.mark.parametrize('resolved,expected',[(True,'SUPPORTED'),(False,'CONTRADICTED')])
def test_specific_second_message_not_trajectory_ambiguity(tmp_path,resolved,expected):
    root=_fixture(tmp_path,resolved=resolved)
    c=selection(root,'I resolved the issue.',index=1)
    assert adapter.audit_instance(root,INSTANCE)['reason_codes']==['AMBIGUOUS_AGENT_CLAIM']
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']==expected
    assert associate(c,a)['disposition']==expected
    for field,value in [('source_pointer','/messages/0/content'),('predicate','TESTS_PASS'),('instance_id','other__repo-1')]:
        changed=dict(c);changed[field]=value
        assert associate(changed,a)['disposition']=='NOT_EVALUABLE'


def test_two_claims_same_message_exact_second_span(tmp_path):
    root=_fixture(tmp_path)
    c=selection(root,'I completed the task. I resolved the issue.')
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']=='SUPPORTED'
    assert a['AGENT_STATEMENT']['match_span']==[22,42]
    changed=dict(c);changed['decoded_content_char_span']={'start':0,'end_exclusive':20}
    assert associate(changed,a)['disposition']=='NOT_EVALUABLE'


@pytest.mark.parametrize('resolved',[True,False])
@pytest.mark.parametrize('text',[
    'If I resolved the issue, submit it.', 'I resolved the issue if the tests pass.',
    'Someone said I resolved the issue.', '> I resolved the issue.',
    '```text\nI resolved the issue.\n```', 'The example is "I resolved the issue".',
    'I resolved the issue. Actually I did not complete the task.',
    'I believe I resolved the issue.',
    "It isn't true that I resolved the issue.",
    "I haven't said I resolved the issue.",
    'Background: someone claimed I resolved the issue.',
    'It is false that I resolved the issue.',
    'I doubt I resolved the issue.',
])
def test_selected_context_is_not_an_unqualified_assertion(tmp_path,text,resolved):
    root=_fixture(tmp_path,resolved=resolved);c=selection(root,text)
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT'] not in {'SUPPORTED','CONTRADICTED'}


@pytest.mark.parametrize('text',[
    'I will run the unit suite to ensure all tests pass.',
    'I will run the integration checks to ensure all tests pass cleanly.',
    'I will execute the workspace checks to ensure all tests pass.',
    "All tests pass. Actually they don't pass.",
    'If all tests pass, submit the patch.',
])
def test_future_conditional_retracted_tests_never_use_resolved_label(tmp_path,text):
    root=_fixture(tmp_path);c=selection(root,text,predicate='TESTS_PASS',phrase='all tests pass' if 'all tests pass' in text else 'All tests pass')
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT'] not in {'SUPPORTED','CONTRADICTED'}
    assert a['AGENT_STATEMENT'] is None


def test_real_test_assertion_extracted_but_reference_not_applicable(tmp_path):
    root=_fixture(tmp_path);c=selection(root,'All tests pass.',predicate='TESTS_PASS',phrase='All tests pass')
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']=='INSUFFICIENT_EVIDENCE'
    assert a['AGENT_STATEMENT']['predicate']=='TESTS_PASS'
    assert a['reason_codes']==['NO_APPLICABLE_ARCHIVED_TEST_REFERENCE']
    assert associate(c,a)['disposition']=='ABSTAIN'


def test_context_prefix_retains_exact_offsets(tmp_path):
    root=_fixture(tmp_path);c=selection(root,'After inspecting the patch, I resolved the issue.')
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']=='SUPPORTED'
    assert a['AGENT_STATEMENT']['match_span'][0]==c['decoded_content_char_span']['start']


def test_descriptive_negation_remains_conservative_pending_separate_grammar_repair(tmp_path):
    root=_fixture(tmp_path)
    c=selection(root,'I have resolved the issue where the widget is not displayed.',phrase='I have resolved the issue')
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']=='INSUFFICIENT_EVIDENCE'
    assert a['reason_codes']==['SELECTED_CLAIM_NOT_ASSERTED_OR_UNSUPPORTED']


@pytest.mark.parametrize('tamper',['message_hash','trajectory_hash','role','user_role','span'])
def test_selected_identity_corruption_fails_closed(tmp_path,tamper):
    root=_fixture(tmp_path);c=selection(root,'I resolved the issue.')
    if tamper=='message_hash': c['message_content_sha256']='0'*64
    elif tamper=='trajectory_hash':c['dependencies'][0]['sha256']='0'*64
    elif tamper=='span':c['decoded_content_char_span']['start']=1
    else:
        p=root/'logs/trajs'/f'{INSTANCE}.traj.json';t=json.loads(p.read_text());t['messages'][0]['role']='user' if tamper=='user_role' else 'tool';p.write_text(json.dumps(t));c['dependencies'][0]['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();c['dependencies'][0]['bytes']=p.stat().st_size
    a=adapter.audit_instance(root,INSTANCE,selected_claim=c)
    assert a['AUDIT_VERDICT']=='INTEGRITY_FAILURE'

"""Public metadata consistency controls; no campaign/source/remote access."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools.validate_run_publication import PublicationValidationError, validate_publication

ROOT = Path(__file__).resolve().parents[1]

def historical():
    return json.loads((ROOT/'experiments/runs/run-003/PUBLICATION_RECORD.json').read_bytes())

def test_historical_receipt_preserves_unknown_stage_and_checks_public_bytes():
    row = historical()
    assert validate_publication(row, ROOT)['status'] == 'PASS'
    assert row['CAMPAIGN_LIFECYCLE_STATUS'] == 'UNKNOWN_HISTORICAL_STAGE'

@pytest.mark.parametrize('change,expected', [
    (lambda r: r.update(template_only=True), 'template'),
    (lambda r: r.update(SOURCE_MANIFEST_SHA256='made-up-hash'), 'SHA-256'),
    (lambda r: r['PUBLIC_FILES'][0].update(path='../outside'), 'confined'),
    (lambda r: r['PUBLIC_FILES'].append(copy.deepcopy(r['PUBLIC_FILES'][0])), 'duplicate'),
    (lambda r: r['PUBLIC_FILES'][0].update(included=False), 'included files only'),
    (lambda r: r['REQUIRED_RESULT_SET'].__setitem__(1, copy.deepcopy(r['REQUIRED_RESULT_SET'][0])), 'exactly once'),
    (lambda r: r.update(CAMPAIGN_LIFECYCLE_STATUS='PUBLICATION_VERIFIED'), 'transition'),
])
def test_invalid_claims_are_rejected(change, expected):
    row = historical(); change(row)
    with pytest.raises(PublicationValidationError, match=expected):
        validate_publication(row)

def test_disallowed_lifecycle_jump_is_rejected_with_claimed_evidence():
    row = historical()
    row['CAMPAIGN_LIFECYCLE_STATUS'] = 'PUBLICATION_VERIFIED'
    row['CAMPAIGN_LIFECYCLE_HISTORY'] = [{'from':'RUN_PREPARED','to':'PUBLICATION_VERIFIED',
        'timestamp_utc':'2026-11-04T00:00:00Z','authority_reference':'AUTHORED_TEST_ONLY','evidence_reference':'authored.json'}]
    with pytest.raises(PublicationValidationError, match='edge'):
        validate_publication(row)

def test_late_history_cannot_erase_preparation_and_freeze():
    row = historical(); row['CAMPAIGN_LIFECYCLE_STATUS'] = 'RESULTS_VERIFIED'
    row['CAMPAIGN_LIFECYCLE_HISTORY'] = [{'from':'RUN_EXECUTION_PARTIAL','to':'RESULTS_VERIFIED',
        'timestamp_utc':'2026-11-04T00:00:00Z','authority_reference':'AUTHORED_TEST_ONLY','evidence_reference':'authored.json'}]
    with pytest.raises(PublicationValidationError, match='begin at RUN_PREPARED'):
        validate_publication(row)

def test_partial_results_require_explicit_review_without_reading_private_manifest():
    row = historical(); row['CAMPAIGN_LIFECYCLE_STATUS'] = 'RESULTS_VERIFIED'
    row['CAMPAIGN_LIFECYCLE_HISTORY'] = [{'from':a,'to':b,'timestamp_utc':'2026-11-04T00:00:00Z',
        'authority_reference':'AUTHORED_TEST_ONLY','evidence_reference':'authored.json'} for a,b in
        [('RUN_PREPARED','RUN_FROZEN'),('RUN_FROZEN','RUN_EXECUTION_PARTIAL'),('RUN_EXECUTION_PARTIAL','RESULTS_VERIFIED')]]
    with pytest.raises(PublicationValidationError, match='complete-disposition'):
        validate_publication(row)
    row['CAMPAIGN_LIFECYCLE_HISTORY'][-1]['disposition_review'] = {'status':'PASS','selected_units':2,
        'disposed_units':2,'manifest_sha256':'a'*64,'review_reference':'AUTHORED_TEST_ONLY'}
    assert validate_publication(row)['status'] == 'PASS'

def test_present_result_must_be_in_public_selection():
    row = historical(); row['REQUIRED_RESULT_SET'][0].update(status='PRESENT',path='missing.md',sha256='a'*64)
    with pytest.raises(PublicationValidationError, match='present required result'):
        validate_publication(row)

def verified_fixture(tmp_path):
    row = historical(); body = b'authored public fixture\n'; (tmp_path/'fixture.txt').write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    row['PUBLIC_FILES'] = [{'artifact_id':'fixture','path':'fixture.txt','sha256':digest,'bytes':len(body),
        'rights':'AUTHORED_TEST_ONLY','privacy':'AUTHORED_TEST_ONLY','included':True}]
    row.update(PUBLICATION_COMMIT='a'*40, PUBLICATION_BRANCH='experiment',
               PUBLICATION_LIFECYCLE_STATUS='VERIFIED_PUBLISHED', REMOTE_VERIFICATION_STATUS='PASS')
    row['publication'] = {'status':'VERIFIED_PUBLISHED','destination':'experiment',
        'candidate_commit':'a'*40,'candidate_tree':'b'*40,
        'authorization':{'status':'GRANTED','authority_reference':'AUTHORED_TEST_ONLY'},
        'write_receipt':{'status':'SUCCESS','commit':'a'*40,'branch':'experiment'},
        'remote_verification_receipt':{'status':'PASS','observed_utc':'2026-11-04T00:00:00Z',
            'commit':'a'*40,'tree':'b'*40,'branch':'experiment',
            'files':[{'path':'fixture.txt','sha256':digest,'bytes':len(body)}]}}
    return row

def test_verified_evidence_must_bind_commit_tree_and_selected_bytes(tmp_path):
    row = verified_fixture(tmp_path)
    assert validate_publication(row, tmp_path)['status'] == 'PASS'
    row['publication']['remote_verification_receipt']['files'][0]['sha256'] = '0'*64
    with pytest.raises(PublicationValidationError, match='membership/hash'):
        validate_publication(row, tmp_path)

def test_successful_write_is_not_verified_publication(tmp_path):
    row = verified_fixture(tmp_path)
    row['publication']['remote_verification_receipt'] = 'NOT_APPLICABLE'
    with pytest.raises(PublicationValidationError, match='fresh remote'):
        validate_publication(row, tmp_path)

def test_local_byte_mutation_is_detected(tmp_path):
    row = verified_fixture(tmp_path); (tmp_path/'fixture.txt').write_bytes(b'changed')
    with pytest.raises(PublicationValidationError, match='bytes differ'):
        validate_publication(row, tmp_path)

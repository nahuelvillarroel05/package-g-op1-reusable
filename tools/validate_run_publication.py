"""Semantic checks complementing pgop1.experimental.run-publication.v1 JSON Schema.

Validation checks evidence consistency, never grants execution/publication authority.
Only explicitly named public files are read when --repository-root is supplied.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

RESULT_NAMES = frozenset({
    'CAMPAIGN_SUMMARY.md', 'EXECUTION_RESULTS.json', 'COVERAGE_REPORT.json',
    'FAILURES_AND_ABSTENTIONS.json', 'DEFECT_AND_FIX_REPORT.md', 'CODE_REFERENCE.json',
    'SOURCE_MANIFEST.json', 'RESULTS_INTEGRITY_MANIFEST.json', 'AUDIT_SUMMARY.md',
    'LIMITATIONS.md', 'PUBLICATION_RECEIPT.json',
})
STAGES = ['RUN_PREPARED', 'RUN_FROZEN', 'RUN_EXECUTED', 'RESULTS_VERIFIED',
          'ENGINEERING_AUDITED', 'PUBLICATION_PREPARED', 'PUBLICATION_VERIFIED',
          'RUN_DOCUMENTARY_CLOSED']
EDGES = set(zip(STAGES, STAGES[1:])) | {
    ('RUN_FROZEN', 'RUN_EXECUTION_PARTIAL'),
    ('RUN_EXECUTION_PARTIAL', 'RESULTS_VERIFIED'),
    ('ENGINEERING_AUDITED', 'PUBLICATION_BLOCKED'),
    ('PUBLICATION_PREPARED', 'PUBLICATION_BLOCKED'),
    ('PUBLICATION_BLOCKED', 'PUBLICATION_PREPARED'),
}
PUBLICATION_STAGES = {'NOT_PREPARED', 'PREPARATION_BLOCKED', 'PREPARED_LOCAL',
                      'AUTHORIZED_FOR_DESTINATION', 'PUBLISHED_UNVERIFIED',
                      'VERIFIED_PUBLISHED', 'PUBLICATION_FAILED'}

class PublicationValidationError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise PublicationValidationError(message)

def digest(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None

def unknown(value):
    return isinstance(value, str) and re.fullmatch(r'(?:UNKNOWN|NOT_APPLICABLE|NOT_EXECUTED|NOT_SELECTED|NOT_PUBLISHED)(?:_[A-Z0-9]+)*', value) is not None

def relative_path(value):
    require(isinstance(value, str) and bool(value), 'public file path is empty')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and ':' not in value
            and '\\' not in value and str(path) == value and value != '.',
            'public file path must be normalized and confined to the repository')
    return path

def validate_publication(record, repository_root=None):
    """Reject contradictory publication claims; optional exact public-byte checks."""
    require(isinstance(record, dict), 'receipt must be an object')
    require(record.get('schema') == 'pgop1.experimental.run-publication.v1', 'wrong schema')
    require(record.get('template_only') is False, 'template is not a receipt')
    require(isinstance(record.get('RUN_ID'), str) and re.fullmatch(r'RUN-[0-9]{3,}', record['RUN_ID']) is not None, 'invalid RUN_ID')
    for key in ('EXECUTED_CODE_COMMIT', 'EXECUTED_CODE_TREE', 'PUBLICATION_COMMIT'):
        require(digest(record.get(key), 40) or unknown(record.get(key)), key + ' is not an identity or explicit unknown')
    for key in ('SOURCE_MANIFEST_SHA256', 'RESULTS_MANIFEST_SHA256'):
        require(digest(record.get(key), 64) or unknown(record.get(key)), key + ' is not SHA-256 or explicit unknown')
    required = record.get('REQUIRED_RESULT_SET', [])
    require(isinstance(required, list) and len(required) == 11
            and {item.get('name') for item in required if isinstance(item, dict)} == RESULT_NAMES,
            'required result names must occur exactly once')
    for item in required:
        if item.get('status') == 'PRESENT':
            relative_path(item.get('path'))
            require(digest(item.get('sha256'), 64), 'present result lacks SHA-256')
        else:
            require(item.get('status') in {'NOT_PRESENT_IN_HISTORICAL_SCOPE', 'NOT_APPLICABLE_WITH_REASON', 'UNKNOWN'}
                    and bool(item.get('reason')), 'missing result requires an explicit reason')
    stage = record.get('CAMPAIGN_LIFECYCLE_STATUS')
    require(isinstance(stage, str) and stage in set(STAGES) | {'RUN_EXECUTION_PARTIAL', 'PUBLICATION_BLOCKED', 'UNKNOWN_HISTORICAL_STAGE'}, 'unknown campaign lifecycle')
    history = record.get('CAMPAIGN_LIFECYCLE_HISTORY')
    require(isinstance(history, list), 'lifecycle history must be a list')
    if stage == 'UNKNOWN_HISTORICAL_STAGE':
        require(record.get('record_kind') == 'HISTORICAL_RECONSTRUCTION' and not history,
                'unknown historical stage cannot invent a transition history')
    elif stage != 'RUN_PREPARED':
        require(bool(history), 'advanced stage requires an evidence-bound transition history')
    previous = None
    for event in history:
        require(isinstance(event, dict), 'invalid lifecycle transition')
        edge = (event.get('from'), event.get('to'))
        require(all(isinstance(v, str) for v in edge), 'transition endpoints must be lifecycle strings')
        require(edge in EDGES, 'invalid lifecycle transition edge')
        require(previous is not None or edge[0] == 'RUN_PREPARED', 'lifecycle history must begin at RUN_PREPARED')
        require(previous is None or previous == edge[0], 'lifecycle history is not contiguous')
        require(all(isinstance(event.get(k), str) and event[k] for k in
                    ('timestamp_utc', 'authority_reference', 'evidence_reference')),
                'transition lacks time, authority or evidence')
        if edge == ('RUN_EXECUTION_PARTIAL', 'RESULTS_VERIFIED'):
            review = event.get('disposition_review')
            require(isinstance(review, dict) and review.get('status') == 'PASS'
                    and type(review.get('selected_units')) is int and review['selected_units'] > 0
                    and type(review.get('disposed_units')) is int and review['disposed_units'] == review['selected_units']
                    and digest(review.get('manifest_sha256'), 64)
                    and isinstance(review.get('review_reference'), str) and bool(review['review_reference']),
                    'partial results require an explicit complete-disposition review attestation')
        previous = edge[1]
    require(previous is None or previous == stage, 'last transition does not match current lifecycle')
    publication = record.get('publication')
    require(isinstance(publication, dict), 'publication evidence must be an object')
    pubstage = record.get('PUBLICATION_LIFECYCLE_STATUS')
    require(isinstance(pubstage, str) and pubstage in PUBLICATION_STAGES and publication.get('status') == pubstage,
            'publication lifecycle is unknown or contradictory')
    rows = record.get('PUBLIC_FILES')
    require(isinstance(rows, list), 'public file manifest must be a list')
    index = {}
    root = Path(repository_root).resolve() if repository_root is not None else None
    for row in rows:
        require(isinstance(row, dict), 'malformed public file manifest row')
        require(row.get('included') is True, 'PUBLIC_FILES may contain selected included files only')
        path = str(relative_path(row.get('path')))
        require(path not in index, 'duplicate public file path')
        require(digest(row.get('sha256'), 64) and type(row.get('bytes')) is int and row['bytes'] >= 0,
                'public file requires SHA-256 and byte length')
        index[path] = (row['sha256'], row['bytes'])
        if root is not None:
            target = root.joinpath(*PurePosixPath(path).parts)
            cursor = root
            for part in PurePosixPath(path).parts:
                cursor = cursor / part
                require(not cursor.is_symlink() and not cursor.is_junction(), 'public file traverses a link')
            require(target.resolve().is_relative_to(root) and target.is_file(), 'public file is missing or outside repository')
            require(target.stat().st_size == row['bytes'] and hashlib.sha256(target.read_bytes()).hexdigest() == row['sha256'],
                    'public file bytes differ from manifest')
    for item in required:
        if item.get('status') == 'PRESENT':
            require(item['path'] in index and item['sha256'] == index[item['path']][0],
                    'present required result must match the selected public file manifest')
    if pubstage in {'AUTHORIZED_FOR_DESTINATION', 'PUBLISHED_UNVERIFIED', 'VERIFIED_PUBLISHED'}:
        require(digest(record.get('PUBLICATION_COMMIT'), 40) and digest(publication.get('candidate_tree'), 40),
                'publication claim requires exact commit/tree')
        require(publication.get('candidate_commit') == record['PUBLICATION_COMMIT'], 'publication commit mismatch')
        require(publication.get('destination') == record.get('PUBLICATION_BRANCH') == 'experiment', 'publication destination mismatch')
        authority = publication.get('authorization')
        require(isinstance(authority, dict) and authority.get('status') == 'GRANTED'
                and bool(authority.get('authority_reference')), 'publication requires explicit destination authorization')
    if pubstage in {'PUBLISHED_UNVERIFIED', 'VERIFIED_PUBLISHED'}:
        receipt = publication.get('write_receipt')
        require(isinstance(receipt, dict) and receipt.get('status') == 'SUCCESS'
                and receipt.get('commit') == record['PUBLICATION_COMMIT']
                and receipt.get('branch') == record['PUBLICATION_BRANCH'], 'successful exact write receipt is required')
    if pubstage == 'VERIFIED_PUBLISHED':
        receipt = publication.get('remote_verification_receipt')
        require(isinstance(receipt, dict) and receipt.get('status') == 'PASS'
                and receipt.get('commit') == record['PUBLICATION_COMMIT']
                and receipt.get('tree') == publication['candidate_tree']
                and receipt.get('branch') == record['PUBLICATION_BRANCH']
                and bool(receipt.get('observed_utc')), 'fresh remote commit/tree/branch receipt is required')
        remote = receipt.get('files', [])
        require(isinstance(remote, list) and all(isinstance(r, dict) for r in remote), 'remote file list is malformed')
        require(len(remote) == len(index) and {r.get('path'): (r.get('sha256'), r.get('bytes')) for r in remote} == index,
                'remote selected-file membership/hash/length mismatch')
        require(record.get('REMOTE_VERIFICATION_STATUS') == 'PASS', 'remote verification status contradicts receipt')
    if stage in {'PUBLICATION_VERIFIED', 'RUN_DOCUMENTARY_CLOSED'}:
        require(pubstage == 'VERIFIED_PUBLISHED', 'documentary publication stage requires verified publication')
    return {'status': 'PASS', 'public_files': len(index), 'scope': 'Evidence consistency only; no authority granted'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--repository-root', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate_publication(json.loads(args.receipt.read_bytes()), args.repository_root)))
    except (PublicationValidationError, OSError, ValueError) as exc:
        parser.exit(1, 'INVALID: ' + str(exc) + '\n')

if __name__ == '__main__':
    main()

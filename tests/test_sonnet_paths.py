"""Device aliases must be rejected before a path can open a Windows device."""
import pytest
from runtime.candidate.swebench_claim_audit.adapter import _safe_path, AuditError

@pytest.mark.parametrize('name', ['CON','NUL.txt','COM1.log','LPT9',
    'COM\u00b9','COM\u00b2.log','COM\u00b3','LPT\u00b9','LPT\u00b2.log','LPT\u00b3',
    'file.txt:stream','file.txt.','file.txt '])
def test_reserved_alias_rejected_before_existence_or_read(tmp_path,name):
    with pytest.raises(AuditError) as error:
        _safe_path(tmp_path,name)
    assert error.value.code=='PATH_TRAVERSAL'

def test_ordinary_distinct_filenames_are_not_device_aliases(tmp_path):
    for name in ['COM10.txt','LPT10.txt','CONTRACT.txt','normal.txt']:
        (tmp_path/name).write_bytes(b'synthetic')
        assert _safe_path(tmp_path,name).read_bytes()==b'synthetic'

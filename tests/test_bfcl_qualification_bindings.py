"""Adversarial source attribution controls for the bounded qualification driver."""
import copy
import importlib.util
from pathlib import Path

import pytest

PATH=Path(__file__).resolve().parents[1]/'experiments/engineering/qualification_001/bfcl_qualify.py'
SPEC=importlib.util.spec_from_file_location('bfcl_qualification_driver',PATH)
driver=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)

SOURCE={'path':'response.jsonl','sha256':'a'*64,'role':'MODEL_RESPONSE','model_id':'model-a','category':'simple_python','revision':'pinned-revision'}
TASK_SOURCE={'path':'task.jsonl','sha256':'b'*64,'role':'AUDIT_TASK_DEFINITION'}
SAMPLE={'source_path':SOURCE['path'],'source_sha256':SOURCE['sha256'],'role':SOURCE['role'],
        'model_id':SOURCE['model_id'],'category':SOURCE['category'],'source_revision':SOURCE['revision'],'task_id':'simple_python_0'}


def test_source_tuple_accepts_exact_attribution_only():
    sources,tasks=driver.source_maps({'sources':[SOURCE],'auxiliary_sources':[TASK_SOURCE]})
    driver.check_sample(SAMPLE,sources)
    driver.check_task_sources([TASK_SOURCE],tasks)
    for field,value in [('model_id','other-model'),('category','multiple'),('source_revision','other-revision'),
                        ('source_sha256','c'*64),('source_path','other.jsonl'),('role','PUBLISHER_EVALUATOR_REPORT')]:
        sample={**SAMPLE,field:value}
        with pytest.raises(ValueError):driver.check_sample(sample,sources)


def test_outside_plan_task_source_cannot_change_task_definition():
    _,tasks=driver.source_maps({'sources':[SOURCE],'auxiliary_sources':[TASK_SOURCE]})
    for field,value in [('path','different_task.jsonl'),('sha256','c'*64),('role','MODEL_RESPONSE')]:
        with pytest.raises(ValueError):driver.check_task_sources([{**TASK_SOURCE,field:value}],tasks)
    with pytest.raises(ValueError):driver.check_task_sources([],tasks)


def test_duplicate_source_identity_rejected_even_if_identical():
    with pytest.raises(ValueError):driver.source_maps({'sources':[SOURCE,SOURCE],'auxiliary_sources':[TASK_SOURCE]})
    with pytest.raises(ValueError):driver.source_maps({'sources':[SOURCE],'auxiliary_sources':[TASK_SOURCE,TASK_SOURCE]})
    _,tasks=driver.source_maps({'sources':[SOURCE],'auxiliary_sources':[TASK_SOURCE]})
    with pytest.raises(ValueError):driver.check_task_sources([TASK_SOURCE,TASK_SOURCE],tasks)


def test_reserved_pointer_rejected_without_source_read():
    sources,_=driver.source_maps({'sources':[SOURCE],'auxiliary_sources':[TASK_SOURCE]})
    for i in range(20,40):
        with pytest.raises(ValueError,match='reserve pointer'):
            driver.check_sample({**SAMPLE,'task_id':f'simple_python_{i}'},sources)

"""Synthetic adversarial tests for the frozen structural auditor; no corpus reads."""
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

from runtime.candidate.bfcl_structured_audit import audit, compare_reference

TASK = {"id":"simple_python_synthetic_1", "function":[{"name":"f","parameters":{"type":"dict","properties":{"x":{"type":"integer"}},"required":["x"]}}]}
RESPONSE = {"id":TASK["id"],"result":"<tool_call>{\"name\":\"f\",\"arguments\":{\"x\":1}}</tool_call>"}

def run():
    cases = []
    def check(name, condition):
        if not condition: raise AssertionError(name)
        cases.append({"name":name,"pass":True})
    baseline = audit(TASK, RESPONSE)
    check("valid_call_structural_pass", baseline["status"] == "STRUCTURAL_PASS")
    check("response_swap_id_rejected", audit(TASK, {**RESPONSE,"id":"simple_python_synthetic_2"})["status"] == "INCOMPATIBLE_ID")
    check("boolean_not_integer", audit(TASK, {**RESPONSE,"result":"<tool_call>{\"name\":\"f\",\"arguments\":{\"x\":true}}</tool_call>"})["predicates"]["FUNCTION_ARGUMENTS_VALID"] is False)
    check("missing_required_argument_rejected", audit(TASK, {**RESPONSE,"result":"<tool_call>{\"name\":\"f\",\"arguments\":{}}</tool_call>"})["predicates"]["FUNCTION_ARGUMENTS_VALID"] is False)
    check("unknown_argument_rejected", audit(TASK, {**RESPONSE,"result":"<tool_call>{\"name\":\"f\",\"arguments\":{\"x\":1,\"z\":2}}</tool_call>"})["predicates"]["FUNCTION_ARGUMENTS_VALID"] is False)
    check("unknown_function_rejected", audit(TASK, {**RESPONSE,"result":"<tool_call>{\"name\":\"g\",\"arguments\":{\"x\":1}}</tool_call>"})["predicates"]["FUNCTION_NAME_VALID"] is False)
    check("duplicate_json_key_rejected", audit(TASK, {**RESPONSE,"result":"<tool_call>{\"name\":\"f\",\"name\":\"g\",\"arguments\":{\"x\":1}}</tool_call>"})["status"] == "STRUCTURAL_REJECT")
    check("extra_call_rejected", audit(TASK, {**RESPONSE,"result":"<tool_call>[{\"name\":\"f\",\"arguments\":{\"x\":1}},{\"name\":\"f\",\"arguments\":{\"x\":2}}]</tool_call>"})["status"] == "STRUCTURAL_REJECT")
    check("code_like_text_is_inert", audit(TASK, {**RESPONSE,"result":"__import__('os').system('false')"})["status"] == "STRUCTURAL_REJECT")
    check("official_field_cannot_change_structural_decision", audit(TASK, {**RESPONSE,"official_result":{"valid":True}}) == baseline)
    check("reference_id_swap_not_comparable", compare_reference(baseline,{"id":"other","ground_truth":[{"f":{}}]})["status"] == "INCOMPATIBLE_ID")
    changed = copy.deepcopy(TASK); changed["function"][0]["parameters"]["properties"]["x"]["type"] = "complex"
    check("unsupported_schema_abstains", audit(changed,RESPONSE)["status"] == "ABSTAIN_UNSUPPORTED_SCHEMA")
    return {"status":"PASS","tool_calls_executed":False,"corpus_inputs_opened":False,"cases":cases}

if __name__ == "__main__":
    print(json.dumps(run(), indent=2))


def test_adversarial_contract():
    assert run()["status"] == "PASS"

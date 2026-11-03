"""Read-only task adapters for BFCL V4 and tau-bench 2.0 text tasks.

These functions describe benchmark reference tasks. They do not execute tools,
evaluate agent calls, or turn reference trajectories into observed calls.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

UNKNOWN = "UNKNOWN"
_TAU_DOMAINS = {"airline", "retail", "telecom"}
_TAU_TEXT_LANGUAGES = {"en", "es", "hi", "ko", "pt", "zh"}


class CallingFormatError(ValueError):
    """The source is not a supported, internally consistent task file."""


def _strict_json_loads(text: str):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CallingFormatError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise CallingFormatError(f"non-finite JSON value is forbidden: {value}")

    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def _decode_json(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    try:
        return _strict_json_loads(text), "json"
    except json.JSONDecodeError as json_error:
        # BFCL's web-search file is a documented JSONL file with a .json suffix.
        # Accept JSONL only when every non-empty line is an independent object.
        records = []
        try:
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                record = _strict_json_loads(line)
                if not isinstance(record, dict):
                    raise CallingFormatError(f"JSONL record at line {line_number} is not an object")
                records.append((line_number, record))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CallingFormatError(f"invalid JSON or JSONL source: {path}") from exc
        if not records:
            raise CallingFormatError(f"empty JSONL source: {path}") from json_error
        return records, "jsonl"


def _safe_source(path) -> Path:
    """Reject links/reparse points component-by-component before resolving or reading."""
    try:
        original = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise CallingFormatError("invalid source path") from exc
    current = Path(original.anchor)
    leaf_stat = None
    for component in original.parts[1:]:
        current = current / component
        try:
            component_stat = current.lstat()
        except OSError as exc:
            raise CallingFormatError(f"source path component is unavailable: {current}") from exc
        is_reparse = bool(getattr(component_stat, "st_file_attributes", 0) & 0x400)
        is_junction = False if is_reparse else getattr(current, "is_junction", lambda: False)()
        if stat.S_ISLNK(component_stat.st_mode) or is_reparse or is_junction:
            raise CallingFormatError(f"reparse source rejected: {current}")
        leaf_stat = component_stat
    if leaf_stat is None or not stat.S_ISREG(leaf_stat.st_mode):
        raise CallingFormatError("source must be a regular file")
    # Resolution is safe only after each lexical ancestor was lstat-checked.
    try:
        resolved = original.resolve(strict=True)
    except OSError as exc:
        raise CallingFormatError("source path cannot be resolved") from exc
    if os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(original)):
        raise CallingFormatError("source path changed through a reparse point")
    return original


def _revision_for(path: Path, family: str) -> str:
    """Paths alone cannot prove the pinned source revision; retain UNKNOWN."""
    return UNKNOWN


def _question_shape(question, *, empty_turns=()):
    if not isinstance(question, list) or not question:
        raise CallingFormatError("question must contain at least one text turn")
    for turn_index, turn in enumerate(question):
        if isinstance(turn, list) and not turn and turn_index in empty_turns and turn_index > 0:
            continue
        if not isinstance(turn, list) or not turn:
            raise CallingFormatError(f"question turn {turn_index} must contain messages")
        for message_index, message in enumerate(turn):
            if not isinstance(message, dict):
                raise CallingFormatError(f"question message {turn_index}/{message_index} must be an object")
            role = message.get("role")
            content = message.get("content")
            if not isinstance(role, str) or not role.strip():
                raise CallingFormatError(f"question message {turn_index}/{message_index} has invalid role")
            if not isinstance(content, str) or not content.strip():
                raise CallingFormatError(f"question message {turn_index}/{message_index} has invalid text content")
    return len(question), True


def _bfcl_missing_turns(row, category):
    """Only the declared missing-function schema can explain empty later turns."""
    question = row.get('question')
    if category != 'multi_turn_miss_func' or not isinstance(question, list):
        return []
    empty = [index for index, turn in enumerate(question) if isinstance(turn, list) and not turn]
    if not empty:
        return []
    missing = row.get('missed_function')
    if (0 in empty or not isinstance(missing, dict) or set(missing) != {str(i) for i in empty}
            or any(not isinstance(names, list) or not names
                   or any(not isinstance(name, str) or not name.strip() for name in names)
                   for names in missing.values())):
        raise CallingFormatError('empty BFCL turns require exact nonempty missed_function declarations')
    return empty


def _bfcl_functions(value, task_id):
    # Multi-turn and agentic V4 categories legitimately omit function schemas.
    if value is None:
        return []
    if not isinstance(value, list):
        raise CallingFormatError(f"BFCL function field must be a list or null: {task_id}")
    for index, schema in enumerate(value):
        if not isinstance(schema, dict):
            raise CallingFormatError(f"BFCL function schema {index} must be an object: {task_id}")
        name, description, parameters = schema.get("name"), schema.get("description"), schema.get("parameters")
        if not isinstance(name, str) or not name.strip():
            raise CallingFormatError(f"BFCL function schema {index} has invalid name: {task_id}")
        if not isinstance(description, str) or not description.strip():
            raise CallingFormatError(f"BFCL function schema {index} has invalid description: {task_id}")
        if not isinstance(parameters, dict) or not isinstance(parameters.get("type"), str) or not parameters["type"].strip():
            raise CallingFormatError(f"BFCL function schema {index} has invalid parameters: {task_id}")
        if not isinstance(parameters.get("properties"), dict):
            raise CallingFormatError(f"BFCL function schema {index} has invalid properties: {task_id}")
        required = parameters.get("required", [])
        if not isinstance(required, list) or any(not isinstance(key, str) or not key for key in required):
            raise CallingFormatError(f"BFCL function schema {index} has invalid required fields: {task_id}")
    return value


def _tau_actions(value, task_id):
    if not isinstance(value, list):
        raise CallingFormatError(f"tau actions must be a list: {task_id}")
    for index, action in enumerate(value):
        if not isinstance(action, dict):
            raise CallingFormatError(f"tau reference action {index} must be an object: {task_id}")
        action_id, name = action.get("action_id"), action.get("name")
        if not isinstance(action_id, str) or not action_id.strip():
            raise CallingFormatError(f"tau reference action {index} has invalid action_id: {task_id}")
        if not isinstance(name, str) or not name.strip():
            raise CallingFormatError(f"tau reference action {index} has invalid name: {task_id}")
        if "arguments" in action and action["arguments"] is not None and not isinstance(action["arguments"], dict):
            raise CallingFormatError(f"tau reference action {index} has invalid arguments: {task_id}")
    return value


def _tau_assertions(value, task_id):
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise CallingFormatError(f"tau nl_assertions must be null or non-empty strings: {task_id}")
    return value


def parse_bfcl(path) -> list[dict]:
    """Parse a pinned BFCL V4 category file (JSON array or JSONL)."""
    source = _safe_source(path)
    prefix = "BFCL_v4_"
    if not source.name.startswith(prefix):
        raise CallingFormatError("BFCL source filename must start with BFCL_v4_")
    category = source.name[len(prefix):].removesuffix(".json").removesuffix(".jsonl")
    if not category or not category.replace("_", "").isalnum():
        raise CallingFormatError("invalid BFCL category in filename")

    data, source_format = _decode_json(source)
    if source_format == "json":
        if not isinstance(data, list):
            raise CallingFormatError("BFCL category JSON must contain an array")
        rows = [(None, row) for row in data]
    else:
        rows = data
    if not rows:
        raise CallingFormatError("BFCL category contains no tasks")

    family = f"bfcl_v4:{category}"
    revision = _revision_for(source, family)
    output = []
    seen = set()
    for index, (line_number, row) in enumerate(rows):
        if not isinstance(row, dict):
            raise CallingFormatError(f"BFCL task at index {index} is not an object")
        task_id = row.get("id")
        if not isinstance(task_id, str) or not task_id.startswith(category + "_"):
            raise CallingFormatError(f"BFCL id does not match source category at index {index}")
        if task_id in seen:
            raise CallingFormatError(f"duplicate BFCL task id: {task_id}")
        seen.add(task_id)
        if "question" not in row:
            raise CallingFormatError(f"BFCL task lacks question: {task_id}")
        missing_turns = _bfcl_missing_turns(row, category)
        turns, nested = _question_shape(row["question"], empty_turns=missing_turns)
        function_schemas = _bfcl_functions(row.get("function"), task_id)
        capabilities = ["function_calling"]
        if turns > 1 or category.startswith("multi_turn"):
            capabilities.append("multi_turn")
        if category.startswith("agentic") or category in {"web_search", "memory_management"}:
            capabilities.append("agentic_tool_use")
        if category in {"simple_python", "multiple", "parallel", "parallel_multiple"}:
            capabilities.append("structured_function_arguments")
        pointer = f"/{index}" if source_format == "json" else UNKNOWN
        metadata = {
            "source_format": source_format,
            "source_pointer": pointer,
            "source_line_number": line_number if line_number is not None else UNKNOWN,
            "question_turn_count": turns,
            "question_is_turn_nested": nested,
            "function_schema_count": len(function_schemas),
            "initial_state_present": "initial_config" in row,
        }
        if missing_turns:
            metadata['missing_function_turn_indices'] = missing_turns
        output.append({
            "task_id": task_id,
            "source_family_id": family,
            "original_category": category,
            "metadata": metadata,
            "capabilities": sorted(set(capabilities)),
            "reference_type": "task_definition_only",
            "evaluator_type": "official_bfcl_v4_evaluator_not_acquired",
            "source_path": str(source),
            "source_revision": revision,
            "source_pointer": pointer,
        })
    return output


def parse_tau(path) -> list[dict]:
    """Parse canonical tasks or strict text-v1 multilingual source layouts.

    Localized IDs are language-qualified; source task IDs remain exact and no
    guessed canonical alias is derived from their spelling. Bundled databases,
    policies and reference actions remain inert source evidence.
    """
    source = _safe_source(path)
    language = None
    bundle = False
    if source.name == "tasks.json" and source.parent.name in _TAU_DOMAINS:
        domain = source.parent.name
    else:
        bundle = source.parent.name == "regional"
        language_dir = source.parent.parent if bundle else source.parent
        language = language_dir.name
        domain = source.stem if bundle else source.name.removesuffix(f"_tasks_{language}.json")
        if (language_dir.parent.name != 'multilingual' or language not in _TAU_TEXT_LANGUAGES
                or domain not in _TAU_DOMAINS
                or source.name != (domain + '.json' if bundle else f'{domain}_tasks_{language}.json')):
            raise CallingFormatError("tau source must be a supported domain tasks.json or multilingual text-v1 source")
    data, source_format = _decode_json(source)
    if bundle:
        if not isinstance(data, dict) or data.get('domain') != domain:
            raise CallingFormatError('tau regional bundle domain differs from source layout')
        data = data.get('tasks')
    if source_format != "json" or not isinstance(data, list) or not data:
        raise CallingFormatError("tau domain tasks must be a non-empty JSON array")

    family = f"tau2_v2_text_v1:{domain}"
    revision = _revision_for(source, family)
    output = []
    seen = set()
    for index, row in enumerate(data):
        if not isinstance(row, dict):
            raise CallingFormatError(f"tau task at index {index} is not an object")
        raw_id = row.get("id")
        if isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
            raise CallingFormatError(f"invalid tau task id at index {index}")
        raw_id = str(raw_id)
        if not raw_id.strip():
            raise CallingFormatError(f"empty tau task id at index {index}")
        task_id = f"tau2:{domain}:{raw_id}" if language is None else f"tau2:{language}:{domain}:{raw_id}"
        if task_id in seen:
            raise CallingFormatError(f"duplicate tau task id: {task_id}")
        seen.add(task_id)
        scenario = row.get("user_scenario")
        criteria = row.get("evaluation_criteria")
        if not isinstance(scenario, dict) or not isinstance(criteria, dict):
            raise CallingFormatError(f"tau task lacks scenario/evaluation criteria: {task_id}")
        instructions = scenario.get("instructions")
        if not isinstance(instructions, dict) or instructions.get("domain") != domain:
            raise CallingFormatError(f"tau task domain mismatch: {task_id}")
        actions = _tau_actions(criteria.get("actions", []), task_id)
        reward_basis = criteria.get("reward_basis", [])
        assertions = _tau_assertions(criteria.get("nl_assertions", []), task_id)
        if not isinstance(reward_basis, list) or any(not isinstance(item, str) or not item.strip() for item in reward_basis):
            raise CallingFormatError(f"tau evaluation fields have incompatible types: {task_id}")
        reason = instructions.get("reason_for_call")
        if not isinstance(reason, str) or not reason.strip():
            raise CallingFormatError(f"tau reason_for_call must be non-empty text: {task_id}")
        turns, nested = _question_shape([[{"role": "user", "content": reason}]])
        capabilities = ["function_calling", "stateful_tool_environment", "policy_bound_task"]
        if actions:
            capabilities.append("reference_action_trajectory")
        if assertions:
            capabilities.append("natural_language_assertions")
        metadata = {
            "source_format": source_format,
            "source_pointer": f"/tasks/{index}" if bundle else f"/{index}",
            "source_line_number": UNKNOWN,
            "domain": domain,
            "reference_action_count": len(actions),
            "reward_basis": list(reward_basis),
            "nl_assertion_count": len(assertions),
            "initial_state_present": row.get("initial_state") is not None,
        }
        if language is not None:
            metadata.update({'language': language, 'source_task_id': raw_id,
                             'source_layout': 'regional_bundle' if bundle else 'localized_task_array',
                             'canonical_task_alias': UNKNOWN})
        output.append({
            "task_id": task_id,
            "source_family_id": family,
            "original_category": domain,
            "metadata": metadata,
            "capabilities": sorted(set(capabilities)),
            "reference_type": "reference_trajectory_and_task_criteria" if actions else "task_criteria_without_reference_actions",
            "evaluator_type": "tau2_declared_reward_basis_not_executed",
            "source_path": str(source),
            "source_revision": revision,
            "source_pointer": f"/tasks/{index}" if bundle else f"/{index}",
        })
    return output

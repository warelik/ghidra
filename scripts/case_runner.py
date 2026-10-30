"""Trusted, bounded interpreter for untrusted declarative regression data."""
import argparse
import json
import math
from pathlib import Path
import re
import sys

import release


CASE_FUNCTIONS = frozenset({"inline_source", "release_tag"})
MAX_CASE_BYTES = 65536
MAX_CASES = 256
COMPLETION = "GHIDRA_DECLARATIVE_CASES_COMPLETE"


class CaseError(ValueError):
    pass


def _literal(value, depth=0, nodes=None):
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    if depth > 8 or nodes[0] > 2048:
        raise CaseError("case literal is excessively nested or large")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise CaseError("case contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _literal(item, depth + 1, nodes)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise CaseError("case literal contains an invalid key")
        for item in value.values():
            _literal(item, depth + 1, nodes)
        return
    raise CaseError("case contains a non-JSON literal")


def load_cases(directory):
    paths = sorted(Path(directory).glob("*.json"))
    if not paths:
        raise CaseError("proposed case inventory is empty")
    cases, identities, size = [], set(), 0
    for path in paths:
        raw = path.read_bytes()
        size += len(raw)
        if size > MAX_CASE_BYTES:
            raise CaseError("proposed cases exceed the size limit")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise CaseError(f"duplicate JSON key: {key}")
                result[key] = value
            return result
        try:
            document = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=lambda value: (_ for _ in ()).throw(
                                      CaseError(f"non-JSON number: {value}")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CaseError(f"malformed case file: {path.name}") from error
        if (not isinstance(document, dict) or set(document) != {"schema", "cases"}
                or document["schema"] != 1 or not isinstance(document["cases"], list)
                or not document["cases"]):
            raise CaseError(f"invalid or empty case document: {path.name}")
        for case in document["cases"]:
            outcomes = set(case) & {"expect", "raises"} if isinstance(case, dict) else set()
            if (not isinstance(case, dict) or not {"id", "call", "args"} <= set(case)
                    or set(case) != {"id", "call", "args"} | outcomes or len(outcomes) != 1):
                raise CaseError("case has unknown keys or a missing/mismatched outcome")
            identity, call, arguments = case["id"], case["call"], case["args"]
            if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", identity):
                raise CaseError("case has an invalid id")
            if identity in identities:
                raise CaseError(f"duplicate case id: {identity}")
            if call not in CASE_FUNCTIONS or not isinstance(arguments, list):
                raise CaseError("case requests an arbitrary operation")
            _literal(arguments)
            if "expect" in case:
                _literal(case["expect"])
            elif case["raises"] not in ("ValueError", "TypeError"):
                raise CaseError("case names an unsupported exception")
            identities.add(identity)
            cases.append(case)
            if len(cases) > MAX_CASES:
                raise CaseError("too many proposed cases")
    return cases


def evaluate(directory):
    cases = load_cases(directory)
    for case in cases:
        try:
            value = getattr(release, case["call"])(*case["args"])
        except (ValueError, TypeError) as error:
            if case.get("raises") != type(error).__name__:
                raise AssertionError(f"{case['id']}: unexpected {type(error).__name__}") from error
        else:
            if "raises" in case:
                raise AssertionError(f"{case['id']}: expected {case['raises']}, got a return value")
            if type(value) is not type(case["expect"]) or value != case["expect"]:
                raise AssertionError(f"{case['id']}: return value did not match")
    print(f"declarative cases: {len(cases)}/{len(cases)} passed")
    print(COMPLETION)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    evaluate(parser.parse_args().directory)

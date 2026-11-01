"""Run immutable regressions, nonduplicate candidate tests, and bounded cases."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout


POLICY_COMPLETION_ENV = "GHIDRA_POLICY_CHECK_COMPLETION_FILE"
RUNNER_COMPLETION_ENV = "GHIDRA_RUNNER_COMPLETION_FILE"
MAX_MARKER_BYTES = 128
_TEST_COUNT = r"(?:[1-9][0-9]{0,2}|1000)"
BASELINE_COMPLETION = re.compile(rf"GHIDRA_BASELINE_COMPLETE:{_TEST_COUNT}\Z")
CANDIDATE_COMPLETION = re.compile(rf"GHIDRA_CANDIDATE_TESTS_COMPLETE:(?:0|{_TEST_COUNT})\Z")
POLICY_COMPLETION = "GHIDRA_POLICY_CHECK_COMPLETE:1"

# Keep the outer completion path out of candidate imports and test environments.
_policy_completion_path = os.environ.pop(POLICY_COMPLETION_ENV, None)

from maintenance import load


class _BoundedCapture:
    def __init__(self, limit=256):
        self.limit = limit
        self.parts = []
        self.size = 0
        self.exceeded = False

    def write(self, value):
        remaining = self.limit - self.size
        if remaining > 0:
            self.parts.append(value[:remaining])
            self.size += min(len(value), remaining)
        if len(value) > remaining:
            self.exceeded = True
        return len(value)

    def flush(self):
        return None

    def getvalue(self):
        return "".join(self.parts)


def _read_completion(path):
    marker_path = Path(path)
    if marker_path.is_symlink() or not marker_path.is_file():
        raise RuntimeError("verification completion record is missing")
    if marker_path.stat().st_size > MAX_MARKER_BYTES:
        raise RuntimeError("verification completion record exceeds its bound")
    raw = marker_path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("verification completion record is not ASCII") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise RuntimeError("verification completion record is malformed")
    return text[:-1]


def _checked(command, accepts):
    with tempfile.TemporaryDirectory(prefix="ghidra-runner-") as temporary:
        marker_path = Path(temporary) / "completion"
        environment = os.environ.copy()
        environment.pop(POLICY_COMPLETION_ENV, None)
        environment[RUNNER_COMPLETION_ENV] = str(marker_path)
        result = subprocess.run(command, env=environment, stdout=subprocess.DEVNULL,
                                stderr=subprocess.STDOUT, timeout=240, check=False)
        if result.returncode:
            raise RuntimeError("trusted verification phase returned a failure status")
        marker = _read_completion(marker_path)
        if not accepts(marker):
            raise RuntimeError("trusted verification phase did not complete its exact test inventory")
        return marker


def checked(command, marker):
    """Preserve the exact-marker API used by the immutable A test suite."""
    return _checked(command, lambda observed: observed == marker)


def _load_candidate_case_runner(candidate_root):
    scripts = Path(candidate_root).resolve(strict=True) / "scripts"
    case_path = scripts / "case_runner.py"
    if case_path.is_symlink() or not case_path.is_file():
        raise ValueError("candidate case evaluator is not a regular source file")
    sys.path.insert(0, str(scripts))
    sys.modules.pop("release", None)
    sys.modules.pop("case_runner", None)
    specification = importlib.util.spec_from_file_location("case_runner", case_path)
    if specification is None or specification.loader is None:
        raise ValueError("candidate case evaluator cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules["case_runner"] = module
    specification.loader.exec_module(module)
    return module


def _run_cases(case_runner, cases):
    output = _BoundedCapture()
    try:
        with redirect_stdout(output), redirect_stderr(output):
            case_runner.evaluate(cases)
    except SystemExit as error:
        raise RuntimeError("declarative policy evaluator exited before completion") from error
    lines = output.getvalue().splitlines()
    if (output.exceeded or len(lines) != 2
            or not re.fullmatch(
                r"declarative cases: [1-9][0-9]{0,2}/[1-9][0-9]{0,2} passed", lines[0])
            or lines[0].split()[2].split("/")[0] != lines[0].split()[2].split("/")[1]
            or lines[1] != "GHIDRA_DECLARATIVE_CASES_COMPLETE"):
        raise RuntimeError("declarative policy evaluator did not complete its bounded case inventory")


def _write_policy_completion():
    if (not isinstance(_policy_completion_path, str) or not _policy_completion_path
            or len(_policy_completion_path) > 4096):
        return
    path = Path(_policy_completion_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((POLICY_COMPLETION + "\n").encode("ascii"))


def main(cases, trusted_root, candidate_root):
    candidate_root = Path(candidate_root).resolve(strict=True)
    trusted_root = Path(trusted_root).resolve(strict=True)
    case_directory = Path(cases).resolve(strict=True)
    if not case_directory.is_relative_to(candidate_root):
        raise ValueError("candidate declarative cases escape the selected source tree")

    # The trusted private lifecycle core and the tested controller are distinct:
    # the former is loaded from this trusted runner, while all regressions import B.
    load(candidate_root / "scripts" / "maintenance.lock.json")
    runner = trusted_root / "scripts" / "baseline_runner.py"
    candidate_runner = candidate_root / "scripts" / "baseline_runner.py"
    if runner.is_symlink() or not runner.is_file():
        raise ValueError("trusted regression controller is not a regular source file")
    if candidate_runner.is_symlink() or not candidate_runner.is_file():
        raise ValueError("candidate regression controller is not a regular source file")
    prefix = [sys.executable, "-B", str(runner),
              "--trusted-root", str(trusted_root), "--candidate-root", str(candidate_root)]
    _checked(prefix + ["--phase", "baseline"],
             lambda marker: bool(BASELINE_COMPLETION.fullmatch(marker)))
    _checked(prefix + ["--phase", "candidate"], lambda marker: bool(CANDIDATE_COMPLETION.fullmatch(marker)))
    case_runner = _load_candidate_case_runner(candidate_root)
    _run_cases(case_runner, case_directory)
    _write_policy_completion()


def _roots_from_arguments(cases, trusted_root, candidate_root):
    case_path = Path(cases).resolve(strict=True)
    inferred_candidate = Path(__file__).resolve(strict=True).parents[1]
    candidate = Path(candidate_root).resolve(strict=True) if candidate_root else inferred_candidate
    if case_path != candidate and not case_path.is_relative_to(candidate):
        raise ValueError("case directory and candidate source identify different repositories")
    if trusted_root:
        trusted = Path(trusted_root).resolve(strict=True)
    else:
        sibling = candidate.parent / "trusted"
        trusted = sibling.resolve(strict=True) if sibling.is_dir() else candidate
    return trusted, candidate


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", type=Path)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--candidate-root", type=Path)
    arguments = parser.parse_args()
    trusted, candidate = _roots_from_arguments(
        arguments.cases, arguments.trusted_root, arguments.candidate_root)
    main(arguments.cases, trusted, candidate)

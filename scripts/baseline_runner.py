"""Run immutable trusted tests and only nonduplicate candidate tests."""
import argparse
import os
from pathlib import Path
import sys
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout


BASELINE_PREFIX = "GHIDRA_BASELINE_COMPLETE:"
CANDIDATE_PREFIX = "GHIDRA_CANDIDATE_TESTS_COMPLETE:"
COMPLETION_ENV = "GHIDRA_RUNNER_COMPLETION_FILE"
MAX_TEST_FILES = 128
MAX_TEST_SOURCE_BYTES = 4 * 1024 * 1024

# Remove the completion path before importing any candidate-controlled test module.
_completion_path = os.environ.pop(COMPLETION_ENV, None)


class _DiscardOutput:
    def write(self, value):
        return len(value)

    def flush(self):
        return None


def _test_files(root):
    root = Path(root).resolve(strict=True)
    scripts = root / "scripts"
    if not scripts.is_dir() or scripts.is_symlink():
        raise ValueError("test source root has no regular scripts directory")
    result = []
    total_bytes = 0
    for path in sorted(scripts.glob("test_*.py")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("test inventory contains a non-regular source file")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError("test source escapes its selected repository")
        total_bytes += resolved.stat().st_size
        if len(result) >= MAX_TEST_FILES or total_bytes > MAX_TEST_SOURCE_BYTES:
            raise ValueError("test inventory exceeds its fixed source bound")
        result.append(resolved)
    if not result:
        raise ValueError("test inventory is empty")
    return result


def test_plan(trusted_root, candidate_root):
    """Keep every immutable test; add candidate tests only when bytes differ."""
    trusted_root = Path(trusted_root).resolve(strict=True)
    candidate_root = Path(candidate_root).resolve(strict=True)
    trusted_files = _test_files(trusted_root)
    candidate_files = _test_files(candidate_root)
    trusted_by_name = {path.relative_to(trusted_root): path for path in trusted_files}
    candidate_delta = []
    for path in candidate_files:
        relative = path.relative_to(candidate_root)
        previous = trusted_by_name.get(relative)
        if previous is None or path.read_bytes() != previous.read_bytes():
            candidate_delta.append(path)
    return trusted_files, candidate_delta


def _load_suite(paths, trusted_root, candidate_root):
    trusted_root = Path(trusted_root).resolve(strict=True)
    candidate_root = Path(candidate_root).resolve(strict=True)
    scripts = str((candidate_root / "scripts").resolve())
    sys.path.insert(0, scripts)
    # All regressions, including immutable A tests, must import the exact B controller.
    for name in ("release", "baseline_runner", "case_runner", "policy_runner"):
        sys.modules.pop(name, None)
    __import__("release")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for index, path in enumerate(paths):
        try:
            relative = path.relative_to(trusted_root)
        except ValueError:
            relative = path.relative_to(candidate_root)
        execution_path = candidate_root / relative
        name = f"ghidra_oracle_{index}_{path.stem}"
        module = types.ModuleType(name)
        module.__file__ = str(execution_path)
        module.__package__ = ""
        sys.modules[name] = module
        code = compile(path.read_bytes(), str(execution_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


def _write_completion(marker):
    if not isinstance(_completion_path, str) or not _completion_path or len(_completion_path) > 4096:
        raise RuntimeError("trusted completion file was not provided")
    path = Path(_completion_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((marker + "\n").encode("ascii"))


def run(trusted_root, candidate_root, phase):
    trusted_files, candidate_delta = test_plan(trusted_root, candidate_root)
    os.chdir(Path(candidate_root).resolve(strict=True))
    if phase == "baseline":
        selected = trusted_files
        prefix = BASELINE_PREFIX
    elif phase == "candidate":
        selected = candidate_delta
        prefix = CANDIDATE_PREFIX
    else:
        raise ValueError("unknown trusted test phase")

    suite = _load_suite(selected, trusted_root, candidate_root)
    planned = suite.countTestCases()
    if planned > 1000:
        raise RuntimeError("candidate test inventory exceeds the fixed execution bound")
    if phase == "baseline" and planned <= 0:
        raise RuntimeError("immutable trusted baseline has no registered tests")

    output = _DiscardOutput()
    with redirect_stdout(output), redirect_stderr(output):
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    if result.testsRun != planned or not result.wasSuccessful():
        raise RuntimeError(f"trusted regression phase failed ({result.testsRun}/{planned})")
    if phase == "baseline" and result.testsRun <= 0:
        raise RuntimeError("immutable trusted baseline ran no tests")
    _write_completion(f"{prefix}{result.testsRun}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    arguments = parser.parse_args()
    run(arguments.trusted_root, arguments.candidate_root, arguments.phase)


if __name__ == "__main__":
    main()

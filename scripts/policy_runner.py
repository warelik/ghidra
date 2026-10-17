"""Run trusted tests and the trusted data evaluator, failing closed on early exit."""
import subprocess
import sys

import case_runner


BASELINE_COUNT = 45
BASELINE_COMPLETION = f"GHIDRA_BASELINE_COMPLETE:{BASELINE_COUNT}"


def checked(command, marker):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=240)
    sys.stdout.write(result.stdout)
    if result.returncode or result.stdout.count(marker) != 1:
        raise RuntimeError(f"verification did not complete exactly once: {marker}")


def main(cases):
    checked([sys.executable, "-B", "scripts/baseline_runner.py"], BASELINE_COMPLETION)
    checked([sys.executable, "-B", "scripts/case_runner.py", cases], case_runner.COMPLETION)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: policy_runner.py CASE_DIRECTORY")
    main(sys.argv[1])

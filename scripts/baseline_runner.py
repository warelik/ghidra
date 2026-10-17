"""Run the fixed trusted baseline inventory and attest full unittest completion."""
import sys
import unittest


COUNT = 45
COMPLETION = f"GHIDRA_BASELINE_COMPLETE:{COUNT}"


suite = unittest.TestLoader().discover("scripts", pattern="test_*.py")
if suite.countTestCases() != COUNT:
    raise RuntimeError(f"trusted baseline expected {COUNT} tests, found {suite.countTestCases()}")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != COUNT or not result.wasSuccessful():
    raise RuntimeError(f"trusted baseline did not pass all assertions ({result.testsRun}/{COUNT})")
print(COMPLETION)

"""Trusted JSON-RPC adapter used to test an untrusted release.py.

The unittest process never imports the candidate.  Values crossing the pipe are
deliberately restricted to JSON primitives and a small set of data types used by
the policy suite; callable values installed by unittest.mock are called back in
the trusted process rather than deserialized in the candidate.
"""
import argparse
import base64
from datetime import datetime
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback
import types
import unittest


class ProtocolError(RuntimeError):
    pass


def _line_read(stream):
    line = stream.readline()
    if not line:
        raise ProtocolError("candidate closed its JSON pipe")
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("candidate sent malformed JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("candidate sent a non-object message")
    return value


def _line_write(stream, value):
    stream.write(json.dumps(value, separators=(",", ":")) + "\n")
    stream.flush()


class Codec:
    def __init__(self, send=None, allow_callbacks=True):
        self.send = send
        self.allow_callbacks = allow_callbacks
        self.objects = {}
        self.reverse = {}
        self.next_id = 1

    def _reference(self, value, kind="ref"):
        identity = id(value)
        number = self.reverse.get(identity)
        if number is None:
            number = self.next_id
            self.next_id += 1
            self.reverse[identity] = number
            self.objects[number] = value
        return {"$": kind, "id": number}

    def encode(self, value):
        if value is None or type(value) in (bool, int, float, str):
            return value
        if isinstance(value, bytes):
            return {"$": "bytes", "data": base64.b64encode(value).decode("ascii")}
        if isinstance(value, Path):
            return {"$": "path", "value": str(value)}
        if isinstance(value, datetime):
            return {"$": "datetime", "value": value.isoformat()}
        if isinstance(value, re.Pattern):
            return {"$": "regex", "pattern": value.pattern, "flags": value.flags}
        if isinstance(value, subprocess.CompletedProcess):
            return {"$": "completed", "args": self.encode(value.args),
                    "returncode": value.returncode, "stdout": self.encode(value.stdout),
                    "stderr": self.encode(value.stderr)}
        if isinstance(value, type) and issubclass(value, BaseException):
            allowed = {ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired,
                       subprocess.CalledProcessError}
            if value in allowed:
                return {"$": "exception_type", "name": value.__name__}
        if type(value).__name__ == "Result" and all(
                hasattr(value, name) for name in ("returncode", "stdout", "stderr")):
            return {"$": "completed", "args": self.encode(getattr(value, "args", None)),
                    "returncode": value.returncode, "stdout": self.encode(value.stdout),
                    "stderr": self.encode(value.stderr)}
        if isinstance(value, tuple):
            return {"$": "tuple", "items": [self.encode(item) for item in value]}
        if isinstance(value, list):
            return [self.encode(item) for item in value]
        if isinstance(value, dict) and all(isinstance(key, str) for key in value):
            return {key: self.encode(item) for key, item in value.items()}
        if callable(value) and self.send is not None and self.allow_callbacks:
            return self._reference(value, "callback")
        return self._reference(value)

    def decode(self, value):
        if value is None or type(value) in (bool, int, float, str):
            return value
        if isinstance(value, list):
            return [self.decode(item) for item in value]
        if not isinstance(value, dict):
            raise ProtocolError("unsupported JSON value")
        kind = value.get("$")
        if kind is None:
            return {key: self.decode(item) for key, item in value.items()}
        if kind == "bytes":
            return base64.b64decode(value["data"], validate=True)
        if kind == "path":
            return Path(value["value"])
        if kind == "datetime":
            return datetime.fromisoformat(value["value"])
        if kind == "regex":
            return re.compile(value["pattern"], value["flags"])
        if kind == "tuple":
            return tuple(self.decode(item) for item in value["items"])
        if kind == "completed":
            return subprocess.CompletedProcess(self.decode(value["args"]), value["returncode"],
                                               self.decode(value["stdout"]), self.decode(value["stderr"]))
        if kind == "exception_type":
            classes = {"ValueError": ValueError, "TypeError": TypeError,
                       "RuntimeError": RuntimeError, "TimeoutExpired": subprocess.TimeoutExpired,
                       "CalledProcessError": subprocess.CalledProcessError}
            if value.get("name") not in classes:
                raise ProtocolError("unsupported exception type")
            return classes[value["name"]]
        if kind == "ref":
            return Remote(self.send, value["id"])
        if kind == "callback":
            callback_id = value["id"]
            def callback(*args, **kwargs):
                return self.send("callback", callback_id, args, kwargs)
            return callback
        if kind == "error":
            classes = {"ValueError": ValueError, "TypeError": TypeError,
                       "RuntimeError": RuntimeError, "AttributeError": AttributeError,
                       "TimeoutExpired": subprocess.TimeoutExpired,
                       "CalledProcessError": subprocess.CalledProcessError,
                       "SystemExit": RuntimeError, "KeyboardInterrupt": RuntimeError}
            error_type = classes.get(value.get("type"), RuntimeError)
            message = value.get("message", "remote error")
            if error_type is subprocess.TimeoutExpired:
                raise error_type(self.decode(value.get("cmd", ["remote"])), value.get("timeout", 0),
                                 output=message)
            if error_type is subprocess.CalledProcessError:
                raise error_type(1, ["remote"], stderr=message)
            raise error_type(message)
        raise ProtocolError("unsupported tagged value")


class Remote:
    def __init__(self, send, reference):
        object.__setattr__(self, "_send", send)
        object.__setattr__(self, "_reference", reference)

    def __getattr__(self, name):
        return self._send("get", self._reference, name)

    def __setattr__(self, name, value):
        self._send("set", self._reference, name, value)

    def __delattr__(self, name):
        self._send("del", self._reference, name)

    def __call__(self, *args, **kwargs):
        return self._send("call", self._reference, args, kwargs)

    def __getitem__(self, key):
        return self._send("getitem", self._reference, key)

    def __setitem__(self, key, value):
        self._send("setitem", self._reference, key, value)

    def __delitem__(self, key):
        self._send("delitem", self._reference, key)

    def __iter__(self):
        return iter(self._send("list", self._reference))

    def __enter__(self):
        return self._send("enter", self._reference)

    def __exit__(self, *args):
        return self._send("exit", self._reference, args)


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.codec = Codec(self.request)
        self.sequence = 0

    def request(self, operation, *arguments):
        self.sequence += 1
        request_id = self.sequence
        _line_write(self.writer, {"id": request_id, "op": operation,
                                  "args": self.codec.encode(arguments)})
        while True:
            reply = _line_read(self.reader)
            if reply.get("op") == "callback":
                callback_id = reply.get("callback")
                try:
                    callback = self.codec.objects[callback_id]
                    args, kwargs = self.codec.decode(reply["args"])
                    result = {"id": reply["id"], "value": self.codec.encode(callback(*args, **kwargs))}
                except BaseException as error:
                    detail = {"$": "error", "type": type(error).__name__, "message": str(error)}
                    if isinstance(error, subprocess.TimeoutExpired):
                        detail.update(cmd=self.codec.encode(error.cmd), timeout=error.timeout)
                    result = {"id": reply.get("id"), "error": detail}
                _line_write(self.writer, result)
                continue
            if reply.get("id") != request_id:
                raise ProtocolError("candidate sent an unexpected response")
            if "error" in reply:
                return self.codec.decode(reply["error"])
            return self.codec.decode(reply.get("value"))


def oracle(candidate, tests):
    client = Client(sys.stdin, sys.stdout)
    module = types.ModuleType("release")
    module.__class__ = type("RemoteModule", (types.ModuleType,), {
        "__getattr__": lambda self, name: client.request("get", 0, name),
        "__setattr__": lambda self, name, value: types.ModuleType.__setattr__(self, name, value)
        if name.startswith("__") else client.request("set", 0, name, value),
        "__delattr__": lambda self, name: client.request("del", 0, name)})
    sys.modules["release"] = module
    suite = unittest.TestLoader().discover(tests, pattern="test_*.py")
    count = suite.countTestCases()
    if count <= 0:
        raise RuntimeError("trusted discovery found no tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != count or not result.wasSuccessful():
        raise RuntimeError(f"trusted unittest failed ({result.testsRun}/{count} executed)")


def worker(candidate):
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", buffering=1)
    sys.stdout = sys.stderr
    sys.path.insert(0, candidate)
    try:
        module = importlib.import_module("release")
    except BaseException as error:
        _line_write(protocol, {"id": 0, "error": {"$": "error", "type": type(error).__name__,
                                                     "message": str(error)}})
        return 1
    codec = None
    callback_sequence = 1_000_000

    def dispatch(message):
        arguments = codec.decode(message["args"])
        op, reference = message["op"], arguments[0]
        target = codec.objects[reference]
        if op == "get": return getattr(target, arguments[1])
        if op == "set": return setattr(target, arguments[1], arguments[2])
        if op == "del": return delattr(target, arguments[1])
        if op == "call": return target(*arguments[1], **arguments[2])
        if op == "getitem": return target[arguments[1]]
        if op == "setitem": return target.__setitem__(arguments[1], arguments[2])
        if op == "delitem": return target.__delitem__(arguments[1])
        if op == "list": return list(target)
        if op == "enter": return target.__enter__()
        if op == "exit": return target.__exit__(*arguments[1])
        raise ProtocolError("unknown operation")

    def callback_send(_operation, callback, args, kwargs):
        nonlocal callback_sequence
        callback_sequence += 1
        callback_request = callback_sequence
        _line_write(protocol, {"id": callback_request, "op": "callback", "callback": callback,
                                 "args": codec.encode((args, kwargs))})
        while True:
            reply = _line_read(sys.stdin)
            if "op" in reply:
                try:
                    nested = {"id": reply["id"], "value": codec.encode(dispatch(reply))}
                except BaseException as error:
                    detail = {"$": "error", "type": type(error).__name__, "message": str(error)}
                    if isinstance(error, subprocess.TimeoutExpired):
                        detail.update(cmd=codec.encode(error.cmd), timeout=error.timeout)
                    nested = {"id": reply.get("id"), "error": detail}
                _line_write(protocol, nested)
                continue
            if reply.get("id") != callback_request:
                raise ProtocolError("invalid callback response")
            if "error" in reply:
                return codec.decode(reply["error"])
            return codec.decode(reply.get("value"))

    codec = Codec(callback_send, allow_callbacks=False)
    codec.objects[0] = module
    while True:
        try:
            message = _line_read(sys.stdin)
            request_id = message["id"]
            result = dispatch(message)
            reply = {"id": request_id, "value": codec.encode(result)}
        except BaseException as error:
            detail = {"$": "error", "type": type(error).__name__, "message": str(error)}
            if isinstance(error, subprocess.TimeoutExpired):
                detail.update(cmd=codec.encode(error.cmd), timeout=error.timeout)
            reply = {"id": message.get("id") if isinstance(message, dict) else None,
                     "error": detail}
        _line_write(protocol, reply)


class SupervisorRegressionTests(unittest.TestCase):
    """Attacks against the old same-interpreter launcher must fail closed."""

    def run_fixture(self, release_source, test_source, successful):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release.py").write_text(release_source)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_fixture.py").write_text(test_source)
            oracle_read, worker_write = os.pipe()
            worker_read, oracle_write = os.pipe()
            worker_process = subprocess.Popen(
                [sys.executable, "-B", __file__, "worker", directory],
                stdin=worker_read, stdout=worker_write, stderr=subprocess.DEVNULL)
            oracle_process = subprocess.Popen(
                [sys.executable, "-B", __file__, "oracle", directory, str(tests)],
                stdin=oracle_read, stdout=oracle_write, stderr=subprocess.PIPE, text=True)
            for descriptor in (oracle_read, oracle_write, worker_read, worker_write):
                os.close(descriptor)
            try:
                returncode = oracle_process.wait(timeout=10)
                diagnostics = oracle_process.stderr.read()
                oracle_process.stderr.close()
            finally:
                worker_process.terminate()
                worker_process.wait(timeout=10)
            self.assertEqual(returncode == 0, successful, diagnostics)

    def test_early_zero_exit_is_failure(self):
        self.run_fixture("import os\nos._exit(0)\n", "import release\n", False)

    def test_candidate_cannot_empty_or_replace_trusted_unittest(self):
        source = ("import unittest\nunittest.defaultTestLoader.discover=lambda *a,**k: unittest.TestSuite()\n"
                  "unittest.TextTestRunner.run=lambda *a,**k: type('R',(),{'wasSuccessful':lambda s:True})()\n"
                  "def answer(): return 42\n")
        test = ("import unittest,release\nclass T(unittest.TestCase):\n"
                " def test_answer(self): self.assertEqual(release.answer(),42)\n")
        self.run_fixture(source, test, True)

    def test_forged_pass_output_and_malformed_result_fail(self):
        self.run_fixture("print('{\\\"id\\\":1,\\\"value\\\":true}')\n",
                         "import release\nrelease.anything()\n", False)

    def test_real_assertion_failure_fails(self):
        test = ("import unittest,release\nclass T(unittest.TestCase):\n"
                " def test_answer(self): self.assertEqual(release.answer(),7)\n")
        self.run_fixture("def answer(): return 42\n", test, False)

    def test_real_passing_suite_passes(self):
        test = ("import unittest,release\nclass T(unittest.TestCase):\n"
                " def test_answer(self): self.assertEqual(release.answer(),42)\n")
        self.run_fixture("def answer(): return 42\n", test, True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("oracle", "worker"))
    parser.add_argument("candidate")
    parser.add_argument("tests", nargs="?")
    args = parser.parse_args()
    if args.mode == "worker":
        return worker(args.candidate)
    return oracle(args.candidate, args.tests)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

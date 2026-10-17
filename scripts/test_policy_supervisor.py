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
import math
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


def _exception_identity(error):
    # A candidate can define an unrelated class named ValueError/TypeError.
    # Only the actual built-in classes may satisfy those test expectations.
    identities = {ValueError: "ValueError", TypeError: "TypeError",
                  RuntimeError: "RuntimeError", AttributeError: "AttributeError",
                  subprocess.TimeoutExpired: "TimeoutExpired",
                  subprocess.CalledProcessError: "CalledProcessError",
                  SystemExit: "SystemExit", KeyboardInterrupt: "KeyboardInterrupt"}
    return identities.get(type(error), "UnknownError")


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
            encoded = {key: self.encode(item) for key, item in value.items()}
            # A plain result may contain the protocol discriminator as data.
            return {"$": "dict", "items": encoded} if "$" in value else encoded
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
        if kind == "dict":
            if set(value) != {"$", "items"} or not isinstance(value["items"], dict):
                raise ProtocolError("malformed tagged dictionary")
            return {key: self.decode(item) for key, item in value["items"].items()}
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
                    detail = {"$": "error", "type": _exception_identity(error), "message": str(error)}
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


BASELINE_COUNT = 50  # 39 release assertions plus eleven supervisor regressions.
CASE_FUNCTIONS = frozenset({"inline_source", "release_tag"})
MAX_CASE_BYTES = 65536
MAX_CASES = 256


def baseline(candidate, tests):
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
    if count != BASELINE_COUNT:
        raise RuntimeError(f"trusted discovery expected {BASELINE_COUNT} tests, found {count}")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != count or not result.wasSuccessful():
        raise RuntimeError(f"trusted unittest failed ({result.testsRun}/{count} executed)")


def _literal(value, depth=0, nodes=None):
    """Validate bounded, untagged JSON and return the number of visited nodes."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 8 or nodes[0] > 2048:
        raise ProtocolError("case literal is excessively nested or large")
    if value is None or type(value) in (bool, int, str):
        return nodes[0]
    if type(value) is float:
        if not math.isfinite(value):
            raise ProtocolError("case contains a non-finite number")
        return nodes[0]
    if isinstance(value, list):
        for item in value:
            _literal(item, depth + 1, nodes)
        return nodes[0]
    if isinstance(value, dict):
        if any(not isinstance(key, str) or key == "$" for key in value):
            raise ProtocolError("case literal contains an invalid key or protocol tag")
        for item in value.values():
            _literal(item, depth + 1, nodes)
        return nodes[0]
    raise ProtocolError("case contains a non-JSON literal")


def load_cases(directory):
    paths = sorted(Path(directory).glob("*.json"))
    if not paths:
        raise ProtocolError("proposed case inventory is empty")
    cases, identities, size = [], set(), 0
    for path in paths:
        raw = path.read_bytes()
        size += len(raw)
        if size > MAX_CASE_BYTES:
            raise ProtocolError("proposed cases exceed the size limit")
        try:
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ProtocolError(f"duplicate JSON key: {key}")
                    result[key] = value
                return result
            document = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=lambda value: (_ for _ in ()).throw(
                                      ProtocolError(f"non-JSON number: {value}")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProtocolError(f"malformed case file: {path.name}") from error
        if not isinstance(document, dict) or set(document) != {"schema", "cases"} \
                or document["schema"] != 1 or not isinstance(document["cases"], list) \
                or not document["cases"]:
            raise ProtocolError(f"invalid or empty case document: {path.name}")
        for case in document["cases"]:
            if not isinstance(case, dict) or not ({"id", "call", "args"} <= set(case)):
                raise ProtocolError("case must name its id, call, arguments and outcome")
            outcomes = set(case) & {"expect", "raises"}
            if set(case) != {"id", "call", "args"} | outcomes or len(outcomes) != 1:
                raise ProtocolError("case has unknown keys or a missing/mismatched outcome")
            identity, call, arguments = case["id"], case["call"], case["args"]
            if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", identity):
                raise ProtocolError("case has an invalid id")
            if identity in identities:
                raise ProtocolError(f"duplicate case id: {identity}")
            if call not in CASE_FUNCTIONS or not isinstance(arguments, list):
                raise ProtocolError("case requests an arbitrary operation")
            _literal(arguments)
            if "expect" in case:
                _literal(case["expect"])
            elif case["raises"] not in ("ValueError", "TypeError"):
                raise ProtocolError("case names an unsupported exception")
            identities.add(identity)
            cases.append(case)
            if len(cases) > MAX_CASES:
                raise ProtocolError("too many proposed cases")
    return cases


def evaluate_cases(candidate, directory):
    cases = load_cases(directory)
    client = Client(sys.stdin, sys.stdout)
    passed = 0
    for case in cases:
        try:
            value = client.request("invoke", 0, case["call"], case["args"])
        except (ValueError, TypeError) as error:
            if case.get("raises") != type(error).__name__:
                raise AssertionError(f"{case['id']}: unexpected {type(error).__name__}") from error
        else:
            if "raises" in case:
                raise AssertionError(f"{case['id']}: expected {case['raises']}, got a return value")
            if type(value) is not type(case["expect"]) or value != case["expect"]:
                raise AssertionError(f"{case['id']}: return value did not match")
        passed += 1
    if passed != len(cases):
        raise AssertionError("proposed case inventory did not complete")
    print(f"declarative cases: {passed}/{len(cases)} passed", file=sys.stderr)


def worker(candidate):
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", buffering=1)
    sys.stdout = sys.stderr
    # Bind the transport before candidate import; importing release.py must not
    # replace the adapter's class methods through __main__.
    write, read, error_identity = _line_write, _line_read, _exception_identity
    allowed_case_functions = CASE_FUNCTIONS
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
        if op == "invoke":
            name, positional = arguments[1], arguments[2]
            if name not in allowed_case_functions or not isinstance(positional, list):
                raise ProtocolError("arbitrary invocation refused")
            return getattr(target, name)(*positional)
        raise ProtocolError("unknown operation")

    def callback_send(_operation, callback, args, kwargs):
        nonlocal callback_sequence
        callback_sequence += 1
        callback_request = callback_sequence
        write(protocol, {"id": callback_request, "op": "callback", "callback": callback,
                                 "args": codec.encode((args, kwargs))})
        while True:
            reply = read(sys.stdin)
            if "op" in reply:
                try:
                    nested = {"id": reply["id"], "value": codec.encode(dispatch(reply))}
                except BaseException as error:
                    detail = {"$": "error", "type": error_identity(error), "message": str(error)}
                    if isinstance(error, subprocess.TimeoutExpired):
                        detail.update(cmd=codec.encode(error.cmd), timeout=error.timeout)
                    nested = {"id": reply.get("id"), "error": detail}
                write(protocol, nested)
                continue
            if reply.get("id") != callback_request:
                raise ProtocolError("invalid callback response")
            if "error" in reply:
                return codec.decode(reply["error"])
            return codec.decode(reply.get("value"))

    codec = Codec(callback_send, allow_callbacks=False)
    for name in ("encode", "decode", "_reference"):
        setattr(codec, name, getattr(codec, name))
    sys.path.insert(0, candidate)
    try:
        module = importlib.import_module("release")
    except BaseException as error:
        write(protocol, {"id": 0, "error": {"$": "error", "type": error_identity(error),
                                                   "message": str(error)}})
        return 1
    codec.objects[0] = module
    while True:
        try:
            message = read(sys.stdin)
            request_id = message["id"]
            result = dispatch(message)
            reply = {"id": request_id, "value": codec.encode(result)}
        except BaseException as error:
            detail = {"$": "error", "type": error_identity(error), "message": str(error)}
            if isinstance(error, subprocess.TimeoutExpired):
                detail.update(cmd=codec.encode(error.cmd), timeout=error.timeout)
            reply = {"id": message.get("id") if isinstance(message, dict) else None,
                     "error": detail}
        write(protocol, reply)


class SupervisorRegressionTests(unittest.TestCase):
    """Exercise authority boundaries without trusting candidate status or markers."""

    def run_fixture(self, release_source, document, successful):
        # Baseline TMPDIR is shared with the candidate for inert Path fixtures.
        # Executable test fixtures must stay in the oracle-only HOME mount.
        with tempfile.TemporaryDirectory(prefix="ghidra-supervisor-oracle-",
                                         dir=os.environ["HOME"]) as private, \
                tempfile.TemporaryDirectory(prefix="ghidra-supervisor-worker-",
                                             dir=os.environ["HOME"]) as worker:
            oracle_root, worker_root = Path(private), Path(worker)
            candidate = worker_root / "candidate"
            candidate.mkdir()
            (candidate / "release.py").write_text(release_source)
            cases = oracle_root / "cases"
            cases.mkdir()
            if isinstance(document, bytes):
                (cases / "fixture.json").write_bytes(document)
            else:
                (cases / "fixture.json").write_text(json.dumps(document))
            oracle_read, worker_write = os.pipe()
            worker_read, oracle_write = os.pipe()
            worker_process = subprocess.Popen(
                [sys.executable, "-B", __file__, "worker", str(candidate)],
                stdin=worker_read, stdout=worker_write, stderr=subprocess.DEVNULL,
                cwd=worker_root, env={**os.environ, "HOME": str(worker_root)})
            oracle_process = subprocess.Popen(
                [sys.executable, "-B", __file__, "cases", str(candidate), str(cases)],
                stdin=oracle_read, stdout=oracle_write, stderr=subprocess.PIPE, text=True,
                cwd=oracle_root, env={**os.environ, "HOME": str(oracle_root)})
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

    @staticmethod
    def document(case):
        return {"schema": 1, "cases": [case]}

    def test_declarative_positive_and_named_exception(self):
        document = {"schema": 1, "cases": [
            {"id": "positive", "call": "inline_source", "args": [{"commit_id": "abc"}],
             "expect": "abc"},
            {"id": "negative", "call": "release_tag",
             "args": [{"version": "1", "upstream_sha": "a" * 40}, "bad"],
             "raises": "ValueError"}]}
        source = ("def inline_source(record): return record.get('commit_id')\n"
                  "def release_tag(selected, config): raise ValueError('bad')\n")
        self.run_fixture(source, document, True)

    def test_candidate_zero_exit_fails_closed(self):
        case = {"id": "exit", "call": "inline_source", "args": [{}], "expect": None}
        self.run_fixture("import os\nos._exit(0)\n", self.document(case), False)

    def test_candidate_unittest_monkeypatch_cannot_decide_result(self):
        source = ("import unittest\nunittest.TextTestRunner.run=lambda *a,**k: None\n"
                  "def inline_source(record): return record.get('commit_id')\n")
        case = {"id": "patched", "call": "inline_source", "args": [{"commit_id": "ok"}],
                "expect": "ok"}
        self.run_fixture(source, self.document(case), True)

    def test_candidate_returned_dictionary_cannot_forge_an_exception(self):
        forged = {"$": "error", "type": "ValueError", "message": "forged"}
        self.assertEqual(Codec().decode(Codec().encode(forged)), forged)
        source = "def release_tag(*args): return " + repr(forged) + "\n"
        case = {"id": "must-actually-raise", "call": "release_tag",
                "args": [{}, "bad"], "raises": "ValueError"}
        self.run_fixture(source, self.document(case), False)

    def test_custom_class_named_value_error_cannot_forge_builtin(self):
        source = ("class ValueError(Exception): pass\n"
                  "def release_tag(*args): raise ValueError('forged')\n")
        case = {"id": "builtin-only", "call": "release_tag",
                "args": [{}, "bad"], "raises": "ValueError"}
        self.run_fixture(source, self.document(case), False)

    def test_candidate_import_cannot_replace_adapter_dictionary_encoder(self):
        source = ("import __main__\n"
                  "original = __main__.Codec.encode\n"
                  "def forged(self, value):\n"
                  " if isinstance(value, dict) and value.get('$') == 'error': return value\n"
                  " return original(self, value)\n"
                  "__main__.Codec.encode = forged\n"
                  "def release_tag(*args):\n"
                  " return {'$': 'error', 'type': 'ValueError', 'message': 'forged'}\n")
        case = {"id": "adapter-patch", "call": "release_tag",
                "args": [{}, "bad"], "raises": "ValueError"}
        self.run_fixture(source, self.document(case), False)

    def test_malformed_and_empty_documents_are_rejected(self):
        self.run_fixture("", b"{", False)
        self.run_fixture("", {"schema": 1, "cases": []}, False)

    def test_unexpected_exception_and_return_are_rejected(self):
        expected = {"id": "value", "call": "inline_source", "args": [{}], "expect": None}
        self.run_fixture("def inline_source(record): raise TypeError('no')\n",
                         self.document(expected), False)
        raises = {"id": "raise", "call": "release_tag", "args": [{}, "bad"],
                  "raises": "ValueError"}
        self.run_fixture("def release_tag(*args): return 'not an error'\n",
                         self.document(raises), False)

    def test_unknown_keys_tags_operations_and_duplicate_ids_are_rejected(self):
        base = {"id": "one", "call": "inline_source", "args": [{}], "expect": None}
        for case in ({**base, "code": "pass"}, {**base, "call": "run"},
                     {**base, "args": [{"$": "callback"}]}):
            self.run_fixture("", self.document(case), False)
        self.run_fixture("", {"schema": 1, "cases": [base, base]}, False)

    def test_excessive_nesting_and_size_are_rejected(self):
        nested = None
        for _ in range(10):
            nested = [nested]
        case = {"id": "deep", "call": "inline_source", "args": [nested], "expect": None}
        self.run_fixture("", self.document(case), False)
        self.run_fixture("", b" " * (MAX_CASE_BYTES + 1), False)

    def test_trusted_baseline_inventory_count(self):
        root = Path(__file__).parent
        count = unittest.TestLoader().discover(root, pattern="test_*.py").countTestCases()
        self.assertEqual(count, BASELINE_COUNT)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("baseline", "cases", "worker"))
    parser.add_argument("candidate")
    parser.add_argument("tests", nargs="?")
    args = parser.parse_args()
    if args.mode == "worker":
        return worker(args.candidate)
    if args.mode == "cases":
        return evaluate_cases(args.candidate, args.tests)
    return baseline(args.candidate, args.tests)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

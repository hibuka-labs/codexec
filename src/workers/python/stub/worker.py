"""codexec Python worker: one resident interpreter, JSON-lines protocol.

Protocol: process stdin carries host frames (one JSON object per line);
process stdout carries worker frames only — model `print()` is captured per
block and returned inside `block_result` frames. Capability shims call back
with `_phi_call(name, args)`; that is the single hook point the host applies
policy + journal at. The PEP 578 audit hook below routes mediated stdlib
effects (layer 2) through the same point on the reserved `__audit__` name.

Hard rules implemented here (codexec-design §4.4):
  D2  every block is validated before any block runs
  D3  a result in a variable is not "seen" — the displayhook echo is
  D4  one uncaught exception stops the remaining blocks of the step
"""

import ast
import io
import json
import os
import sys
import threading
import time
import traceback
import warnings

from phi_audit import AUDIT_CALL as _AUDIT_CALL
from phi_audit import jsonable as _jsonable
from phi_audit import mediate as _mediate

_NS = {"__name__": "__main__"}
_inbox = []
_call_seq = 0
_current_cell = [0]
# Round start in `time.monotonic()` terms — progress ticks are stamped from it.
_round_start = [0.0]

# One frame per write, under a lock: progress ticks fire from the heartbeat
# thread and a torn frame would poison the protocol for every consumer.
_send_lock = threading.Lock()


def _send(obj):
    line = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    with _send_lock:
        os.write(1, line)


def _progress(rid, index, text):
    """One progress tick on the protocol channel: what a cell printed and how
    long the round has been running. The observation reaches the model only
    when the round ends — this trail is what makes the run legible after."""
    _send({
        "kind": "progress",
        "request_id": rid,
        "index": index,
        "at_ms": int((time.monotonic() - _round_start[0]) * 1000),
        "text": text[:200],
    })


def _next_frame():
    while True:
        if _inbox:
            return _inbox.pop(0)
        # The wire is UTF-8 bytes (serde_json on the host writes UTF-8), but
        # the text layer of stdin is the machine's locale: on Windows that is
        # the ANSI code page with `surrogateescape`, which folds every
        # non-ASCII byte of model code into mojibake and lone surrogates (and
        # then `compile()` refuses them). Read bytes; the wire's codec is the
        # contract's, never the machine's.
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.decode("utf-8").strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except Exception:
            continue


def _tail(text, max_lines=20):
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[-max_lines:])


# ---- host-call seam (the one hook point) ---------------------------------

# One RPC at a time: `call_id` ↔ `host_result` correlation must not interleave
# when several threads (or the audit hook) call home concurrently.
_call_lock = threading.RLock()

# How many host calls are in flight right now. `threading.RLock` has no
# `locked()`, and the heartbeat's "is a call suspended?" question is about
# the call, not about the lock.
_in_call = [0]


def _phi_call(name, args):
    global _call_seq
    with _call_lock:
        _in_call[0] += 1
        try:
            _call_seq += 1
            call_id = "c%d" % _call_seq
            _send({
                "kind": "host_call",
                "call_id": call_id,
                "fn": name,
                "args": list(args),
                "cell_index": _current_cell[0],
            })
            while True:
                frame = _next_frame()
                if frame is None:
                    raise RuntimeError("host closed the channel during host_call")
                if frame.get("kind") == "host_result" and frame.get("call_id") == call_id:
                    if frame.get("ok"):
                        return frame.get("value")
                    raise RuntimeError(frame.get("error") or "host call failed")
                _inbox.append(frame)
        finally:
            _in_call[0] -= 1


_NS["_phi_call"] = _phi_call


# ---- ns discovery (help protocol) -----------------------------------------
#
# Declaration docs arrive from the host at pack install (`_phi_define_docs`,
# sourced from `MethodSpec` via phi-ns `help_doc`). `help` answers from that
# table, so the declaration is the only place facts live — a shim's docstring
# is convenience, never the answer, and cannot drift from it. `dir()` is the
# builtin; names live in `_NS`. `help()` with no arguments prints the
# overview instead of pydoc's interactive helper, which would block on stdin
# in this worker.

_phi_docs = {}


def _phi_define_docs(mapping):
    for name, text in (mapping or {}).items():
        _phi_docs[name] = text


def _phi_name_of(obj):
    """Resolve a live object back to its declaration name (`sh.run`)."""
    direct = getattr(obj, "_name", None)
    if isinstance(direct, str):
        return direct
    fn = getattr(obj, "__func__", obj)
    for root, val in list(_NS.items()):
        if root.startswith("_"):
            continue
        if val is obj:
            return root
        for attr in dir(val):
            if attr.startswith("_"):
                continue
            w = getattr(val, attr, None)
            if w is obj or getattr(w, "__func__", w) is fn:
                return "%s.%s" % (root, attr)
    return None


def _phi_help_text(name):
    if name in _phi_docs:
        return _phi_docs[name]
    kids = sorted(k for k in _phi_docs if k.startswith(name + "."))
    if kids:
        return "\n\n".join(_phi_docs[k] for k in kids)
    return None


def _phi_declared_root(name):
    root = name.split(".", 1)[0]
    if root in _phi_docs or any(k.startswith(root + ".") for k in _phi_docs):
        return root
    return None


def _phi_help(x=None):
    if x is None:
        if not _phi_docs:
            print("no namespace declarations installed")
            return
        roots = {}
        for k in sorted(_phi_docs):
            roots.setdefault(k.split(".", 1)[0], []).append(k)
        for root in sorted(roots):
            print(root + ":")
            for k in roots[root]:
                print("  " + _phi_docs[k].splitlines()[0])
        return
    name = x if isinstance(x, str) else _phi_name_of(x)
    if name is not None:
        text = _phi_help_text(name)
        if text is not None:
            print(text)
            return
        if not isinstance(x, str) or _phi_declared_root(name) is not None:
            # An ns-shaped name (or a live proxy) with no declaration: fail
            # loud — a silent fallthrough would hide a real gap.
            raise ValueError(
                "no namespace declaration for %r; declared: %s"
                % (name, ", ".join(sorted(_phi_docs)) or "none")
            )
    import pydoc

    return pydoc.help(x)


_NS["help"] = _phi_help
_NS["_phi_define_docs"] = _phi_define_docs


# ---- mediated-effect audit hook (layer 2, PEP 578) -----------------------
#
# Every mediated stdlib event becomes one call-row at the host-call seam:
# decide → journal write-ahead → let the effect run. Raising here blocks the
# operation (fail-closed) and the exception surfaces on the effect's call
# site. The event set and the call-site filters live in `phi_audit` (shared
# with every Python child's `sitecustomize.py` hook) and must match the
# host's classifier table exactly (`codexec/src/audit.rs`); tests enforce it.

# Per-thread re-entrancy guard: a mediated event fired from inside the hook's
# own plumbing (e.g. `repr` of a hostile arg) must not recurse into the RPC.
_hook_state = threading.local()


def _audit_hook(event, args):
    if getattr(_hook_state, "depth", 0):
        return
    # Arm the guard *first*: `sys._getframe` is itself an audited event, so
    # asking for the caller would re-enter this hook forever. Everything the
    # hook does (frame grab, filtering, the RPC) runs under the guard.
    _hook_state.depth = 1
    try:
        try:
            caller = sys._getframe(1)
        except ValueError:
            return
        rw = _mediate(event, args, caller)
        if rw is None:
            return
        _phi_call(_AUDIT_CALL, [event, [_jsonable(a) for a in args], rw])
    finally:
        _hook_state.depth = 0


# ---- namespace snapshots -------------------------------------------------

def _generic_detail(val):
    if isinstance(val, (list, tuple, set, dict)):
        return str(len(val))
    if val is None or isinstance(val, (bool, int, float, str)):
        return repr(val)
    return ""


def _summary_attr(val):
    """Read `_phi_summary_` without poking `__getattr__` — attribute handlers
    fire real effects (ctypes does `dlsym` on any lookup), and our telemetry
    must never manufacture rows the model did not cause."""
    try:
        return object.__getattribute__(val, "_phi_summary_")
    except AttributeError:
        return None
    except Exception:
        return None


def ns_entries():
    entries = []
    for name, val in list(_NS.items()):
        if name.startswith("_"):
            continue
        if name in ("__builtins__", "__name__", "__doc__", "__package__",
                    "__loader__", "__spec__", "__file__", "__cached__",
                    "__annotations__", "help"):
            # `help` is runtime surface (the help protocol), not user state —
            # the snapshot lists what is alive to use, not how to discover it
            continue
        if isinstance(val, type):
            # class objects are definitions, not state — the snapshot lists
            # what is alive to use (`sh`, `out`, `x`), not what defines it
            continue
        kind = type(val).__name__
        detail = None
        summary = _summary_attr(val)
        if callable(summary):
            try:
                detail = str(summary())
            except Exception:
                detail = None
        if detail is None:
            detail = _generic_detail(val)
        try:
            rep = repr(val)
        except Exception:
            rep = kind
        if len(rep) > 120:
            rep = rep[:117] + "..."
        entries.append({"name": name, "kind": kind, "repr": rep, "detail": detail})
    return entries


# ---- auto-proxies for registered host functions --------------------------

class _PhiNs(object):
    pass


class _PhiFn(object):
    def __init__(self, name):
        self._name = name

    def __call__(self, *args):
        return _phi_call(self._name, list(args))


def _define(names):
    for name in names:
        root, _, tail = name.partition(".")
        if not root or not tail:
            continue
        obj = _NS.get(root)
        if obj is None:
            obj = _PhiNs()
            _NS[root] = obj
        elif not isinstance(obj, _PhiNs):
            # a shim owns this root (e.g. `sh = ShellSdk()`) and wires calls
            # through `_phi_call` itself
            continue
        setattr(obj, tail, _PhiFn(name))


# ---- block execution -----------------------------------------------------

def _cap(text, limit):
    if len(text) <= limit:
        return text, False
    cut = limit
    while cut > 0 and not isinstance(text[cut - 1], str):
        cut -= 1
    return text[:cut] + "\n…[truncated]", True


class _Tee(io.StringIO):
    """Capture stream that also ticks the progress trail: what a cell prints
    is legible while the round runs, not only when it ends. Ticks are
    throttled (one per 250ms per stream) and truncated — the full body still
    rides back on the block result; this is a trail, not a second channel."""
    _THROTTLE = 0.25

    def __init__(self, rid, index):
        super().__init__()
        self._rid = rid
        self._index = index
        self._last = 0.0

    def write(self, s):
        n = super().write(s)
        now = time.monotonic()
        text = s.strip()
        if text and now - self._last >= self._THROTTLE:
            self._last = now
            _progress(self._rid, self._index, text.replace("\n", " / "))
        return n


def _run_block(tree, stdout_cap, stderr_cap, pre_err=(), rid="", index=0):
    out_buf, err_buf = _Tee(rid, index), _Tee(rid, index)
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out_buf, err_buf
    error = None
    try:
        body = list(tree.body)
        last = None
        if body and isinstance(body[-1], ast.Expr):
            last = body[-1]
            body = body[:-1]
        if body:
            mod = ast.Module(body=body, type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, "<cell>", "exec"), _NS)
        if last is not None:
            expr = ast.Expression(body=last.value)
            ast.fix_missing_locations(expr)
            value = eval(compile(expr, "<cell>", "eval"), _NS)
            if value is not None:
                _NS["out"] = value
                text = str(value)
                if text:
                    sys.stdout.write(text)
                    if not text.endswith("\n"):
                        sys.stdout.write("\n")
    except BaseException as exc:  # noqa: BLE001 — any failure ends the step
        error = {
            "kind": type(exc).__name__,
            "message": str(exc) or repr(exc),
            "traceback": _tail(traceback.format_exc()),
        }
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    out, _ = _cap(out_buf.getvalue(), stdout_cap)
    err = "\n".join(t for t in (*pre_err, err_buf.getvalue()) if t)
    err, _ = _cap(err, stderr_cap)
    return out, err, error


# ---- request handlers ----------------------------------------------------

def _done(rid, phase, started, exit_code, error=None, stopped_at=None):
    _send({
        "kind": "done",
        "request_id": rid,
        "exit": exit_code,
        "elapsed_ms": int((time.time() - started) * 1000),
        "phase": phase,
        "error": error,
        "stopped_at": stopped_at,
    })


def _dump_stack():
    """Where every thread is stuck, on fd 2 (the host drains stderr into the
    ring the timeout error reads). Marker first so the host can find the dump
    among ordinary diagnostics."""
    try:
        os.write(2, b"\n===PHI_STACK_DUMP===\n")
        import faulthandler
        faulthandler.dump_traceback(file=os.fdopen(2, "w", closefd=False))
    except Exception:
        pass


def _heartbeat(rid, started, timeout_ms, stop):
    """Progress ticks (one per `interval` while a round runs) plus a stack
    dump just before the round's hard deadline and every tick after it: a hung
    cell leaves "where it stuck" behind instead of only "timeout", and the dump
    stays fresh through the hang. The dump never fires while a host call is in
    flight — a cell suspended for human consent is not a stuck cell (the round
    budget freezes with it, so the deadline must not count that time either).

    `started` is wall clock (the `done` frame's elapsed); the deadline runs on
    the monotonic clock — mixing the two in one comparison is how the dump
    silently never fires."""
    t0 = time.monotonic()
    interval = min(5.0, max(0.5, timeout_ms / 4000.0))
    deadline = t0 + (timeout_ms / 1000.0) * 0.9
    while True:
        now = time.monotonic()
        wait = interval
        if now < deadline:
            wait = min(wait, deadline - now)
        if stop.wait(wait):
            return
        if time.monotonic() >= deadline and not _in_call[0]:
            _dump_stack()
            continue
        _progress(rid, _current_cell[0], "still running")


def _handle_exec(rid, frame):
    started = time.time()
    _round_start[0] = time.monotonic()
    blocks = frame.get("blocks") or []
    config = frame.get("config") or {}
    limits = config.get("limits") or {}
    stdout_cap = int(limits.get("stdout", 262144))
    stderr_cap = int(limits.get("stderr", 65536))
    timeout_ms = int(config.get("timeout_ms") or 120000)

    stop = threading.Event()
    beater = threading.Thread(target=_heartbeat,
                              args=(rid, started, timeout_ms, stop), daemon=True)
    beater.start()
    try:
        # D2: validate every block before running any of them. The parse itself
        # emits warnings (e.g. SyntaxWarning on an invalid escape) and this pass
        # runs outside `_run_block`'s capture — record them per block and hand
        # them to that block's stderr instead of leaking them to the real one.
        trees = []
        parse_notes = []
        for i, block in enumerate(blocks):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    trees.append(ast.parse(block.get("code") or "", "<cell %d>" % i))
                except SyntaxError as exc:
                    error = {
                        "kind": type(exc).__name__,
                        "message": str(exc),
                        "traceback": _tail(traceback.format_exc()),
                    }
                    _done(rid, "exec", started, 1, error=error, stopped_at=i)
                    return
            parse_notes.append([
                "%s:%s: %s: %s" % (w.filename, w.lineno, w.category.__name__, w.message)
                for w in caught
            ])

        stopped_at = None
        for i, tree in enumerate(trees):
            _current_cell[0] = i
            # Children of this block inherit the attribution (sitecustomize
            # stamps their events with it).
            os.environ["PHI_CELL"] = str(i)
            out, err, error = _run_block(tree, stdout_cap, stderr_cap,
                                         parse_notes[i], rid, i)
            _send({
                "kind": "block_result",
                "request_id": rid,
                "index": i,
                "stdout": out,
                "stderr": err,
                "error": error,
                "ns": ns_entries(),
            })
            if error is not None:
                stopped_at = i
                break

        _done(rid, "exec", started, 0 if stopped_at is None else 1,
              stopped_at=stopped_at)
    finally:
        stop.set()


def _handle_eval(rid, frame):
    started = time.time()
    code = frame.get("code") or ""
    try:
        exec(compile(code, "<install>", "exec"), _NS)
        _send({"kind": "value", "request_id": rid, "ok": True,
               "repr": None, "error": None})
    except BaseException as exc:  # noqa: BLE001
        _send({"kind": "value", "request_id": rid, "ok": False, "repr": None,
               "error": _tail(traceback.format_exc()) or str(exc)})
    _done(rid, "eval", started, 0)


def _handle_define(rid, frame):
    started = time.time()
    _define(frame.get("names") or [])
    _done(rid, "define", started, 0)


def _handle_ns(rid):
    started = time.time()
    _send({"kind": "ns_entries", "request_id": rid, "entries": ns_entries()})
    _done(rid, "ns", started, 0)


def main():
    while True:
        frame = _next_frame()
        if frame is None:
            break
        kind = frame.get("kind")
        rid = frame.get("request_id", "")
        if kind == "exec":
            _handle_exec(rid, frame)
        elif kind == "eval":
            _handle_eval(rid, frame)
        elif kind == "define":
            _handle_define(rid, frame)
        elif kind == "ns":
            _handle_ns(rid)
        elif kind == "shutdown":
            _done(rid, "shutdown", time.time(), 0)
            break
        elif kind == "host_result":
            _inbox.append(frame)
        # unknown frames are dropped (forward compatibility)


# Installed last: from here on, mediated effects cross the seam (the hook
# cannot be removed — PEP 578).
sys.addaudithook(_audit_hook)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # last-resort diagnostics must not go to stdout (protocol channel)
        sys.stderr.write(traceback.format_exc())
        os._exit(2)

"""codexec child-process audit mediation (PEP 578).

CPython's `site` module auto-imports this file in every Python child the
resident worker spawns (`PYTHONPATH` points at this directory and
`PHI_AUDIT_SOCK` names the host's audit socket). It mirrors the worker's own
hook: mediated stdlib effects are decided and journaled at the host *before*
they run — a denial raises here and blocks the effect in the child
(fail-closed), exactly as in the worker. Without this file a child's effects
left the ledger blind (the subprocess hole: only the parent's
`subprocess.Popen` row).

Installed only in children: the resident worker is the `codexec-worker-*.py`
script on `argv[0]` and runs its own hook — mediating twice would double the
rows.

Residual holes (beyond codexec-design §8.4): a child started with `-S` / `-E`
/ `-I` skips `site` or `PYTHONPATH` and is not covered; non-Python children
(a shell, a binary) stay invisible — their parent's `subprocess.Popen` row is
the only trace; a child that dislodges this hook through `sys.modules` can
silence it (same as the worker's own hook).
"""

import os
import sys


def _install():
    sock_path = os.environ.get("PHI_AUDIT_SOCK")
    if not sock_path:
        return
    argv0 = sys.argv[0] if sys.argv else ""
    if os.path.basename(argv0).startswith("codexec-worker-"):
        return  # the resident worker runs its own hook — never both
    try:
        import json
        import socket
        import threading
        from phi_audit import jsonable, mediate
    except Exception:
        return  # shared filters unreachable: nothing coherent to install

    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
    except Exception:
        sock = None  # host unreachable: fail-closed below, never open

    state = {"seq": 0, "lock": threading.Lock(), "depth": 0}

    def emit(event, args, rw):
        # One RPC at a time per connection: `id` ↔ verdict must not interleave.
        with state["lock"]:
            if sock is None:
                raise RuntimeError("audit channel unavailable (host not reachable)")
            state["seq"] += 1
            rid = state["seq"]
            line = json.dumps({
                "id": rid,
                "event": event,
                "args": args,
                "rw": rw,
                "cell": int(os.environ.get("PHI_CELL", "0") or 0),
            }) + "\n"
            sock.sendall(line.encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    raise RuntimeError("audit channel closed")
                buf += chunk
            verdict = json.loads(buf.decode("utf-8"))
            if not verdict.get("ok"):
                raise RuntimeError(verdict.get("error") or "audit denied")

    def hook(event, args):
        if state["depth"]:
            return
        # Arm the guard *first*: `sys._getframe` is itself an audited event,
        # so asking for the caller would re-enter this hook forever.
        state["depth"] = 1
        try:
            try:
                caller = sys._getframe(1)
            except ValueError:
                return
            rw = mediate(event, args, caller)
            if rw is None:
                return
            emit(event, [jsonable(a) for a in args], rw)
        finally:
            state["depth"] = 0

    sys.addaudithook(hook)


_install()

"""Shared mediation filters for codexec's PEP 578 audit hooks.

One source for the mediated event set and the call-site filters both hook
halves apply: the resident worker's hook (worker.py) and every Python child
process's hook (sitecustomize.py). The set must match the host's
classification table exactly (`codexec/src/audit.rs`); tests on both sides
parse this file and assert it — a drift would silently un-mediate effects.

Filter defaults are bound as default arguments so a cell monkeypatching this
module's globals cannot widen the blind spot (it can still try to dislodge
the hook itself through `sys.modules` — same residual hole as before).
"""

import os
import sys

# Wire name the hooks call back on — reserved, never a pack method
# (`codexec/src/audit.rs` `AUDIT_CALL`).
AUDIT_CALL = "__audit__"

# Mediated stdlib events, sorted. Events not here pass silent (interpreter
# plumbing: `import`, `exec`, `compile`, `marshal.loads`, ...). Residual
# holes after mediation are documented in codexec-design §8.4.
MEDIATED = frozenset((
    "ctypes.dlopen",
    "ctypes.dlsym",
    "open",
    "os.chflags",
    "os.chmod",
    "os.chown",
    "os.exec",
    "os.fork",
    "os.kill",
    "os.killpg",
    "os.link",
    "os.listdir",
    "os.mkdir",
    "os.posix_spawn",
    "os.rename",
    "os.remove",
    "os.rmdir",
    "os.scandir",
    "os.symlink",
    "os.system",
    "os.truncate",
    "os.utime",
    "shutil.copyfile",
    "shutil.copymode",
    "shutil.copystat",
    "shutil.move",
    "shutil.rmtree",
    "socket.bind",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.sendto",
    "subprocess.Popen",
))

# Interpreter plumbing — the caller frame of these events is the import/debug
# machinery, not user code. pathlib/os/shutil are deliberately NOT here: user
# calls through them must be mediated (their module-top-level effects during
# import ARE mediated too — caller is the module frame).
INTERNAL_PREFIXES = (
    "_frozen_importlib", "importlib", "zipimport",
    "linecache", "tokenize", "traceback", "bdb", "pdb",
)


def is_pseudo_path(path):
    """Compile/exec labels — not effect targets. CPython's error rendering
    fetches source lines for them (a failed `ast.parse` in the traceback
    caret extraction opens `<unknown>`; a D2 syntax error opens `<cell N>`),
    and those fetches must not become ledger rows. Residual hole (§8.4): a
    real file literally named `<unknown>` etc. would pass silent."""
    if not isinstance(path, str):
        return False  # int paths are open fds — real targets
    if path in ("<unknown>", "<string>", "<stdin>", "<console>",
                "<install>", "<cell>"):
        return True
    return path.startswith("<cell ") and path.endswith(">")


def open_rw(mode, flags):
    """Decode `open`'s mode/flags to "read"/"write" with the interpreter's own
    constants — the flag bits are platform-specific and belong here."""
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        return "write"
    wbits = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    try:
        if flags & wbits:
            return "write"
    except TypeError:
        pass
    return "read"


def jsonable(a):
    """One event arg → JSON-safe. Digest correlation, not payload fidelity."""
    if a is None or isinstance(a, (bool, int, float, str)):
        return a
    if isinstance(a, (bytes, bytearray)):
        return bytes(a).decode("utf-8", "replace")
    if isinstance(a, (list, tuple)):
        return [jsonable(x) for x in a]
    return repr(a)[:200]


def mediate(event, args, caller, _mediated=MEDIATED, _prefixes=INTERNAL_PREFIXES):
    """The pre-filters, in order. Returns the `rw` decode ("" for non-`open`
    events) when this (event, call site) pair is mediated, or None to pass
    silent. `caller` is the frame that caused the effect — the hook's own
    caller, handed in by the hook because only it knows its frame depth."""
    if event not in _mediated:
        return None
    if event == "open" and is_pseudo_path(args[0] if args else None):
        return None
    name = caller.f_globals.get("__name__") or ""
    if isinstance(name, str) and name.startswith(_prefixes):
        return None
    if event == "open":
        return open_rw(args[1] if len(args) > 1 else None,
                       args[2] if len(args) > 2 else 0)
    return ""

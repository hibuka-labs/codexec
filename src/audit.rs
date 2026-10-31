//! Worker-effect mediation (audit seam layer 2): the host half of the PEP 578
//! audit hook in the Python worker (codexec-design §8.4).
//!
//! The worker's stdlib never crosses `host_call`, so pure-Python effects used
//! to leave the journal blind (the 2026-10-27 dogfood gap). The hook turns
//! every mediated stdlib event into one call-row at the same chokepoint pack
//! calls use: classify → decide → journal write-ahead → let the effect run
//! (or refuse, fail-closed).
//!
//! Two lists define the surface and must not drift:
//!
//! - `MEDIATED_EVENTS` here — the classification table's keys;
//! - `_MEDIATED` in `workers/python/stub/worker.py` — the hook's pre-filter.
//!
//! The tests below parse the stub and assert they are the same set (and that
//! the stub calls back on this module's reserved name). Events not on the
//! list pass silent (interpreter plumbing: `import`, `exec`, `compile`,
//! `marshal.loads`, …), and the hole that remains after mediation is
//! documented in codexec-design §8.4: ctypes calls past the bind point,
//! `os.stat`-level reads, C-extension-internal syscalls.

use phi_cap::Capability;

/// Wire name the hook calls back on — reserved, never a pack method.
pub const AUDIT_CALL: &str = "__audit__";

/// Every mediated event name, sorted. The stub's `_MEDIATED` must match.
pub const MEDIATED_EVENTS: &[&str] = &[
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
];

/// Classify one mediated event under the one capability vocabulary.
///
/// `rw` is the hook's decode of `open`'s mode/flags via the interpreter's own
/// constants (`"read"` / `"write"`); only `open` reads it. None = not a
/// mediated event — the caller must refuse (fail-closed on set drift).
///
/// ctypes events sit under `Process`: past the bind point a ctypes call is
/// arbitrary native code, and of the six classes that is the honest closest.
pub fn classify(event: &str, rw: &str) -> Option<Capability> {
    use Capability::*;
    let cap = match event {
        "open" => {
            if rw == "write" {
                WriteFs
            } else {
                ReadFs
            }
        }
        "os.listdir" | "os.scandir" => ReadFs,
        "os.rename" | "os.remove" | "os.mkdir" | "os.rmdir" | "os.chmod" | "os.chown"
        | "os.chflags" | "os.link" | "os.symlink" | "os.truncate" | "os.utime"
        | "shutil.copyfile" | "shutil.copymode" | "shutil.copystat" | "shutil.move"
        | "shutil.rmtree" => WriteFs,
        "os.system" | "subprocess.Popen" | "os.fork" | "os.exec" | "os.posix_spawn" | "os.kill"
        | "os.killpg" | "ctypes.dlopen" | "ctypes.dlsym" => Process,
        "socket.connect"
        | "socket.bind"
        | "socket.sendto"
        | "socket.getaddrinfo"
        | "socket.gethostbyname" => Net,
        _ => return None,
    };
    Some(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mediated_event_classifies() {
        for &ev in MEDIATED_EVENTS {
            assert!(
                classify(ev, "read").is_some(),
                "{ev} must have a capability class"
            );
        }
    }

    #[test]
    fn open_splits_on_the_hooks_read_write_decode() {
        assert_eq!(classify("open", "read"), Some(Capability::ReadFs));
        assert_eq!(classify("open", "write"), Some(Capability::WriteFs));
    }

    #[test]
    fn mutation_stays_write_process_stays_process() {
        assert_eq!(classify("os.rename", ""), Some(Capability::WriteFs));
        assert_eq!(classify("subprocess.Popen", ""), Some(Capability::Process));
        assert_eq!(classify("ctypes.dlopen", ""), Some(Capability::Process));
        assert_eq!(classify("socket.connect", ""), Some(Capability::Net));
        assert_eq!(classify("os.listdir", ""), Some(Capability::ReadFs));
    }

    #[test]
    fn unknown_events_classify_to_nothing() {
        assert_eq!(classify("import", ""), None);
        assert_eq!(classify("marshal.loads", ""), None);
        assert_eq!(classify("ctypes.call_function", ""), None);
    }

    #[test]
    fn the_stub_hook_set_matches_this_table() {
        // The two lists are the same surface seen from each side; a drift
        // would silently un-mediate effects (the stub filters first).
        let stub = include_str!("workers/python/stub/worker.py");
        let block = stub
            .split("_MEDIATED = frozenset((")
            .nth(1)
            .expect("worker.py declares _MEDIATED")
            .split("))")
            .next()
            .expect("_MEDIATED closes");
        let mut from_stub: Vec<&str> = block
            .lines()
            .map(|l| l.trim().trim_matches(',').trim())
            .filter(|l| l.starts_with('"'))
            .map(|l| l.trim_matches('"'))
            .collect();
        from_stub.sort_unstable();
        let mut from_table: Vec<&str> = MEDIATED_EVENTS.to_vec();
        from_table.sort_unstable();
        assert_eq!(from_stub, from_table, "worker.py _MEDIATED drifted");
    }

    #[test]
    fn the_stub_calls_back_on_this_reserved_name() {
        // A drift here would land audit calls as undeclared pack methods.
        let stub = include_str!("workers/python/stub/worker.py");
        assert!(
            stub.contains(&format!("_AUDIT_CALL = \"{AUDIT_CALL}\"")),
            "worker.py must name _AUDIT_CALL = {AUDIT_CALL:?}"
        );
    }
}

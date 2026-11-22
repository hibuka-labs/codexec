# Changelog

All notable changes to the `codexec` crate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A timeout says where the round hung, even on a loaded machine.** The
  worker's stack dump rides its stderr, so it reaches the host through the
  drain task — a different task than the one that timed out. Reading the
  dump the instant the deadline tripped was a race with that task: on a busy
  runner the drain had not been scheduled yet, and the round died without
  saying where it hung. The failure was real either way, but the diagnosis
  is what the timeout is for. The read now waits briefly for a dump that is
  already written, bounded so a dump that never lands cannot hold the
  timeout open.
- **The child-process audit tests survive a Windows path.** The fixtures
  interpolated a raw path into Python *source text*, and a Windows path is
  `C:\Users\me\file.txt` — Python reads the `\U` as the start of a unicode
  escape and the cell dies with "'unicodeescape' codec can't decode bytes"
  before the code under test ever runs. The paths now go into the cell as
  proper Python string literals, so the value the cell sees is the path and
  nothing else.
- **The child-audit tests run where the channel exists.** The channel that
  mediates a child's effects is a Unix domain socket, so it is not installed
  on Windows — but two tests asserted that a child's write is mediated, and
  they failed there for a reason the design already documents. Those tests
  now run on the platforms that have the channel, and Windows gets a test
  that pins the blind spot instead: the child's write lands and the journal
  holds no row for it. The limitation stays asserted, not skipped.

## [0.2.1] - 2026-11-16

### Fixed
- **The worker reads the wire as bytes, not as locale text.** A UTF-8
  payload split across the socket boundary used to go through the
  platform's locale decoding, which on a non-UTF-8 locale mangled the
  bytes and failed the frame. The wire is bytes; it is now read as bytes.

## [0.2.0] - 2026-11-09

### Added
- **Python subprocesses are audited too.** A child the worker spawns
  auto-installs the same PEP 578 mediation (`sitecustomize.py`, loaded via
  `PYTHONPATH`) and streams its events over a Unix socket — one connection
  per child, one inline verdict per event. The child's effects land in the
  journal as `call` rows like any other host call, and a denial raises
  *inside the child*, before the effect runs (fail-closed). On non-Unix
  platforms the channel is not installed and the old blind spot remains.

### Changed
- **The observation carries more than the result.** Effects, the timeout
  stack and progress travel with the observation, so a caller can tell what
  actually happened without re-reading the journal.

## [0.1.0] - 2026-10-31

### Added
- **First release.** The CodeAct execution layer: one resident interpreter behind one tool.
Action parsing, the host-call seam where policy and journal are welded on,
per-turn limits, the artifact store, and the escape hatch.

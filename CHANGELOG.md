# Changelog

All notable changes to the `codexec` crate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

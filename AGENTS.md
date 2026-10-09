# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

You can browse and install extra skills here:
<https://github.com/moonbitlang/skills>

## Project Structure

- MoonBit packages are organized per directory; each directory contains a
  `moon.pkg` file listing its dependencies. Each package has its files and
  blackbox test files (ending in `_test.mbt`) and whitebox test files (ending in
  `_wbtest.mbt`).

- In the toplevel directory, there is a `moon.mod` file listing module
  metadata.

## Coding convention

- MoonBit code is organized in block style, each block is separated by `///|`,
  the order of each block is irrelevant. In some refactorings, you can process
  block by block independently.

- Try to keep deprecated blocks in file called `deprecated.mbt` in each
  directory.

## Tooling

- `moon fmt` is used to format your code properly.

- `moon ide` provides project navigation helpers like `peek-def`, `outline`, and
  `find-references`. See $moonbit-agent-guide for details.

- `moon info` is used to update the generated interface of the package, each
  package has a generated interface file `.mbti`, it is a brief formal
  description of the package. If nothing in `.mbti` changes, this means your
  change does not bring the visible changes to the external package users, it is
  typically a safe refactoring.

- In the last step, run `moon info && moon fmt` to update the interface and
  format the code. Check the diffs of `.mbti` file to see if the changes are
  expected.

- Run `moon test` to check tests pass. MoonBit supports snapshot testing; when
  changes affect outputs, run `moon test --update` to refresh snapshots.

- Prefer `assert_eq` or `assert_true(pattern is Pattern(...))` for results that
  are stable or very unlikely to change. For snapshot tests that record
  structured debugging output, derive `Debug` and use `debug_inspect`, rather
  than deriving `Show` for debugging. For solid, well-defined results (e.g.
  scientific computations), prefer assertion tests. You can use
  `moon coverage analyze > uncovered.log` to see which parts of your code are
  not covered by tests.

## Project Conventions

- This module is a client library: the root package is the public API surface;
  `cmd/` and `examples/` hold runnable programs, not core logic.

- Package layout follows SNMP protocol layering: `ber` (BER-TLV wire codec),
  `oid` (object identifier), `pdu` (SNMP message and PDU structures), `session`
  (UDP transport, request/response correlation, retry), `mib` (generic walk
  helpers). New packages are added batch by batch as their functionality lands.

- Failures use dedicated enum error types (one per package) with MoonBit error
  handling; no stringly-typed errors.

- Naming follows MoonBit core style: PascalCase types, snake_case functions and
  bindings.

- Tests: blackbox `_test.mbt` files for every public API; whitebox `_wbtest.mbt`
  only for invariants not observable from outside.

- Encoder/decoder functions are validated against golden byte vectors derived by
  hand from the SNMP specifications (RFC 1157, 3416, 3411–3417) and against
  byte-level fixtures recorded from a real agent (net-snmp). Protocol constants
  and wire-format decisions cite the relevant RFC section in comments.

- The public API is designed for reuse: minimal surface, no global state, and no
  binding to a single use case (no hard-coded MIB objects in the core).

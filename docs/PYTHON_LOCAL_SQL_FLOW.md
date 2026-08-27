# Python Local SQL-Flow Boundary

**Status:** Implemented as a bounded AST extension to `SEC-SAST-001` version `0.2.0`. This document specifies exactly one local propagation pattern. It is not a whole-program dataflow engine, an ORM security assessment, or a guarantee that all SQL is parameterized.

## Purpose

The native Python SQL control continues to report a direct f-string, percent-format expression, or literal `.format(...)` expression supplied as the first argument to `execute` or `executemany`. It now also reports the same construction when it is assigned to one simple local name and that same name is later supplied to a standalone `execute` or `executemany` call in the same lexical function or module scope.

The extension is deliberately small. It preserves the existing direct-pattern evidence exactly. A local-flow finding additionally records the normalized evidence value `flow: local_straight_line_assignment`; it never records the variable name, SQL text, interpolated value, parameters, source excerpt, or database identifier.

## Detection contract

| Observable source structure | Result |
|---|---|
| `query = f"...{value}..."` followed by `cursor.execute(query)` in the same straight-line scope | One blocking `SEC-SAST-001` finding with construction `f_string` and local-flow evidence. |
| Literal percent or `.format(...)` construction assigned to one name, followed by `execute` or `executemany` | One blocking local-flow finding for the corresponding construction kind. |
| Direct unsafe expression passed to an execute sink | Existing direct finding behavior is preserved without a `flow` evidence field. |
| Local tracked name reassigned to a non-interpolated expression before the sink | No local-flow finding; the prior tracked value is forgotten. |
| No Python source in the bounded inventory | `NOT_APPLICABLE`, as before. |

## Explicit exclusions

| Excluded construct | Boundary rationale |
|---|---|
| `if`, `for`, `while`, `try`, `with`, `match`, and other compound statements | The control does not reason about path conditions, loop state, exception paths, or context-manager behavior. A potential assignment inside a skipped compound statement is not followed. |
| Aliases such as `alias = query` | The control follows only the original simple assignment name and does not propagate aliases. |
| Attributes, subscripts, tuple unpacking, globals, nonlocals, and object fields | The control does not model object or container state. |
| Function calls, imports, closures, callbacks, returns, parameters, and interprocedural flow | The control does not resolve code across call boundaries or modules. |
| Execute calls used as assignment values or nested in other expressions | Only standalone expression statements, including awaited standalone calls, are considered as local-flow sinks. |
| ORMs, non-SQL injection families, dynamic strings, runtime values, and database-driver semantics | These require separate contracts, fixtures, and reviewed precision evidence. |
| A clean result | It means only that the direct or one-local-name pattern was not found. It does not mean that SQL is secure. |

## Authority and contract provenance

`SEC-SAST-001` remains policy-selected and deterministic. It produces normalized control executions and findings; the versioned policy engine alone assigns `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, `PASS`, or `NOT_EVALUATED`. The capability registry and domain-control catalog are declarative provenance records. The mapped contract `CONTROL-INJECTION-PYTHON-001` version `0.2.0` is informative and cannot execute code, select an adapter, suppress a finding, alter a waiver, or affect a release decision.

## Fixture matrix

The regression set includes direct f-string, percent-format, and `.format(...)` local assignments; an explicit safe reassignment; a conditional assignment; alias propagation; an assigned execute result; the existing direct-sink pattern; and integration fixtures for a vulnerable local flow, safe reassignment, and conditional ambiguity. The conditional fixture is intentionally clean because following branch state would exceed this first contract.

# Bounded Python SQL Single-Local-Alias Contract

**Status:** Implemented as a separate opt-in native static control. This document describes one AST-visible lexical flow only; it does not establish exploitability, taint provenance, SQL safety, database security, runtime behavior, or application security.

## Purpose and authority boundary

`SEC-SAST-SQL-ALIAS-001` version `0.1.0` detects exactly one local Python statement sequence in a single lexical scope:

```python
query = f"SELECT * FROM accounts WHERE id = {account_id}"
aliased_query = query
cursor.execute(aliased_query)
```

The existing `SEC-SAST-001` remains unchanged. It covers a direct unsafe expression passed to `execute`/`executemany` and a direct unsafe query-name assignment passed to a standalone sink. The new control covers only the **one additional direct name-to-name alias** between an already recognized unsafe query construction and the sink. It does not alter historical rule IDs, versions, fingerprints, or policy behavior for `SEC-SAST-001`.

> **Only the versioned deterministic policy engine is a release authority.** A finding is bounded normalized evidence; an absent finding is not evidence that SQL is parameterized or safe.

The control is selected only by `rules/python-sql-single-alias-policy.yaml`. The default, strict, strict-CI, release-evidence, and external-adapter profiles do not select it implicitly.

## Exact recognized flow

| Step | Required AST-visible condition |
|---|---|
| Unsafe source | A simple name receives an f-string, `%` operation with a string literal left operand, or string-literal `.format(...)` call. |
| Single alias | A different simple name receives the source name through one ordinary assignment with exactly one target. |
| Sink | A standalone expression invokes `execute` or `executemany` with the alias name as first argument; an immediately awaited standalone call is also recognized. |
| Scope | The source assignment, alias assignment, and sink occur linearly within the same module, function, async function, or directly scanned class method body. |
| Normalized evidence | Construction category, sink category, flow label `single_local_name_alias`, source-relative path, and positive line only. |

If a tracked source name is reassigned to a safe/unsupported value before an alias is created, its source tracking is removed. When an alias is created, it captures the observed unsafe construction; a later source reassignment does not retroactively change that alias. Reassigning the alias itself clears it. If a skipped compound statement contains a store to a tracked source or alias name, tracking is invalidated rather than inferred.

## Deliberate exclusions

The control does not follow a second alias, imports, function/method calls or return values, attributes, subscripts, destructuring, tuple assignments, annotated assignments, augmented assignments, globals, nonlocals, closures, comprehensions, branches, loops, `try`, `with`, `match`, callbacks, non-standalone sinks, ORM APIs, parameter-binding semantics, database-driver behavior, user-input provenance, source reachability, or runtime values.

A query with `alias_two = alias_one`, an alias declared through `alias: str = query`, a query/alias created in a branch, or `return cursor.execute(alias)` is deliberately unsupported. These shapes receive no finding from this control, not a safety verdict.

## Policy and reports

A matching finding is `BLOCKER` severity and `HIGH` confidence because every required syntactic condition is present. The dedicated policy currently assigns `BLOCK`; policy selection and disposition remain versioned configuration decisions. Exact, expiry-bound waivers retain their existing behavior.

Before Deploy retains no query text, Python variable names, values, comments, source excerpts, database names, connection details, or raw AST. JSON, Markdown, and SARIF use the same normalized finding fields and cannot expose the source SQL string.

## Fixture matrix

| Fixture class | Expected behavior |
|---|---|
| Unsafe f-string query → one direct alias → `execute` | One `SEC-SAST-SQL-ALIAS-001` finding under the dedicated policy. |
| Parameterized query → one direct alias → `execute` | No finding. |
| Unsafe query overwritten by a parameterized query before aliasing | No finding. |
| Alias chain, branch assignment, or wrapped `return execute(...)` sink | No finding; each form is explicitly excluded. |
| Default policy on the vulnerable alias fixture | `PASS` for this rule because the new control is not selected implicitly. |
| Repository without Python source | Explicit `NOT_APPLICABLE` execution. |

## Reference

[1]: https://docs.python.org/3/library/ast.html "Python ast — abstract syntax trees"

# Python data-integrity control boundary

**Status:** Bounded deterministic control, version `0.1.0`.

`SEC-DATA-INTEGRITY-001` inspects Python AST only. It detects a direct call to a standalone `execute` or `executemany` method whose first argument is a literal SQL string beginning with `UPDATE` or `DELETE` and containing no `WHERE` token.

| Property | Contract |
|---|---|
| Policy | `python-data-integrity-policy.yaml` only; default and strict profiles remain unchanged. |
| Finding evidence | Constant `{artifact: python, issue: destructive_sql_without_where}` plus relative path and line. |
| Vulnerable shape | Direct literal SQL mutation passed to `execute`/`executemany`, without `WHERE`. |
| Safe shape | Literal `UPDATE` or `DELETE` containing `WHERE`. |
| Excluded shape | F-strings, `%` formatting, `.format()`, variables, aliases, attributes beyond the direct execute sink, calls, branches, ORM methods, migrations, schemas, runtime transactions, and all non-Python files. |
| Error behavior | Invalid Python is normalized by the orchestrator as a fail-closed control error. |

The control does not infer table names, query semantics, affected rows, transactions, authorization, tenant isolation, concurrency, database constraints, migrations, ORM behavior, or runtime execution. It never executes Python, SQL, the target application, package managers, Docker, scanners, or network requests.

Reports never retain SQL text, table names, column names, source excerpts, or target-controlled values. The policy engine remains the sole release authority.

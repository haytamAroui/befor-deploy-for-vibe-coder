# Next.js error-handling depth

`SEC-NEXT-ERROR-STACK-001` is a bounded static control for supported Next.js App Router Route Handler files.

It reports only a direct `catch (name)` flow where that same `name.stack` expression is passed inside `NextResponse.json(...)` or `Response.json(...)` in the catch block.

It does not infer exception-message sensitivity, aliases, helpers, custom response wrappers, Server Actions, pages, logging destinations, environment-specific rewriting, observability redaction, or deployed runtime behavior.

The control maps to `DOMAIN-ERROR-HANDLING-001` and `DOMAIN-SENSITIVE-DATA-001`. It is evidence for deterministic policy evaluation; it is not a release authority by itself.

# Minimal `find_callers` Experiment

PR42 deliberately implements the smallest dynamic-context hypothesis worth measuring.

The model has two possible actions:

```text
FINAL
FIND_CALLERS(symbol)
```

There is no generic repository search, file read, symbol lookup, dependency graph, test finder, shell, edit, patch, approval, verification, policy, or release tool.

`find_callers` is a bounded deterministic lexical observation over the canonical repository inventory. For each lexical call site it returns the repository-relative path, exact call line, and at most two nearby lines on each side. That context window is deliberately small but sufficient for the pilot to expose the caller action or an adjacent safety condition. It explicitly does **not** claim runtime reachability, type resolution, semantic equivalence, or interprocedural dataflow.

The index rejects symlinked files or path components before source bytes are read, and applies file-count, total-byte, per-file, result-count, result-byte, step, tool-call, and duration bounds.

Every initial context item and every caller observation receives a content hash and evidence ID. Final claims must cite only evidence actually exposed during that run.

Evidence dependency is derived by Before Deploy:

```text
initial_context_only   claim cites no caller observation
expanded_context_used  claim cites at least one find_callers observation
```

The model cannot set this label itself. Calling the tool without citing the result does not create exploration credit.

Static comparison runs use the same loop with `enable_find_callers=false`; a tool request in that mode fails the advisory run rather than silently widening context.

All output remains `AI_DISCOVERY_ADVISORY` with `gate_effect=NONE`. The experiment has no path to `PolicyDecision` or release disposition.

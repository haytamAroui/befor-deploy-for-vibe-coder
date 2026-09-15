# Caller Pilot v2 Corpus

This corpus expands the blinded caller benchmark without changing the `find_callers` tool contract or the PR43 STOP/GO thresholds.

## Scope

`fixtures/caller-pilot-v2` contains 24 balanced cases:

- 8 `STATIC-SUFFICIENT` cases where the defect is visible in the initial helper evidence;
- 8 `EXPLORATION-REQUIRED` cases where the helper is neutral and the hazardous use is visible only at a caller;
- 8 `FALSE-POSITIVE-TRAP` cases where caller context demonstrates a safe use that should not be reported.

The v2 expansion adds authorization, boundary-condition, password-policy, path traversal, open redirect, unsafe HTML, shell injection, parameterized SQL, header validation, bounded numeric input, and hostname allowlisting patterns.

Case IDs and source identifiers remain neutral and opaque. Class labels and defect IDs live only in evaluator metadata. The model-visible initial evidence remains limited to the declared source range, and the existing `find_callers` implementation remains the only optional expansion tool.

## Evidence status

The live GPT-5.6 Luna v1 pilot run remains a recorded `STOP`. This v2 corpus is implementation work only; it does not reinterpret that result and does not claim that exploration has been validated. The v1 corpus remains unchanged so the recorded run can be reproduced from its original commit.

The deferred final roadmap step may rerun the blinded comparison against v2 after the PR43 protocol/location issue is addressed.

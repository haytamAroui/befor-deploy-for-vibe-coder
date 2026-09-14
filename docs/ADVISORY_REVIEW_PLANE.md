# Advisory Review Plane

## Purpose

Before Deploy keeps two different kinds of reasoning separate:

1. **Deterministic assurance** — repository evidence, reviewed controls, coverage, policy, waivers, and the final `PolicyDecision`.
2. **Advisory review** — AI or third-party review findings that may help discover bugs, security concerns, performance problems, or maintainability issues.

Only the deterministic `PolicyDecision` is release authority. Advisory findings always carry:

```text
authority = ADVISORY
gate_effect = NONE
```

This is a structural invariant, not a prompt convention.

## `before-deploy review`

`review` runs the normal deterministic scan and optionally imports one or more advisory JSON files:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --advisory-file /tmp/ocr-result.json \
  --output-dir /tmp/before-deploy-review
```

The command writes the normal deterministic artifacts:

- `report.json`
- `report.md`
- `report.sarif`

and two unified developer-review artifacts:

- `review.json`
- `review.md`

The process exit code is derived from the deterministic `PolicyDecision` exactly as it is for `scan`. Imported advisory findings cannot add a block, remove a block, create a waiver, suppress a finding, or turn `ERROR` into `PASS`.

## OpenCodeReview ingestion

The advisory loader accepts OpenCodeReview JSON emitted by `ocr review --format json`. It supports a top-level array or the common object containers `comments`, `results`, and `issues`.

The importer intentionally retains only bounded review metadata:

- path
- start/end line
- content/message
- category
- severity
- optional confidence

It intentionally discards model-private or raw-code fields such as `thinking`, `existing_code`, and `suggestion_code`. Advisory message content remains untrusted and is not deterministic evidence.

## Canonical advisory schema

Other review providers can emit this small schema:

```json
{
  "source": {"provider": "example-reviewer"},
  "findings": [
    {
      "finding_id": "EXAMPLE-1",
      "title": "Possible transaction consistency bug",
      "message": "A debit can complete before a later credit fails.",
      "category": "bug",
      "severity": "high",
      "confidence": 0.91,
      "location": {
        "path": "src/payments.py",
        "start_line": 42,
        "end_line": 49
      }
    }
  ]
}
```

Accepted categories are `bug`, `security`, `performance`, `maintainability`, `test`, `style`, `documentation`, and `other`. Accepted severities are `critical`, `high`, `medium`, `low`, and `info`. Unknown values normalize conservatively to `other` / `info` rather than acquiring policy meaning.

## Correlation semantics

Phase 1 correlation is intentionally narrow. An advisory finding is correlated with deterministic findings only when their repository-relative source locations overlap.

A correlation means only:

> these findings refer to overlapping source lines

It does **not** mean the deterministic control proved the AI claim, that the AI confirmed the deterministic finding, or that the advisory finding gains release authority.

Future semantic correlation must remain equally explicit about its evidence contract.

## Architecture sources

This design borrows ideas rather than source code:

- OpenCodeReview's structured findings and deterministic review-selection philosophy inspired a normalized advisory plane.
- The Before Deploy Claude plugin's read-only/reporting boundary inspired the explicit `ADVISORY` / `gate_effect=NONE` contract.

No OpenCodeReview implementation code is copied into Before Deploy. This keeps Before Deploy's MIT codebase independent while allowing architectural learning from the Apache-2.0 project.

## Next increments

The intended sequence after this foundation is:

1. deterministic diff preview and explicit exclusion reasons;
2. isolated advisory provider execution with fixed arguments, timeouts, output-size bounds, and no policy mutation;
3. resumable review sessions and stable finding lifecycle (`open`, `fixed`, `dismissed`, `false_positive`);
4. bounded repository-context selection for AI review;
5. regression-test generation and human-approved remediation loops;
6. benchmark fixtures measuring precision, recall, F1, token use, latency, and fix verification separately for deterministic and advisory planes.

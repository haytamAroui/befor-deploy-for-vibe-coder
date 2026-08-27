# Requirements Evidence

**Status:** Bounded, deterministic diagnostic evidence. This document does not add a control, policy disposition, waiver path, scanner selection rule, implementation conclusion, or release authority.

## Purpose

The requirements-evidence collector reads only a small fixed set of repository documentation paths and emits a versioned signal when a reviewed lexical phrase family occurs. In version **0.2.0**, it can emit `REQUIREMENT-AUTHORIZATION` for a bounded authorization/access-control phrase family.

| Property | Contract |
|---|---|
| Signal ID | `REQUIREMENT-AUTHORIZATION` |
| Signal version | `0.2.0` |
| Signal kind | `REQUIREMENT` |
| Stored title | `Declared security domain: Authorization` |
| Stored metadata | Constant `classification=declared`, `domain=AUTHORIZATION` |
| Stored location | Relative path and first matching line only |
| Coverage result | `DECLARED_REVIEW_REQUIRED` |

## Accepted documentation and phrases

The collector examines a root `README.*`, or Markdown files named `architecture.md`, `design.md`, `requirements.md`, `spec.md`, or `specification.md`, as well as Markdown files beneath `docs/`. It reads at most 200,000 characters from each included document and processes files in deterministic inventory order.

The authorization signal matches case-insensitive forms of **authorization** and common verb inflections, `role-based access control`, `access control`, `RBAC`, `access control list`/`ACL`, and `permission-based access control`. A standalone reference to an HTTP `authorization header` is explicitly excluded because it is protocol terminology, not a declared access-control requirement.

## Deliberate exclusions

The signal does not read application source, dependency manifests, arbitrary `.txt` notes, generated files, remote documents, issue trackers, pull requests, tickets, wikis, deployments, identity providers, APIs, databases, containers, cloud accounts, or runtime traffic. It does not execute target code, commands, builds, tests, package managers, Docker, Compose, external scanners, or network requests.

It does not parse Markdown semantics, infer that a phrase is a requirement, resolve aliases, interpret policy language, distinguish users from services, identify tenant/object/function/property authorization, establish ownership checks, inspect routes or data flows, evaluate access-control correctness, or establish that a feature is implemented or secure.

The normalized signal never stores matching source text, document excerpts, document values, secret-like tokens, author names, interpretation, model output, or arbitrary prose. It retains only the constant ID/title/metadata and the relative path plus line number needed for review.

## Authority boundary

A requirements signal can add a diagnostic coverage expectation and result in `DECLARED_REVIEW_REQUIRED`. It cannot select a capability, control, adapter, tool, policy, or waiver; cannot create a finding; cannot suppress a finding; and cannot change `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`.

> `REQUIREMENT-AUTHORIZATION` means that bounded documentation contains a reviewed authorization/access-control phrase. It is not proof of an authorization implementation, feature existence, or security posture.

The deterministic versioned policy engine remains the sole release authority. A future AI consumer, if any, may receive only normalized redacted reports and cannot alter this boundary.

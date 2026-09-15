# Evidence Challenge

Evidence Challenge is a bounded semantic review layer for advisory findings. It exists to separate **structural citation validity** from an independent attempt to challenge whether the supplied evidence actually supports the claim.

The existing caller experiment records `supported_claim` and `citation_correct` after deterministic trace validation. Those fields mean that a claim cites evidence from its allowed execution trace; they are not an independent semantic proof. Evidence Challenge adds that missing semantic layer without changing deterministic release authority.

## Authority boundary

Every normalized challenge has:

- schema: `before-deploy-evidence-challenge-v1`
- authority: `AI_EVIDENCE_CHALLENGE_ADVISORY`
- gate effect: `NONE`

A challenge cannot change the original finding fingerprint, policy decision, scan result, release decision, branch state, deployment state, or waiver state. `SUPPORTED` means only that the challenger found no unresolved material objection under the supplied evidence. It does **not** convert an advisory finding into deterministic assurance.

## Verdicts

- `SUPPORTED` — the supplied evidence supports the challenged advisory claim and no unresolved objection is recorded.
- `INSUFFICIENT` — a material part of the claim is not established by the supplied evidence.
- `CONTRADICTED` — supplied evidence materially conflicts with the advisory claim.
- `UNRESOLVED` — the supplied evidence leaves the semantic question unresolved.

`INSUFFICIENT` and `CONTRADICTED` require at least one structured objection. `SUPPORTED` rejects unresolved objections.

## Evidence discipline

The normalized challenge retains only evidence IDs and SHA-256 content hashes. Model-authored challenge text may cite only evidence IDs explicitly supplied to the challenge operation. Unknown evidence IDs are rejected rather than silently accepted.

Objections are normalized into content-addressed `OBJ-*` identifiers. The full assessment is likewise content-addressed as `ECH-*` from the finding fingerprint, verdict, summary, evidence identities, and normalized objections. Re-running normalization over identical inputs produces the same identifiers.

This module does not expose repository search, shell access, editing, release verification, or any additional exploration tool. A future model adapter may author `EvidenceChallengeDraft` objects, but the deterministic normalizer remains responsible for trace boundaries and stable identity.

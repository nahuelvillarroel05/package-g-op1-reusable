# Prospective attribution ambiguity contract v1

Identity: `pgop1.swebench.attribution-ambiguity.v1`. Owner decision:
`ATTRIBUTION_CONTRACT_OPTION_2=APPROVED`. This is experimental English claim
engineering within `runtime/candidate/swebench_claim_audit/`; it supplies no
operational authority. Historical parser 1.11.0 and rejected 1.13.0 results keep
their original meanings. New behavior is `CONTRACT_VERSION_CHANGE`.

## Selection and compatibility

Select explicitly with `audit_evidence` request
`claim_attribution_contract="pgop1.swebench.attribution-ambiguity.v1"`.
Omitting the field preserves the historical contract and parser version.
Unknown contract selectors must fail closed. Current derivation and recovery
must retain and reapply the selector from committed bytes; no silent fallback
to a different contract is valid. The identity must be checked for preexisting
use before registration. Storage integrity and semantic validity remain separate.

## Ownership and claim state

Ownership describes the source's declared speaker, not an authenticated human
or model. A textual speaker label never authenticates identity. Existing parser
categories and state fields carry these conceptual classes without introducing
a second verdict engine:

| Conceptual class | Required consequence |
| --- | --- |
| DIRECT_ATTRIBUTED_CLAIM | Preserve predicate, polarity, source attribution and comparison eligibility. |
| QUOTED_THIRD_PARTY_CLAIM | Preserve excluded source-bound candidate; do not promote it to the agent's assertion. |
| UNATTRIBUTABLE_CONTENT | Preserve exclusion and its exact provenance/context reason. |
| AMBIGUOUS_ATTRIBUTION | Owner UNKNOWN; retain incompatible interpretations and candidate polarity separately from an asserted value. |
| EXPLICIT_RETRACTION | Preserve the retraction/exclusion and prevent comparison as an active assertion. |
| SUPERSEDED_CLAIM | Preserve original claim, correction relationship and replacement; compare only eligible active claims. |

The selected API uses existing `attribution_status` values `DIRECT`, `QUOTED`,
`UNKNOWN`, `RETRACTION`, `SUPERSEDED`, plus the new
`AMBIGUOUS_ATTRIBUTION` value. Existing `claim_state`, exclusion reason and
correction links distinguish the conceptual classes above. Ambiguous candidates
live in `CLAIM_REJECTIONS` and normalized `claim_rejection` observations; their
candidate polarity is not an asserted value. Missing message IDs remain UNKNOWN;
a source-declared ID remains unverified and is distinct from its JSON pointer.

Direct `I resolved the task.` and `I did not resolve the task.` remain distinct
positive and negative claims when the source supplies adequate declared speaker
provenance. Balanced unambiguous third-party quotation must remain excluded,
including an adjacent clear own assertion outside its closure. A correction is
not an ordinary active contradiction. Unknown ownership cannot hide an independently
accredited active contradiction.

## Conflict evidence and abstention

Ambiguity requires at least two plausible structural interpretations of the
same original predicate-bearing span with incompatible ownership or comparison
consequences. Punctuation, a semicolon, a first-person word, an unknown vocabulary
item or a parser exception alone is not conflict evidence.

Each ambiguity observation must bind the original source reference/SHA-256,
message pointer, matched text, character and UTF-8 byte half-open offsets,
content hash, predicate and candidate polarity. It must record the relevant
quote delimiters and report frame, alternative ownership assignments, available
evidence, exact incompatibility reason and consequence for comparison. Its owner
is `UNKNOWN`, its attribution status `AMBIGUOUS_ATTRIBUTION`, and its individual
verdict `INSUFFICIENT_EVIDENCE`. Neither SUPPORTED nor CONTRADICTED may be assigned
definitively to this unknown owner.

For the retained A-010 strings, an early terminal-looking apostrophe can close
a report locally, while a later delimiter can close an outer report containing
a typed quoted literal. If no qualified evidence distinguishes these parses,
the intervening apparent own claim remains an ambiguous candidate. Record the
actual delimiter positions. Do not decide from the shape of `movin`, `ready`,
`x` or other payload tokens.

Aggregate comparison retains ordinary evidence conflicts, source failures and
clear claim verdicts. If including versus excluding ambiguous candidates can
change an active comparison outcome, abstain with
`ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON` and explain the alternatives. If those
alternatives yield the same aggregate verdict, preserve that verdict and retain
the ambiguity observation. UNKNOWN must not become an unconditional aggregate
abstention policy. Historical boolean evidence matching and scope/time checks
remain in force.

Claims sharing one delimiter frame are correlated: the local-close interpretation
includes its eligible candidates together and the outer-close interpretation
excludes them together. Retraction, correction, temporal compatibility and other
eligibility rules apply within each interpretation. A possible correction must
not definitively supersede a clear claim while its owner remains unresolved.
The implementation bounds scenario propagation to 256 canonical active-claim
states. Exceeding that bound must produce an explicit verification error with
`ATTRIBUTION_SCENARIO_LIMIT`; it is not semantic evidence for UNKNOWN ownership.

## Integrity and bounded scope

Original bytes are immutable. Decoded message offsets are Unicode codepoint
offsets and UTF-8 offsets into that message; source pointers locate the message
within the committed source, and are not claimed to be raw JSON file offsets.
Any normalization must retain a verifiable mapping back to these positions.
Do not associate a span with different content or conflate duplicate content
from distinct source identities. Hashes authenticate byte consistency, not speaker
identity or semantic truth.

Context Engine must admit original sources and source-bound observations,
preserve the exact audit capsule, and recover them in a fresh process. Repeated
semantic derivation from admitted bytes proves reproducibility only. Existing
`UNAUTHENTICATED` and `SEMANTIC_VALIDATION_NOT_PROVEN` qualifiers remain applicable.
No Engine validation may be relaxed for this contract.

This is a bounded deterministic extension of the existing claim grammar, not
general natural-language understanding, independent semantic holdout qualification,
Linux validation, Formal I7 completion or Physical C2 authorization. Material
counterexamples block acceptance and require a fresh prospective candidate and
independent review; negative observations remain preserved.

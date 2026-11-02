# Prospective attribution ambiguity contract v2

Identity: `pgop1.swebench.attribution-ambiguity.v2`. This selector opts into a
bounded English grammar extension for Sonnet findings F-01, F-02, F-03 and F-06.
It is experimental claim engineering under `runtime/candidate/`; it grants no
operational authority. It is not general natural-language understanding and
does not establish semantic precision, recall, or qualification.

## Selection and compatibility

Select explicitly on `audit_evidence` with
`claim_attribution_contract="pgop1.swebench.attribution-ambiguity.v2"`, or on
`audit_file` with the same registered selector in its descriptor. Unknown
selectors fail closed. Omission preserves the historical legacy behavior.
Selecting v1 preserves the v1 semantics and output path; v2 is a new contract
identity and must be retained in audit derivation and Context Engine recovery.
The v1 contract remains [here](ATTRIBUTION_AMBIGUITY_V1.md).

V2 reuses the existing bounded extraction, quote masking, attribution conflict
analysis, correlated scenario propagation, source binding, temporal
compatibility, and aggregation safeguards. It does not replace those safeguards
with a second verdict engine. Source roles remain declared and unauthenticated.

## Bounded semantic rules

### Retraction and correction (F-01)

Recognized same-message forms include bounded pronoun-targeted corrections such
as `Actually, I didn't resolve it.`, `That is false.`, `I retract that.`,
`I take that back.`, and `Scratch that.` Cross-message explicit retraction
events use the same trajectory source and link to the latest compatible prior
claim under the existing temporal and declared-speaker scope rules. Events
retain source pointer, matched text, character and UTF-8 byte spans, content
hash, source hash, and target binding.

Generic correction language such as `I was wrong.` has no reliable target in
this grammar. It produces a source-bound `RETRACTION_UNRESOLVED` event and
candidate target alternatives. Possible targets are marked uncertain and do
not receive a definitive verdict. A pronoun such as `it` or `that` must bind to
a compatible source-bound prior task claim; without one it is a recognized but
unsupported form. An explicit correction with a bound prior claim retains the
replacement as a comparable `RESOLVED_CORRECTION`. This does not retract
unrelated claims.
Quoted, coded, interrogative, conditional, and reported text continues through
the existing exclusion and attribution analysis.

### Polarity and unsupported forms (F-02)

The registered subset recognizes selected contractions (`haven't`, `didn't`,
`couldn't`), `failed to resolve`, bound pronoun objects (`it`, `that`), and
affirmative do-support (`I did resolve the task`). Future modality such as
`won't resolve` is recognized as unsupported rather than treated as a factual
negative. The forms are bounded to the listed task predicates and syntax.
Unrecognized wording remains outside this grammar; no recall claim is implied.

### Temporal state scope (F-03)

Impersonal state sentences are comparable only when explicitly marked
`Final outcome:` in this grammar, for example `Final outcome: The task is
resolved.` or `Final outcome: The task is unresolved.` Bare state sentences and
intermediate states such as `The task is still unresolved; let me investigate.`
are preserved as `TEMPORAL_SCOPE_UNKNOWN` or
`INTERMEDIATE_STATE_ASSERTION` rejections. Final issue/bug states are tagged
`NONCOMPARABLE_STATE` because the boolean evaluator only binds task resolution.
This keeps supported and contradicted controls available for explicitly final
task states while avoiding definitive comparison of an unscoped or intermediate
status.

### Grammar coverage (F-06)

The v2 task-success grammar accepts `I resolved the task successfully.` and
the existing present/past task-resolution forms, including the bounded clause
`I resolved the task, and the tests pass.` The test-result tail is syntax
coverage only. V2 does not infer task success from a standalone `the tests
pass` statement.

## Source-bound status fields

Claims and rejection rows expose named semantic statuses alongside the
existing exact source pointer, character span, UTF-8 span, and content hash:

- `SUPPORTED_CLAIM_FORM`, `RECOGNIZED_BUT_UNSUPPORTED_FORM`,
  `UNATTRIBUTABLE_CONTENT`, and `NO_CLAIM` describe grammar/attribution scope.
- `EXPLICIT_RETRACTION`, `RESOLVED_CORRECTION`, `RETRACTION_UNRESOLVED`, and
  `NO_RETRACTION` distinguish target resolution outcomes.
- `FINAL_OUTCOME_ASSERTION`, `INTERMEDIATE_STATE_ASSERTION`,
  `TEMPORAL_SCOPE_UNKNOWN`, and `NONCOMPARABLE_STATE` describe temporal and
  comparison scope.

`NO_CLAIM` is message scoped and binds the whole message. Other statuses bind
the specific matched span. These are parser classifications, not semantic
truth or speaker authentication.

## Decision and limitations

### Review corrections and uncertainty alternatives

Only complete declarative retraction cues are effective. Questions such as
`I retract that?` and cues qualified by another subject or a condition do not
withdraw an earlier clear assertion. `Wait,` admits affirmative and negative
corrections symmetrically under v2.

A pronoun does not select its own predicate. Before binding `it` or `that`,
the parser retains prior compatible task and issue resolution mentions in the
same declared trajectory scope, including a nearby mention excluded as a possible
correction. Competing subject predicates yield source-bound antecedent
alternatives and `RETRACTION_UNRESOLVED`; the task claim may not receive a
definitive individual verdict. A single compatible subject retains decisive
correction behavior. These are bounded resolution-subject rules, not general
pronoun understanding.

The existing comparison scenario engine includes the retained interpretation
and each source-bound target alternative for unresolved cues. Generic retraction
uncertainty does not silently delete its possible target in every scenario.
Unanimous aggregate outcomes remain decisive, including when another unaffected
claim establishes the same outcome. Divergent outcomes abstain with an explicit
uncertainty reason. The existing 256-state bound and verification-error stop
apply; exceeding that bound supplies no semantic evidence.

For the recognized positive collective, passive and emphasis forms, and bare
states of unknown temporal scope, the parser can retain a candidate polarity
without asserting it. The same scenario engine compares eligible and excluded
interpretations when that difference can change the aggregate. Unknown wording
is never assigned a negative value. Questions, quotes, code, conditions,
intermediate states and reported content retain their exclusion guards.

Overlapping v2 patterns emit an identical per-message span/interpretation only
once. This preserves Context Engine's duplicate-identity rejection; observations
with different spans, interpretations or source identities are not merged.

Same-message generic uncertainty retains its original claim as a possible
active assertion, with an exact cue span/hash and target link, before scenario
comparison. It is not discarded during extraction. Complete declarative cues
may introduce an explanation with a colon; comma-qualified cues preserve target
uncertainty. Predicate-bearing corrections use predicate-specific supersession
instead of withdrawing whichever unrelated claim happens to be nearest.

Intermediate-state markers are read from the state's own clause and its bounded
investigation continuation. A marker in another sentence or a quoted span does
not accredit that state's timing. `Currently` alone is not proof of an
intermediate or final outcome. Positive and negative state variants share the
existing bounded state-link grammar; explicit `Final outcome:` remains required
for a definitive individual final-state comparison.

`Still` in the state's own clause is an intermediate marker under this bounded
contract. It must not leak from an unrelated clause. An earlier intermediate
state does not conflict with a later explicitly marked final outcome.

Only source-bound direct assertions with supported grammar and attribution can
be compared. Ambiguous attribution, unresolved retraction, unknown temporal
scope, non-comparable predicates, or unsupported forms remain visible in
rejection/evidence records and may result in abstention when they affect the
comparison. Clear independent assertions continue to be evaluated under the
existing aggregate rules. Questions, third-party report frames, nested quotes,
Markdown quotes, and code continue to use the existing structural exclusions.

The contract is limited to deterministic patterns and tested English examples.
Tests are engineering regressions, not an independent semantic holdout. V2
does not authorize a campaign, model use, GOLD access, `src/` promotion, merge,
or advancement of I0-I7 or Physical C2 state.

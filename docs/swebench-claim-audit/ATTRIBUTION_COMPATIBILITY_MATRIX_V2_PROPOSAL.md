# Attribution contract compatibility matrix proposal

This proposal describes selectors in the experimental claim adapter. It does
not change frozen campaign interpretation or provide authority to select a
contract for a campaign.

| Behavior | No selector (legacy) | Explicit v1 | Explicit v2 |
| --- | --- | --- | --- |
| Contract identity | Omitted | `pgop1.swebench.attribution-ambiguity.v1` | `pgop1.swebench.attribution-ambiguity.v2` |
| Intended use | Historical compatibility | Structural attribution ambiguity contract | Bounded F-01/F-02/F-03/F-06 grammar extension |
| Default selection | Yes when omitted | No | No |
| Unknown selector | N/A | Fail closed | Fail closed |
| Quote/report ambiguity | Historical parser behavior | Existing conflict/scenario safeguards | Same v1 safeguards reused |
| Retraction | Historical parser behavior | Narrow explicit retraction forms | Bounded pronouns/contractions; generic target unresolved |
| Negation | Historical grammar | Existing v1 grammar | Selected contractions and forms; unsupported wording stays bounded |
| Impersonal state | Historical parser behavior | Existing v1 grammar | `Final outcome:` required for comparable task state |
| Postposed `successfully` | Historical parser behavior | Existing v1 grammar | Explicit task-resolution form accepted |
| Qualification | None implied | None implied | None implied |

V2 source-bound row classifications include `SUPPORTED_CLAIM_FORM`,
`RECOGNIZED_BUT_UNSUPPORTED_FORM`, `UNATTRIBUTABLE_CONTENT`, and `NO_CLAIM`;
retraction classifications include `EXPLICIT_RETRACTION`,
`RESOLVED_CORRECTION`, `RETRACTION_UNRESOLVED`, and `NO_RETRACTION`; state
classifications include `FINAL_OUTCOME_ASSERTION`,
`INTERMEDIATE_STATE_ASSERTION`, `TEMPORAL_SCOPE_UNKNOWN`, and
`NONCOMPARABLE_STATE`. Every match row retains the source pointer and exact
character/UTF-8 spans, while `NO_CLAIM` binds the full message.

Compatibility requirements:

1. An omitted selector must not silently become v1 or v2.
2. Existing v1 outputs and campaign evidence retain their original meaning.
3. V2 identity must survive source parsing, request derivation, capsule storage,
   fresh-process recovery, and re-derivation.
4. Unknown selectors fail closed in both file-level and instance-level APIs.
5. Tests and this matrix establish only bounded implementation behavior, not
   general accuracy or independent qualification.

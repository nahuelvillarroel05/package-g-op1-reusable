# Publication status — campaign 001

Recorded 2026-11-07 UTC. This addendum distinguishes Owner confirmation from the current Codex network attempt.

## Owner-confirmed historical release

| Field | Value |
| --- | --- |
| Branch | `experiment` |
| Published historical commit | `0f708ce34ef3422b85567d05c4ea35c9c7ab0311` |
| `main` observed at Owner check | `b2483bed23be2ccbcdcc1e5e4c8e26943758b874` |
| Confirmation source | Owner's PowerShell `git ls-remote --heads origin experiment main` output |
| Confirmation time | `OWNER_REPORTED_TIME_NOT_RECORDED` |
| Scope | Public Git publication of the documented campaign snapshot; not new validation or formal certification |

The release manifest's earlier `PENDING_OWNER_MANUAL_PUSH` field is a **historical snapshot**, not a statement about the current remote branch. This addendum records a later publication event. It does not rewrite the frozen original records.

## Codex remote check

At **2026-11-07T04:09:54.7752874Z**, Codex attempted `git ls-remote --heads origin experiment main` with interactive prompting disabled. The query failed: `schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS (0x8009030e)`. No remote heads were returned. No authentication or credential repair was attempted. The two historical remote references above are **Owner-reported**, not independently confirmed by Codex; the Owner confirmation timestamp is not available.

The local pre-change `experiment` HEAD was `0f708ce34ef3422b85567d05c4ea35c9c7ab0311`, tree `7b7b9df5d26d07eb5e5570016ec2c8ccd291a505`. Local ancestry does not establish the current remote head. Recheck both remote branches before manual publication; reconcile unexpected advancement without rewriting history.

## New documentation-only commit

The changes that add this page and improve navigation are a **separate local candidate**, not yet published by Codex. Until the Owner manually pushes and verifies the new commit, mark:

`PRESENTATION_UPDATE=LOCAL_COMMIT_PENDING_OWNER_MANUAL_PUSH`

## Boundaries

`EXPOSURE_STATUS=UNKNOWN` · `HISTORICAL_GLOBAL_INTEGRITY=DEFERRED` · `SEMANTIC_IMPROVEMENT=NOT_DEMONSTRATED`.

This update is visible on `experiment` after manual publication. The default GitHub page still shows `main`; this intervention does not change that branch or the default branch.

[Campaign overview](CAMPAIGN_OVERVIEW.md) · [Historical release manifest](PUBLIC_RELEASE_MANIFEST.json) · [Experiments index](../../README.md)

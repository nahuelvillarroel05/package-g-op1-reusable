# Transcript attribution contract v1

`pgop1.swebench.transcript.role_export.v1` accepts only the explicit
`pgop1.swebench.transcript-role-export.v1` JSON envelope. The export binds a
run ID, instance ID, nonempty scope, timezone-qualified ISO timestamp, embedded
source text commitment, message IDs, declared speaker labels, byte spans, and
span SHA-256 values. The parser verifies the embedded source hash and every
span hash. It rejects missing or conflicting bindings and malformed spans.

The result is `transcript_attribution` metadata. Its speaker value is explicitly
`SOURCE_DECLARED_UNVERIFIED`, with `SOURCE_DECLARED_NOT_AUTHENTICATED` as the
attribution label. The format proves that the export's declarations are bound
to its committed text; it does not prove that the speaker identity is true,
that the exporter is trusted, or that any message is semantically correct.
No claims are extracted from this parser. Existing Aider Markdown remains
structural and unattributed. Every normalized attribution record includes the
source ID/hash, transcript format, message ID, `speaker_role=UNKNOWN`, separate
`declared_speaker`, speaker provenance and verification level, content hash and
span where available, and `claim_predicate=NONE`.

For native MiniSwe trajectory JSON, the additive
`pgop1.swebench.trajectory.miniswe_role_attribution.v1` parser reads only
top-level messages and emits content hashes plus JSON-pointer message IDs. It
requires request/descriptor run and instance binding, plus explicit scope and
timezone-qualified timestamp on the descriptor. An embedded conflicting run
ID or instance mismatch is rejected. Nested response payloads are never
treated as assistant messages. Root or per-message `agent_id`, `agent_ids`, or
`speaker_id` without a verified scope mapping causes legacy claim extraction to
abstain. Indented code is excluded by the legacy
claim parser. Caller-supplied scope/time bindings are recorded as such and do
not establish transcript event time. This parser also emits no claims; the
legacy parser implementation is prospectively hardened and versioned 1.0.1.
Every top-level message object emits one attribution record, including null or
non-string content, which receives a canonical content hash and
`NON_TEXT_UNSUPPORTED` status. A missing content field is retained as
`CONTENT_MISSING`; a non-object message row rejects the trajectory.

The role export is bounded by existing JSON, source text, and observation limits.
Export-relative offsets are UTF-8 byte offsets, half-open `[start, end)` spans.
Run and instance bindings must agree with the audit request/descriptor. Scope
and timestamp declarations must match the caller binding; they are retained
with distinct declared and caller fields and do not establish actual event time.
Unknown or unavailable
identity facts must remain unknown; callers must not relabel this metadata as
cryptographic authentication.

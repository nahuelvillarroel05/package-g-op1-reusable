# RUN004 lessons applied prospectively to RUN005

RUN004 is closed: 4,510 processed definitions; 5,586 not attempted units; semantic audits 0; reproducible defects 3. Neither attempt is redispatched or rewritten.

E1-D01 was already prospectively corrected to use the returned receipt SHA256. RUN005 adds a reusable physical-reference validator checking persisted receipt bytes and ownership identity, with substitution controls.

E1-D02 preflight was already integrated in the current CLI. A real fresh subprocess CLI recovered V2 authored evidence after mandatory preflight, retained completed/pending membership and unchanged store hashes, and rejected checkpoint tampering. The historical omitted-preflight API call was reproduced as a failure. E1 recovery no longer performs a writer-budget global scan per batch; write-path allocation checks remain.

E1-D03 already had grouped Git archive verification. RUN005 reuses only the comparison against immutable committed bytes within a Campaign. It still rehashes live metadata, code and source commitments and checks Git identity/status on preflight. Same-size substitutions with restored timestamps are rejected. Comparable component measurements, their process counts and limits are preserved in engineering/GIT_VERIFICATION_PERFORMANCE.json.

Focused controls: 79 passed. These authored development controls establish bounded regression evidence; they do not count as authentic outputs, semantic audits, independent custody or formal qualification. RUN005 candidate identity and campaign outcomes are separate artifacts controlled by the parent workflow.

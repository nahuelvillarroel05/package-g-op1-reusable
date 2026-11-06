# Defects and prospective corrections

E1-D01: attempt001 wrapper hashed the receipt summary. Original writers remain immutable; a corrected index rehashes actual journal receipt bytes. E1-D02: recovery CLI omitted preflight; explicit frozen-code preflight plus read-only recovery verified the journal. E1-D03: repeated per-file Git subprocesses caused large overhead; prospective code verifies identical committed bytes in one in-memory archive.

Attempt002 uses separate code/freeze, correct receipt pointers and recovery, exact prior-completion exclusions and bounded per-batch output allocation. No completed001 unit was redispatched. All negative and failed preparation records remain private continuity evidence.

# Security

This is experimental software without certified security or operational qualification. Do not place secrets or protected operational data in public issues or fixtures. Report a potential issue privately to the repository owner through an available GitHub private vulnerability channel; if unavailable, request a private contact without disclosing sensitive details.

MCP exposes fixed tools, with workspace/path and argument checks; the local runtime does execute pinned Python subprocesses. Its checks do not certify machine-wide confinement. The independent client's urllib proxy/redirect behavior is a documented limitation. Use the exact dependency lock and disposable synthetic workspaces. No private corpus policy, native authority or model weights are distributed.

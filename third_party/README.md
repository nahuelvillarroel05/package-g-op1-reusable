# External dependencies

No dependency source, virtual environment, model weights or runtime binary is vendored. Install the exact public MCP lock in `mcp/INSTALL_FREEZE.txt`. The core uses jsonschema and cryptography; MCP additionally uses mcp/mcp-types, Pydantic, AnyIO and the transitive packages in that lock. Each dependency keeps its own license. Publication audit records observed package license metadata separately from historical environments; the old runtime's cryptography 46.0.7 record is not the publication environment's cryptography 50.0.2.

Package-G's `runtime/candidate/deps` contains reused first-party project modules, not a third-party SDK bundle. Do not infer license ownership from its directory name. See `manifests/DEPENDENCY_LICENSES.json` for the audited installed dependency set.

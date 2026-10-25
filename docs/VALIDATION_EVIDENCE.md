# Validation evidence

Three result classes remain separate:

* `PUBLIC_SOURCE_REPRODUCIBILITY`: fresh tests of a clean copy of this selected public tree, with documented Python dependencies.
* `MCP_TRANSPORT_SMOKE_TEST`: genuine SDK handshake, ten-tool enumeration, synthetic pipeline, read-only query/graph/provenance/verify/recover and negative argument/path checks.
* `HISTORICAL_ENGINEERING_EVIDENCE`: inherited version-bound original records identified by hashes, not rerun.

Run tests from a disposable fresh checkout: `python -B tests/smoke_stdio.py` creates an isolated workspace under `runtime/campaigns` and refuses to overwrite its timing evidence. Use another fresh checkout for another run. No model or GGUF is needed. `python -B tests/test_run_ref_boundaries.py` checks read-only identifier boundaries. The publication audit also checks explicit private-policy denial and unavailable formal-fixture provenance.

Private original corpus/native evidence and model benchmarks are not publicly reproducible from this source tree. The I2 expected-hash limitation remains documented. Snapshot integrity does not establish independent custody.

The selected historical core tests use `PYTHONPATH=src` in their own process; do not keep that import root in the MCP process. Install `tests/requirements.txt`, then run `python -B -m pytest -p no:cacheprovider --basetemp <short-disposable-test-directory> -q tests/unit`. The storage contract rejects paths beyond 239 UTF-16 units, so use short checkout and temporary paths. `tests/conftest.py` transparently redirects only `Path.home()` during tests to that pytest basetemp, preserving all frozen source/test bytes and assertions while keeping synthetic home/key/NTFS fixtures inside the selected test directory. Synthetic NTFS/reparse tests exercise disposable files; they do not dispatch the original protected I3 runtime or qualify operational custody.

The full original I0 artifact-provenance test depends on the original repository HEAD and complete historical membership, including intentionally omitted components. It is excluded explicitly from this detached selected source distribution rather than presented as freshly passing.

The first broad publication core run passed 282 tests and failed 49 I2 tests because the Git blob of the synthetic executor uses LF, while its unchanged frozen isolation profile requires the historical Windows CRLF SHA-256. The public tree now uses the exact reviewed CRLF bytes recovered from the original worktree; it preserves the Git-blob identity separately. This changes no source text and weakens no pin. The failed run remains in the private publication audit; the corrected source has a separate fresh test result.

# SPDX-License-Identifier: Apache-2.0
"""Keep inherited synthetic home-directory fixtures inside pytest's temp root.

The frozen test/source bytes are unchanged. This publication harness substitutes
only Path.home for the duration of each test, so disposable synthetic NTFS/key
fixtures stay under the explicitly selected pytest basetemp on the D drive.
"""
from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def synthetic_home_directory(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.getbasetemp() / 'home'
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))

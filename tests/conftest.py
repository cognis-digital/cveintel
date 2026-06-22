"""Shared pytest fixtures.

The bundled vuln DB has ~262k records; loading + indexing it per test is slow.
Provide a session-scoped, pre-indexed VulnDB so corpus-backed tests reuse one
instance instead of re-reading the gz each time.
"""

from __future__ import annotations

import pytest

from cveintel.vulndb_local import VulnDB


@pytest.fixture(scope="session")
def shared_db() -> VulnDB:
    db = VulnDB()
    db.load()
    db._index()  # build indexes once
    return db

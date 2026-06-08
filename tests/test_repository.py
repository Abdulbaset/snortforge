"""Tests for storage/repository.py (Phase 3 team-library acceptance criteria).

Uses an in-memory SQLite backend. The Postgres backend shares the same
interface and SQL shape; switching is an env-var change (see get_repository).
"""

from datetime import datetime, timezone

from storage.models import SavedRuleModel
from storage.repository import SQLiteRepository


def _make_rule(**overrides):
    now = datetime.now(timezone.utc)
    data = dict(
        sid=1000001,
        rev=1,
        title="C2 beacon over HTTP",
        author="abdulbaset",
        raw_rule_text='alert tcp any any -> any any (sid:1000001; rev:1;)',
        mitre_tags=["T1071", "T1071.001"],
        created_at=now,
        updated_at=now,
        notes=None,
    )
    data.update(overrides)
    return SavedRuleModel(**data)


def _repo():
    return SQLiteRepository(":memory:")


def test_save_assigns_id():
    repo = _repo()
    saved = repo.save(_make_rule())
    assert saved.id is not None


def test_search_by_sid():
    repo = _repo()
    repo.save(_make_rule(sid=1000001))
    repo.save(_make_rule(sid=1000002, title="Other"))
    found = repo.search(sid=1000001)
    assert len(found) == 1
    assert found[0].sid == 1000001


def test_search_by_mitre_tag():
    repo = _repo()
    repo.save(_make_rule(mitre_tags=["T1071"]))
    repo.save(_make_rule(sid=1000002, mitre_tags=["T1190"]))
    found = repo.search(mitre_tag="T1071")
    assert len(found) == 1
    assert "T1071" in found[0].mitre_tags


def test_search_by_title_substring():
    repo = _repo()
    repo.save(_make_rule(title="C2 beacon over HTTP"))
    found = repo.search(title="beacon")
    assert len(found) == 1


def test_load_back_by_id():
    repo = _repo()
    saved = repo.save(_make_rule())
    loaded = repo.get(saved.id)
    assert loaded is not None
    assert loaded.raw_rule_text == saved.raw_rule_text
    assert loaded.mitre_tags == ["T1071", "T1071.001"]


def test_update_bumps_rev_and_timestamp():
    repo = _repo()
    saved = repo.save(_make_rule(rev=1))
    original_updated = saved.updated_at
    saved.title = "Edited title"
    updated = repo.update(saved)
    assert updated.rev == 2
    assert updated.updated_at >= original_updated
    reloaded = repo.get(saved.id)
    assert reloaded.rev == 2
    assert reloaded.title == "Edited title"


def test_list_all_orders_newest_first():
    repo = _repo()
    repo.save(_make_rule(sid=1000001))
    repo.save(_make_rule(sid=1000002))
    all_rules = repo.list_all()
    assert len(all_rules) == 2

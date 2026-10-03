"""Negative skill data stays inert in the repository and genuine in scanner tests."""

from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.skill_directory_discovery import discover_skill_documents
from tests import e2e_droid_exec
from tests.skill_fixture_support import (
    MALICIOUS_SKILL_DOCUMENT,
    MALICIOUS_SKILL_FIXTURE,
    PROJECT_ROOT,
    materialize_malicious_skill_plugin,
)


def test_malicious_fixture_is_not_a_discoverable_skill():
    # Covers recursive filename discovery as well as directly targeted discovery.
    assert not list(MALICIOUS_SKILL_FIXTURE.rglob("SKILL.md"))
    for root in (
        MALICIOUS_SKILL_FIXTURE,
        MALICIOUS_SKILL_FIXTURE / "skills",
        MALICIOUS_SKILL_FIXTURE / MALICIOUS_SKILL_DOCUMENT.parent,
    ):
        discovery = discover_skill_documents(root)
        assert discovery.documents == ()
        assert discovery.issues == ()


def test_materialized_fixture_preserves_original_bytes_and_skill_discovery(tmp_path):
    plugin = materialize_malicious_skill_plugin(tmp_path / "malicious-skill-plugin")
    document = plugin / MALICIOUS_SKILL_DOCUMENT
    stored = (MALICIOUS_SKILL_FIXTURE / MALICIOUS_SKILL_DOCUMENT).with_name("SKILL.md.fixture")
    assert document.read_bytes() == stored.read_bytes()
    # Pin the original negative fixture, independently of the materializer.
    assert (
        sha256(document.read_bytes()).hexdigest() == "d20efe664b21ba348745399bc8edb45e0c175199c184d2226a6661b3b70b3ab0"
    )
    discovery = discover_skill_documents(plugin / "skills")
    assert discovery.documents == (document,)
    assert discovery.issues == ()


def test_materializer_refuses_to_restore_a_public_repository_skill():
    with pytest.raises(ValueError, match="outside the repository"):
        materialize_malicious_skill_plugin(MALICIOUS_SKILL_FIXTURE)


def test_headless_scanner_materializes_and_removes_temporary_skill(monkeypatch):
    documents: list[Path] = []

    def inspect_scanner_input(plugin):
        document = plugin / MALICIOUS_SKILL_DOCUMENT
        assert not plugin.resolve().is_relative_to(PROJECT_ROOT)
        assert discover_skill_documents(plugin / "skills").documents == (document,)
        assert (
            sha256(document.read_bytes()).hexdigest()
            == "d20efe664b21ba348745399bc8edb45e0c175199c184d2226a6661b3b70b3ab0"
        )
        documents.append(document)
        return []

    monkeypatch.setattr(e2e_droid_exec, "_test_scanner", inspect_scanner_input)
    assert e2e_droid_exec.test_scanner() == []
    assert len(documents) == 1
    assert not documents[0].exists()


@pytest.mark.parametrize(
    "relative_root",
    [
        ".factory/skills/hol-guard",
        "docs/guard",
        "integrations/claude-code-plugin/skills/setup",
        "integrations/claude-code-plugin/skills/status",
        "tests/fixtures/good-plugin/skills/example",
        "tests/fixtures/hermes-plugin-evil/skills/security/malicious",
    ],
)
def test_other_skills_and_fixtures_remain_discoverable(relative_root):
    root = PROJECT_ROOT / relative_root
    discovery = discover_skill_documents(root)
    assert discovery.documents == (root / "SKILL.md",)
    assert discovery.issues == ()

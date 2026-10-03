"""Tests for data-only PR gating and safe evidence transport."""
from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile

import pytest

from ci.gauntlet.bundle import download, pack, unpack
from ci.gauntlet.github_ci import initialize_gate, requires_gauntlet
from ci.gauntlet.source_identity import validate_identity


@pytest.mark.parametrize("path", ["rust/crates/guard-command/src/pretool.rs",
                                     "src/codex_plugin_scanner/guard/adapters/pi_extension_source.py",
                                     "contracts/guard-hooks.json", "ci/gauntlet/evidence.py",
                                     ".github/workflows/guard-gauntlet-evidence.yml", "uv.lock"])
def test_enforcement_and_qualification_changes_require_live_evidence(path):
    assert requires_gauntlet([path])


def test_unrelated_documentation_does_not_require_a_new_product_run():
    assert not requires_gauntlet(["README.md", "docs/marketing.md"])


class MetadataAPI:
    def __init__(self, rows, count):
        self.rows, self.count, self.statuses = rows, count, []

    def pull(self, number, sha):
        assert number == 1 and sha == "a" * 40
        return {"changed_files": self.count}

    def request(self, path):
        assert path == "/pulls/1/files?per_page=100&page=1"
        return self.rows

    def status(self, *args):
        self.statuses.append(args)


def test_renaming_enforcement_out_of_the_scoped_directory_still_requires_evidence():
    api = MetadataAPI([{"filename": "retired.txt", "previous_filename": "rust/crates/guard-command/src/pretool.rs"}], 1)
    initialize_gate(api, {"inputs": {"pr_number": "1", "candidate_sha": "a" * 40}})
    assert api.statuses[0][1] == "pending"


def test_incomplete_file_inventory_cannot_waive_the_gate():
    api = MetadataAPI([{"filename": "README.md"}], 2)
    with pytest.raises(ValueError, match="incomplete"):
        initialize_gate(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})
    assert not api.statuses


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as result:
        for name, body in entries:
            result.writestr(name, body)
    return buffer.getvalue()


def test_public_evidence_roundtrip(tmp_path):
    source = tmp_path / "source"
    (source / "cases").mkdir(parents=True)
    (source / "summary.json").write_text(json.dumps({"schema": "unit-fixture"}))
    (source / "cases/ordinary.json").write_text("{}")
    output = tmp_path / "evidence.zip"
    digest = pack(source, output)
    unpack(output.read_bytes(), tmp_path / "restored", digest)
    assert (tmp_path / "restored/cases/ordinary.json").read_text() == "{}"


@pytest.mark.parametrize("name", ["../outside.json", "/absolute.json", "raw-prompts.json", "runner.py", "cases\\bad.json"])
def test_archive_never_extracts_code_private_logs_or_path_traversal(tmp_path, name):
    data = archive([("summary.json", "{}"), (name, "bad")])
    with pytest.raises(ValueError, match="unsafe"):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    assert not (tmp_path / "extracted").exists()


def test_archive_digest_and_symlinks_are_verified(tmp_path):
    info = zipfile.ZipInfo("cases/link.json")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    data = archive([("summary.json", "{}"), (info, "../../outside")])
    with pytest.raises(ValueError):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match="digest"):
        unpack(data, tmp_path / "other", "0" * 64)


@pytest.mark.parametrize("url", ["http://localhost/bundle.zip", "https://127.0.0.1/bundle.zip",
                                    "https://example.com/bundle.zip", "https://u:p@test.s3.amazonaws.com/bundle.zip"])
def test_evidence_downloader_rejects_internal_or_unapproved_origins(url):
    with pytest.raises(ValueError):
        download(url)


def test_exact_candidate_or_current_test_merge_is_required():
    candidate, base, source = "a" * 40, "b" * 40, "c" * 40
    report = {"candidate_sha": candidate, "tested_source_sha": source, "installed_source_sha": source,
              "source_parents": [base, candidate], "tested_base_sha": base}
    validate_identity(report, expected_sha=candidate, expected_base_sha=base)
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate, expected_base_sha="d" * 40)
    report["source_parents"] = [base]
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate)

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


@pytest.mark.parametrize(
    "path",
    [
        "rust/crates/guard-command/src/pretool.rs",
        "src/codex_plugin_scanner/guard/adapters/pi_extension_source.py",
        "contracts/guard-hooks.json",
        "ci/gauntlet/evidence.py",
        ".github/workflows/guard-gauntlet-evidence.yml",
        "uv.lock",
    ],
)
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


@pytest.mark.parametrize(
    "name", ["../outside.json", "/absolute.json", "raw-prompts.json", "runner.py", "cases\\bad.json"]
)
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


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/bundle.zip",
        "https://127.0.0.1/bundle.zip",
        "https://example.com/bundle.zip",
        "https://u:p@test.s3.amazonaws.com/bundle.zip",
    ],
)
def test_evidence_downloader_rejects_internal_or_unapproved_origins(url):
    with pytest.raises(ValueError):
        download(url)


def test_exact_candidate_or_current_test_merge_is_required():
    candidate, base, source = "a" * 40, "b" * 40, "c" * 40
    report = {
        "source_dirty": False,
        "candidate_sha": candidate,
        "tested_source_sha": source,
        "installed_source_sha": source,
        "source_parents": [base, candidate],
        "tested_base_sha": base,
    }
    validate_identity(report, expected_sha=candidate, expected_base_sha=base)
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate, expected_base_sha="d" * 40)
    report["source_parents"] = [base]
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate)


class QualifiedAPI(MetadataAPI):
    repo = "hashgraph-online/hol-guard"

    def __init__(self):
        super().__init__([{"filename": "rust/crates/guard-command/src/pretool.rs"}], 1)
        self.state = "success"
        self.conclusion = "success"
        self.path = ".github/workflows/guard-gauntlet-evidence.yml"
        self.artifact = "guard-gauntlet-" + "a" * 40

    def request(self, path):
        if path.startswith("/pulls/"):
            return self.rows
        if "/statuses?" in path:
            return [
                {
                    "context": "Guard Gauntlet",
                    "state": self.state,
                    "target_url": "https://github.com/" + self.repo + "/actions/runs/123",
                }
            ]
        if "/artifacts?" in path:
            return {"artifacts": [{"name": self.artifact, "expired": False}]}
        if path == "/actions/runs/123":
            return {
                "event": "workflow_dispatch",
                "conclusion": self.conclusion,
                "path": self.path,
                "head_repository": {"full_name": self.repo},
            }
        raise AssertionError(path)


def test_required_ci_accepts_only_successful_real_evidence_producer():
    from ci.gauntlet.pr_requirement import require_evidence

    require_evidence(QualifiedAPI(), {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "pending"),
        ("conclusion", None),
        ("path", ".github/workflows/unrelated.yml"),
        ("artifact", "guard-gauntlet-" + "b" * 40),
    ],
)
def test_required_ci_rejects_status_without_matching_successful_producer(field, value):
    from ci.gauntlet.pr_requirement import require_evidence

    api = QualifiedAPI()
    setattr(api, field, value)
    with pytest.raises(RuntimeError):
        require_evidence(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


@pytest.mark.parametrize("dirty", [True, None])
def test_identity_rejects_dirty_or_unrecorded_worktrees(dirty):
    report = {
        "candidate_sha": "a" * 40,
        "tested_source_sha": "a" * 40,
        "installed_source_sha": "a" * 40,
        "source_parents": ["b" * 40],
        "tested_base_sha": None,
        "source_dirty": dirty,
    }
    with pytest.raises(ValueError, match="dirty"):
        validate_identity(report, expected_sha="a" * 40)


def test_immutable_source_manifest_hashes_api_blobs_without_checkout():
    import base64

    from ci.gauntlet.github_source import source_manifest

    class API:
        def request(self, path):
            if path.startswith("/git/commits/"):
                return {"sha": "a" * 40, "parents": [{"sha": "b" * 40}]}
            if path.startswith("/contents/ci/gauntlet?"):
                return [{"name": "runner.py", "path": "ci/gauntlet/runner.py", "type": "file", "sha": "c" * 40}]
            if path.startswith("/contents/ci/pi-exact-continuation/"):
                return {"path": "ci/pi-exact-continuation/package-lock.json", "type": "file", "sha": "d" * 40}
            if path.startswith("/git/blobs/"):
                raw = b"immutable source bytes"
                return {
                    "sha": path.rsplit("/", 1)[1],
                    "encoding": "base64",
                    "size": len(raw),
                    "content": base64.b64encode(raw).decode(),
                }
            raise AssertionError(path)

    manifest = source_manifest(API(), "a" * 40, "a" * 40)
    assert manifest["runner_files"] == {"runner.py": hashlib.sha256(b"immutable source bytes").hexdigest()}
    assert manifest["source_parents"] == ["b" * 40]


def test_public_bundle_can_be_submitted_inline_without_storage_credentials(tmp_path):
    from ci.gauntlet.submission import inline_dispatch_inputs, submitted_archive

    path = tmp_path / "evidence.zip"
    path.write_bytes(archive([("summary.json", "{}")]))
    inputs = inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=True)
    assert submitted_archive(inputs) == path.read_bytes()
    assert len(json.dumps(inputs)) < 60000
    with pytest.raises(ValueError):
        inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=False)


@pytest.mark.parametrize(
    "inputs",
    [
        {},
        {"evidence_base64": "bad!"},
        {"evidence_base64": "AAAA", "evidence_url": "https://example.com"},
        {"evidence_base64": "A" * 55001},
    ],
)
def test_inline_submission_rejects_ambiguous_malformed_or_oversized_data(inputs):
    from ci.gauntlet.submission import submitted_archive

    with pytest.raises(ValueError):
        submitted_archive(inputs)


@pytest.mark.parametrize("parents", [["b" * 40], ["b" * 40, "c" * 40], ["bad-parent"], [None]])
def test_github_manifest_rejects_unrelated_or_malformed_parentage_before_reading_blobs(parents):
    from ci.gauntlet.github_source import source_manifest

    class API:
        def request(self, path):
            assert path == "/git/commits/" + "d" * 40
            return {"sha": "d" * 40, "parents": [{"sha": p} for p in parents]}

    with pytest.raises(ValueError):
        source_manifest(API(), "d" * 40, "a" * 40)

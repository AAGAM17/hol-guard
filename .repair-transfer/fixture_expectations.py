"""Transfer three exact tested source changes; no repository refs are changed."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).with_name('consumer_fix.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

EXPECTED = {
    'tests/support/extension_freshness.py': '4f16400acde38f36934ac0d05e31f054874377a8',
    'tests/test_pending_extension_base.py': '92fdea11a05e9903d3e762fb349010383d52057a',
    'tests/test_generated_cli_uivoid_extension.py': '0bb2d5a19273ccea8f8a508288eeee2461d17588',
}


def transform(path, text):
    if path.endswith('/extension_freshness.py'):
        start = text.index('def pending_decision_diff_regen() -> bool:')
        end = text.index('\n\ndef pending_native_projection_regen()',start)
        text = text[:start] + '''def pending_decision_diff_regen() -> bool:
    """Current decision evidence is evaluated per run and must never be skipped.

    Retained for callers of the former fixture-freshness marker. Source-only
    changes and unavailable Git history do not exempt behavioral evaluation.
    """
    return False
''' + text[end:]
        return text.replace('reason="decision-diff report is regen-owned; enforced after maintainer regeneration",',
                            'reason="current decision evidence has no regeneration exemption",')
    if path.endswith('/test_pending_extension_base.py'):
        start = text.index('def test_pending_decision_diff_marker(')
        return text[:start] + '''@pytest.mark.parametrize("event", ["pull_request", "push", "workflow_dispatch"])
@pytest.mark.parametrize("pending", [False, True])
def test_current_decision_evidence_never_defers_to_regeneration(monkeypatch, event, pending):
    """Freshness markers cannot exempt current behavioral evidence on any ref."""
    import tests.support.extension_freshness as freshness

    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setattr(freshness, "pending_contribution_regen", lambda: pending)
    monkeypatch.setattr(freshness, "_pr_diff_paths", lambda: pytest.fail("current evidence must not consult Git"))
    assert freshness.pending_decision_diff_regen() is False
'''
    text = t.replace_once(text,
        '    assert build["trust"] == json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text())',
        '''    canonical_trust = json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text())
    assert build["trust"]["schemaVersion"] == canonical_trust["schemaVersion"]
    assert build["trust"]["publishers"] == canonical_trust["publishers"]
    # Only the fixture's sources determine its trust contract. Another
    # contributor joining the catalog must not rewrite this behavioral fixture.
    for extension_id in ids:
        assert _trust_classes(build["trust"], extension_id) == _trust_classes(canonical_trust, extension_id)
''')
    needle = 'def test_uivoid_portable_fixture_binds_canonical_sources() -> None:'
    text = t.replace_once(text,needle,'''def _trust_classes(trust: dict, extension_id: str) -> tuple[str, ...]:
    classes = tuple(name for name, ids in trust["classes"].items() if extension_id in ids)
    assert len(classes) == 1, "each fixture source needs exactly one reviewed trust class"
    return classes


'''+needle)
    return text + '''

@pytest.mark.parametrize("change", ["missing", "duplicate", "promoted"])
def test_uivoid_fixture_trust_rejects_missing_ambiguous_or_promoted_identity(change: str) -> None:
    fixture_trust = json.loads(_FIXTURE_PATH.read_text())["build"]["trust"]
    canonical = json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text())
    identity = "command.uivoid"
    if change != "duplicate":
        fixture_trust["classes"]["external"].remove(identity)
    if change != "missing":
        fixture_trust["classes"]["first-party"].append(identity)
    with pytest.raises(AssertionError):
        assert _trust_classes(fixture_trust, identity) == _trust_classes(canonical, identity)
'''


def main():
    t.run(['git','fetch','--no-tags','--depth=1','origin',t.BASE])
    for path,expected in EXPECTED.items():
        original = t.run(['git','show',t.BASE+':'+path]).decode()
        content = t.run(['python3','-m','ruff','format','--stdin-filename',path,'-'],transform(path,original).encode())
        actual = t.hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        assert actual == expected, (path,expected,actual)
        result = t.json.loads(t.run(['gh','api','--method','POST',f'repos/{t.REPO}/git/blobs','--input','-'],
            t.json.dumps({'content':content.decode(),'encoding':'utf-8'}).encode()))
        assert result['sha'] == expected
        print(expected,path,flush=True)
    print('All three snapshot isolation repairs match the tested files; no refs changed.',flush=True)

if __name__ == '__main__':
    main()

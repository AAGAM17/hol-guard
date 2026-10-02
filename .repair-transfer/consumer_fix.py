"""Upload exact locally checked source blobs. No refs, merges or releases."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO = 'hashgraph-online/hol-guard'
BASE = '22a8b12617e64d9c8bd7e02e698865df26c3c20b'
EXPECTED = {
'.github/workflows/cline-contract-ci.yml':'dc5aafa6fcd9b6771ff18ed7293046445d90000e',
'.github/workflows/rust-authority-ownership.yml':'fa605d9d9546ec73265e00f42a75dbeeb5e93a14',
'.github/workflows/rust-command-model-differential.yml':'7fa330c8d93c3a10a3388aac58d152301ec38503',
'.github/workflows/rust-command-shadow.yml':'dce624285c47deb40ab8ae4b7af92bb7d991d3ca',
'.github/workflows/rust-daemon-edge-hardening.yml':'1e9fffc50882732455dfa93cd26bff631dca5ec7',
'.github/workflows/rust-posttool-authority-acceptance.yml':'9e28d9d707865078457628a274aebb1b63b4da48',
'.github/workflows/rust-pretool-adversarial.yml':'9d2f544354f0f8de8fd5de794f289430f82e6e81',
'.github/workflows/rust-pretool-authority-acceptance.yml':'3dc4a81cb6bdd1e573808f74d1020c25b6efc950',
'.github/workflows/rust-runtime-differential.yml':'ca6a1dfe1de984ba3e53517950c85ed0208c62aa',
'.github/workflows/rust-runtime-mutation-differential.yml':'259e937aeaafd6385cb2788aeb86de162e8f6e63',
'.github/workflows/rust-runtime-performance.yml':'79aaeb9efc5976a8c108ff0ba6bc312bee2bc341',
'.github/workflows/rust-runtime-recovery.yml':'91522f7e016822833bae278fc35da7264de56fe6',
'.github/workflows/rust-runtime-rule-contract.yml':'69611767a5dc81cd2f4252909ea8b8fe3172f5c6',
'.github/workflows/rust-runtime-windows-resident.yml':'b7d0ce4210b861e6286f5eb1c2ea07533c6e0f79',
'.github/workflows/rust-runtime.yml':'36f276968f5c5c9be8eee1dd8ea30eaf28bbb254',
'rust/build_support/command_identity.rs':'7f951684fa0076bb9fd29b0c1587a6de2e154c79',
'rust/crates/guard-command/src/native_command_source.rs':'6f133d36843b1922ed4ec01157edc7c17bd80b69',
'rust/crates/guard-command/src/native_command_source_catalog.rs':'fa4261bc41c64c637b28450c72078351680b17e5',
'rust/crates/guard-command/src/native_command_source_fixtures.rs':'e4b0ade9576a78d721c724793e1c3a6f0f81ddd3',
'scripts/ci/verify_native_command_program.py':'487a09450f79173659f1f0d4d6cb2c65c61d8265',
'scripts/ci/check_extension_fixture_isolation.py':'938bdc50b57ee3248b871d71d2748496bea4d4bf',
}


def run(command, payload=None):
    return subprocess.run(command, input=payload, capture_output=True, check=True, timeout=90).stdout


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old,new)


def transform(path, text):
    if path.startswith('.github/workflows/'):
        original = 'cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime'
        new = original + ' -p guard-command --bin hol-guard-runtime --bin guard-command-source'
        output = []
        count = 0
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if stripped not in {original, 'run: '+original}:
                output.append(line)
                continue
            count += 1
            indent = line[:len(line)-len(line.lstrip())]
            if stripped.startswith('run:'):
                output.append(indent+'run: |\n')
                indent += '  '
            output.append(indent+new+'\n')
            powershell = '$env:' in ''.join(output[-8:])
            if powershell:
                output.append(indent+'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n')
            compiler = 'rust/target/release/guard-command-source'+('.exe' if powershell else '')
            if not path.endswith('rust-runtime-rule-contract.yml'):
                output.append(indent+'uv run --no-sync python scripts/ci/verify_native_command_program.py --compiler '+compiler+'\n')
        assert count >= 1
        text = ''.join(output)
        if path.endswith('rust-runtime-rule-contract.yml'):
            text = replace_once(text, '          cargo build --manifest-path rust/Cargo.toml --locked --release -p guard-command --bin guard-command-source\n','')
        return text
    if path.endswith('command_identity.rs'):
        return replace_once(text,'    println!("cargo:rerun-if-changed={}", root.join("crates").display());\n',
            '    // Cargo manifests and each production src directory below are watched.\n'
            '    // Watching the entire crates directory would also invalidate this build\n'
            '    // for portable test fixtures, recreating the fixture/recompile cycle.\n')
    if path.endswith('native_command_source.rs'):
        text = replace_once(text,'#[path = "native_command_source_fixtures.rs"]\nmod fixtures;',
            '#[path = "native_command_source_fixture_catalog.rs"]\nmod fixture_catalog;\n#[path = "native_command_source_fixtures.rs"]\nmod fixtures;')
        text = replace_once(text,"pub fn compile_build_request(bytes: &[u8]) -> Result<CompiledSourceCatalog, &'static str> {",
            "pub fn compile_build_request(bytes: &[u8]) -> Result<CompiledSourceCatalog, &'static str> {\n"
            '    compile_owned_request(bytes, false)\n}\n\n'
            "fn compile_fixture_build_request(bytes: &[u8]) -> Result<CompiledSourceCatalog, &'static str> {\n"
            '    compile_owned_request(bytes, true)\n}\n\n'
            'fn compile_owned_request(\n    bytes: &[u8],\n    fixture: bool,\n'
            ") -> Result<CompiledSourceCatalog, &'static str> {")
        old = '        Some(BaseProgram::Packaged) => compile_addition_with_mcp(&borrowed, &mcp_borrowed, &trust),'
        return replace_once(text,old,
            '        Some(BaseProgram::Packaged) if fixture => {\n'
            '            fixture_catalog::compile_fixture_addition(&borrowed, &mcp_borrowed, &trust)\n'
            '        }\n'+old)
    if path.endswith('native_command_source_catalog.rs'):
        return replace_once(text,'fn lower_catalog(', 'pub(super) fn lower_catalog(')
    if path.endswith('native_command_source_fixtures.rs'):
        return replace_once(text,'let output = compile_build_request(', 'let output = compile_fixture_build_request(')
    if path.endswith('verify_native_command_program.py'):
        return replace_once(text,'    args = parser.parse_args()\n',
            '    args = parser.parse_args()\n    if sys.platform == "win32" and not Path(args.compiler).suffix:\n        args.compiler += ".exe"\n')
    if path.endswith('check_extension_fixture_isolation.py'):
        return run(['python3','-m','ruff','format','--stdin-filename',path,'-'],text.encode()).decode()
    raise RuntimeError(path)


def main():
    run(['git','fetch','--no-tags','--depth=1','origin',BASE])
    for path, expected in EXPECTED.items():
        if path.endswith('check_extension_fixture_isolation.py'):
            data = json.loads(run(['gh','api',f'repos/{REPO}/git/blobs/17105e44b571a1d0f5c3b9ae229f93719af1593c']))
            original = base64.b64decode(data['content']).decode()
        else:
            original = run(['git','show',BASE+':'+path]).decode()
        content = transform(path,original).encode()
        actual = hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        assert actual == expected, (path,expected,actual)
        result = json.loads(run(['gh','api','--method','POST',f'repos/{REPO}/git/blobs','--input','-'],
            json.dumps({'content':content.decode(),'encoding':'utf-8'}).encode()))
        assert result['sha'] == expected
        print(expected,path,flush=True)
    print('All 21 reviewed source blobs uploaded. No refs were changed.',flush=True)


if __name__ == '__main__':
    main()

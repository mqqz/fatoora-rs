"""Routing regressions for workflow-level path filters (no GitHub credentials)."""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {
    path.stem: yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    for path in (ROOT / '.github/workflows').glob('*.yml')
}


def matches(path, pattern):
    """Match the *, ** and **/ subset used by these workflow paths."""
    tokens = re.split(r'(\*\*/|\*\*|\*)', pattern)
    expressions = {'**/': '(?:.*/)?', '**': '.*', '*': '[^/]*'}
    return re.fullmatch(''.join(expressions.get(t, re.escape(t)) for t in tokens), path) is not None


def selected(path, event='pull_request'):
    return {
        name for name, workflow in WORKFLOWS.items()
        if event in workflow['on']
        and any(matches(path, pattern) for pattern in workflow['on'][event].get('paths', []))
    }


class WorkflowPaths(unittest.TestCase):
    def test_matcher_handles_root_and_nested_paths(self):
        self.assertTrue(matches('Cargo.toml', '**/Cargo.toml'))
        self.assertTrue(matches('scripts/probe/Cargo.toml', '**/Cargo.toml'))
        self.assertTrue(matches('bindings/js/examples/demo.mjs', 'bindings/*/examples/**'))
        self.assertFalse(matches('bindings/js/nested/examples/demo.mjs', 'bindings/*/examples/**'))
        self.assertFalse(matches('docs/README.md', 'README.md'))

    def test_docs_do_not_start_package_builds(self):
        for path in ['docs/index.md', 'docs/reference/qr.md', 'docs/assets/examples/c/signing.c', 'mkdocs.yml']:
            with self.subTest(path=path):
                self.assertEqual(selected(path), {'docs'})
                self.assertEqual(selected(path, 'push'), {'docs'})
        self.assertEqual(selected('CONTRIBUTING.md'), set())

    def test_language_only_edits(self):
        cases = {
            'bindings/python/fatoora/api.py': {'python'},
            'bindings/js/index.mjs': {'javascript'},
            'bindings/dotnet/tests/Program.cs': {'dotnet'},
            'bindings/kotlin/src/main/kotlin/Runtime.kt': {'kotlin'},
            'scripts/package_dotnet.py': {'dotnet', 'rust'},
            'scripts/build_kotlin.py': {'kotlin', 'rust'},
            'scripts/check_dotnet_linux.py': {'dotnet', 'kotlin', 'rust'},
            'scripts/check_wasm_size.py': {'javascript', 'rust'},
            'fuzz/seeds/xml_parse/malformed.xml': {'fuzz'},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(selected(path), expected)

    def test_core_and_bridge_changes_reach_consumers(self):
        consumers = {'rust', 'python', 'javascript', 'dotnet', 'kotlin', 'release'}
        for path in ['fatoora-core/src/invoice.rs', 'fatoora-core/assets/schema.xsd', 'fatoora-derive/src/lib.rs']:
            self.assertEqual(selected(path), consumers | {'fuzz'})
        self.assertEqual(selected('fatoora-ffi/src/crypto.rs'), consumers)
        self.assertEqual(selected('fatoora-cli/src/main.rs'), {'rust', 'release'})

    def test_release_metadata_reaches_every_checker(self):
        expected = {name for name, workflow in WORKFLOWS.items() if 'scripts/check_release.py' in str(workflow['jobs'])}
        for path in [
            'Cargo.toml', 'Cargo.lock', 'fatoora-cli/Cargo.toml',
            'fuzz/Cargo.lock', 'scripts/xsd-compat/Cargo.lock',
            'bindings/python/pyproject.toml', 'bindings/python/uv.lock',
            'bindings/js/package.json', 'bindings/js/package-lock.json',
            'bindings/dotnet/Fatoora.csproj', 'bindings/kotlin/build.gradle.kts',
        ]:
            with self.subTest(path=path):
                self.assertTrue(expected <= selected(path), expected - selected(path))

    def test_generated_bindings_reach_combined_checks(self):
        for path in [
            'bindings/c/fatoora.h', 'bindings/c/generated/Config.h',
            'bindings/cpp/fatoora/Config.hpp', 'bindings/python/native/generated/Config.cpp',
            'bindings/js/generated/Config.mjs', 'bindings/dotnet/generated/Config.cs',
            'bindings/kotlin/generated/facade/com/fatoora/Config.kt',
            'scripts/generate_bindings.py', 'scripts/generate_c_facade.py',
            'scripts/generate_dotnet.py', 'scripts/generate_kotlin.py',
            'scripts/install_dotnet_generator.py', 'scripts/install_kotlin_generator.py',
            'scripts/patches/diplomat-kotlin.patch', 'scripts/c_facade_runtime.c',
            'scripts/js-wasm.mjs',
        ]:
            with self.subTest(path=path):
                self.assertTrue({'rust', 'javascript'} <= selected(path))

    def test_docs_follow_included_examples_and_c_headers(self):
        for page in (ROOT / 'docs').rglob('*.md'):
            for snippet in re.findall(r'--8<--\s*"([^":]+)', page.read_text()):
                with self.subTest(snippet=snippet):
                    self.assertIn('docs', selected(snippet))
        self.assertIn('docs', selected('bindings/c/generated/Xml.h'))
        self.assertIn('docs', selected('scripts/check_c_reference.py'))
        self.assertNotIn('scripts/check_c_reference.py', str(WORKFLOWS['rust']['jobs']))

    def test_referenced_scripts_trigger_their_workflow(self):
        for name, workflow in WORKFLOWS.items():
            for script in re.findall(r'\bscripts/[\w/-]+\.py', str(workflow['jobs'])):
                with self.subTest(workflow=name, script=script):
                    self.assertIn(name, selected(script))

    def test_each_workflow_and_both_event_filters_stay_covered(self):
        for name, workflow in WORKFLOWS.items():
            events = workflow['on']
            self.assertIn('workflow_dispatch', events, name)
            for event in ('pull_request', 'push'):
                if event not in events or (event == 'push' and name == 'release'):
                    continue
                paths = events[event]['paths']
                self.assertTrue(paths, (name, event))
                self.assertIn(name, selected(f'.github/workflows/{name}.yml', event))
                # Keep matching semantics limited to this test's supported subset.
                self.assertFalse(any(re.search(r'[!?+\[\]]', p) for p in paths))
            if 'push' in events and 'pull_request' in events and name != 'release':
                self.assertEqual(events['push']['paths'], events['pull_request']['paths'], name)

    def test_publication_events_remain_unfiltered(self):
        for name in ('rust', 'python', 'javascript', 'dotnet', 'kotlin', 'release'):
            # GitHub ignores push.paths on tag pushes. Manual dispatch has no paths.
            self.assertEqual(WORKFLOWS[name]['on']['push']['tags'], ['v*'])
            self.assertNotIn('paths', WORKFLOWS[name]['on']['workflow_dispatch'] or {})
        self.assertNotIn('branches', WORKFLOWS['release']['on']['push'])

    def test_docs_deploy_is_not_available_to_pull_requests(self):
        workflow = WORKFLOWS['docs']
        self.assertEqual(workflow['permissions']['contents'], 'read')
        deploy = workflow['jobs']['deploy']
        self.assertEqual(deploy['needs'], 'validate')
        self.assertIn("github.ref == 'refs/heads/main'", deploy['if'])
        self.assertIn("github.event_name != 'pull_request'", deploy['if'])
        self.assertEqual(deploy['permissions']['contents'], 'write')


if __name__ == '__main__':
    unittest.main()

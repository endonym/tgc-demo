"""Regression checks use synthetic data and temporary directories only."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import evidence
from guards import require


class PreparationProvenance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.runs = Path(temporary.name)
        (self.runs/'result.json').write_text('{"result":"confirmed"}')
        self.inputs = {'demo/src/lib.rs': 'source-before', 'kernel/src/v1.rs': 'kernel-before'}
        self.binaries = {'demo': 'executable-before'}
        for name, value in [('preparation_inputs', self.inputs), ('preparation_binaries', self.binaries)]:
            mock = patch.object(evidence, name, side_effect=lambda value=value: dict(value))
            mock.start()
            self.addCleanup(mock.stop)

    def seal(self):
        return evidence.seal_preparation(self.runs, dict(self.inputs))

    def test_unchanged_run_is_reusable(self):
        record = self.seal()
        self.assertEqual(evidence.verify_preparation(self.runs), record)

    def test_legacy_run_is_not_retroactively_fingerprinted(self):
        with self.assertRaisesRegex(ValueError, 'no preparation provenance'):
            evidence.verify_preparation(self.runs)
        self.assertFalse((self.runs/evidence.PREPARATION_RECORD).exists())

    def test_changed_source_or_kernel_or_tool_is_rejected(self):
        self.seal()
        for name in ['demo/src/lib.rs', 'kernel/src/v1.rs', 'demo/tools/dx/evidence.py']:
            original = dict(self.inputs)
            self.inputs[name] = 'changed'
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'sources differ'):
                evidence.verify_preparation(self.runs)
            self.inputs.clear()
            self.inputs.update(original)

    def test_changed_executable_is_rejected(self):
        self.seal()
        self.binaries['demo'] = 'other-executable'
        with self.assertRaisesRegex(ValueError, 'executables differ'):
            evidence.verify_preparation(self.runs)

    def test_changed_added_or_missing_output_is_rejected(self):
        self.seal()
        output = self.runs/'result.json'
        original = output.read_bytes()
        for mutation in ['changed', 'missing', 'added']:
            if mutation == 'changed':
                output.write_text('{}')
            elif mutation == 'missing':
                output.unlink()
            else:
                (self.runs/'extra.txt').write_text('extra')
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'outputs changed'):
                evidence.verify_preparation(self.runs)
            output.write_bytes(original)
            (self.runs/'extra.txt').unlink(missing_ok=True)

    def test_changed_inputs_cannot_be_sealed(self):
        original = dict(self.inputs)
        self.inputs['demo/src/lib.rs'] = 'changed-during-run'
        with self.assertRaisesRegex(ValueError, 'changed during preparation'):
            evidence.seal_preparation(self.runs, original)
        self.assertFalse((self.runs/evidence.PREPARATION_RECORD).exists())

    def test_seal_is_create_only(self):
        self.seal()
        before = (self.runs/evidence.PREPARATION_RECORD).read_bytes()
        with self.assertRaises(FileExistsError):
            self.seal()
        self.assertEqual((self.runs/evidence.PREPARATION_RECORD).read_bytes(), before)

    def test_prepare_refuses_existing_recordings_before_running_commands(self):
        with patch.object(evidence, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'new run directory'):
                evidence.prepare(self.runs)
            command.assert_not_called()


class OptimisationAndHistory(unittest.TestCase):
    def test_operational_checks_survive_optimisation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'evidence').mkdir()
            (root/'evidence/record.json').write_text('{}')
            (root/'evidence-index.json').write_text(json.dumps({'files': {'record.json': 'wrong-hash'}}))
            snippets = [
                'from guards import require; require(False, "guard active")',
                'import evidence; evidence.no_private({"nested":[{"secret":"synthetic"}]})',
                f'from check_evidence import check_evidence; from pathlib import Path; check_evidence(Path({str(root)!r}))',
                f'import evidence; from pathlib import Path; evidence.verify_preparation(Path({str(root)!r}))',
            ]
            for snippet in snippets:
                result = subprocess.run([sys.executable, '-O', '-B', '-c', snippet],
                    cwd=Path(__file__).parent, capture_output=True, text=True,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertNotEqual(result.returncode, 0, snippet)
                self.assertIn('ValueError', result.stderr)

    def test_validation_runner_final_check_survives_optimisation(self):
        source = ast.parse((evidence.ROOT/'tools/verify.py').read_text())
        check = source.body[-1]
        self.assertIsInstance(check, ast.Expr)
        self.assertEqual(check.value.func.id, 'require')
        for key in ['all_commands_pass', 'inputs_unchanged_during_run', 'kernel_sources_match']:
            summary = dict.fromkeys(['all_commands_pass', 'inputs_unchanged_during_run', 'kernel_sources_match'], True)
            summary[key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                eval(compile(ast.Expression(check.value), '<runner-check>', 'eval', optimize=2),
                    {'require': require, 'summary': summary})

    def test_original_kernel_hashes_are_not_replaced_with_current_hashes(self):
        manifest = evidence.read(evidence.ROOT/'vendor/kernel-source.json')
        originals = {
            'src/host_conformance.rs': 'eabdf9376269848b9cb888fbff8352691afa3e1ed8a3877f916db6882ed9cb9f',
            'src/v1.rs': 'c469aef2476285eafe3522c5382bee8c912eb6b3098bd17953858ab0a7e2447d',
        }
        for name, original in originals.items():
            self.assertEqual(manifest['original_snapshot']['files'][name], original)
            current = hashlib.sha256((evidence.ROOT/'vendor/constitutive-action'/name).read_bytes()).hexdigest()
            self.assertEqual(manifest['files'][name], current)
            self.assertNotEqual(current, original)


if __name__ == '__main__':
    unittest.main()

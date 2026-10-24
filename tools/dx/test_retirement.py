"""Evidence-only boundary regressions; no real website or Rust runs are written."""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence

class EvidenceOnly(unittest.TestCase):
 def test_retired_export_refuses_old_cli_without_writes(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary)
   for flags in [[], ['--prepare-only'], ['--fresh']]:
    result=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('export.py')),
                           '--site',str(root/'site'),'--runs',str(root/'runs'),*flags],
                          capture_output=True,text=True)
    self.assertNotEqual(result.returncode,0)
    self.assertIn('retired',result.stderr)
    self.assertEqual(list(root.iterdir()),[])

 def test_retired_export_has_no_generation_api(self):
  spec=importlib.util.spec_from_file_location('retired_export',Path(__file__).with_name('export.py'))
  module=importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  for name in ['install_site','public_docs','kernel_docs','prepare']:
   self.assertFalse(hasattr(module,name))

 def test_evidence_cli_has_no_site_option(self):
  with tempfile.TemporaryDirectory() as temporary:
   result=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('evidence.py')),
                          'collect','--runs',temporary,'--out',str(Path(temporary)/'out'),
                          '--site',str(Path(temporary)/'www')],capture_output=True,text=True)
   self.assertNotEqual(result.returncode,0)
   self.assertIn('unrecognized arguments',result.stderr)
   self.assertEqual(list(Path(temporary).iterdir()),[])

 def test_existing_collection_is_untouched(self):
  with tempfile.TemporaryDirectory() as temporary:
   out=Path(temporary)/'evidence';out.mkdir()
   (out/'keep').write_text('restored')
   with patch.object(evidence,'verify_preparation') as verify:
    with self.assertRaisesRegex(ValueError,'new output directory'):
     evidence.collect(Path(temporary)/'runs',out)
    verify.assert_not_called()
   self.assertEqual((out/'keep').read_text(),'restored')

 def test_website_outputs_are_refused_before_execution(self):
  out=evidence.ROOT.parent/'TheGenerativeCommons/www/new-evidence'
  with patch.object(evidence,'command') as command, patch.object(evidence,'verify_preparation') as verify:
   with self.assertRaisesRegex(ValueError,'outside the website'):evidence.prepare(out)
   with self.assertRaisesRegex(ValueError,'outside the website'):evidence.collect(Path('/tmp/runs'),out)
   command.assert_not_called();verify.assert_not_called()

 def test_symlink_parent_refused(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);(root/'actual').mkdir();(root/'alias').symlink_to(root/'actual',target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'Symlink output refused'):
    evidence.local_output(root/'alias/out')

 def test_collection_cannot_modify_preparation_tree(self):
  with tempfile.TemporaryDirectory() as temporary:
   runs=Path(temporary)
   with self.assertRaisesRegex(ValueError,'must be separate'):
    evidence.collect(runs,runs/'collected')

 def test_generator_assets_are_removed(self):
  root=Path(__file__).parent
  for name in ['pages.py','staging.py','web/dx.js','web/dx.css','web/chapters.json']:
   self.assertFalse((root/name).exists(),name)

if __name__=='__main__':unittest.main()

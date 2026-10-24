"""Archive-free evidence collection regression tests; all output stays in temporary dirs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import evidence
from check_evidence import check_evidence


class ArchiveFreeEvidence(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)
  self.out=self.root/'evidence-output'
  self.data=self.out
  self.data.mkdir(parents=True)
  self.runs=self.root/'runs'
  case=self.runs/'coverage-cases/crash-example'
  case.mkdir(parents=True)
  self.record=b'{"result": "confirmed"}\n'
  (case/'result.json').write_bytes(self.record)
  (case/'run.stdout').write_text(str(evidence.ROOT.parent)+'/local/path\n')
  (case/'inputs.tar.gz').write_bytes(b'not public')
  for name in ['test-results.txt','kernel-test-results.txt']:
   (self.runs/name).write_text('test result: ok. 1 passed\n')

 def publish(self):
  return evidence.collect_regressions(self.out,self.runs)

 def test_individual_records_and_hashes(self):
  inventory=self.publish()
  self.assertEqual(check_evidence(self.data),inventory)
  record=self.data/'evidence/cases/crash-example/result.json'
  self.assertEqual(record.read_bytes(),self.record)
  self.assertEqual(inventory['files']['cases/crash-example/result.json'],hashlib.sha256(self.record).hexdigest())
  self.assertIn('workspace/local/path',(record.parent/'run.stdout').read_text())
  self.assertFalse(list(self.out.rglob('*.tar.gz')))
  self.assertEqual(inventory['case_directories'],1)
  self.assertEqual(inventory['governance_crash_cases'],1)

 def test_modified_evidence_rejected(self):
  self.publish()
  (self.data/'evidence/cases/crash-example/result.json').write_text('{}')
  with self.assertRaises(ValueError):check_evidence(self.data)

 def test_missing_evidence_rejected(self):
  self.publish()
  (self.data/'evidence/cases/crash-example/result.json').unlink()
  with self.assertRaises(FileNotFoundError):check_evidence(self.data)

 def test_private_json_rejected(self):
  (self.runs/'coverage-cases/crash-example/result.json').write_text('{"secret":"private"}')
  with self.assertRaises(ValueError):self.publish()

 def test_inventory_path_escape_rejected(self):
  self.publish()
  index=self.data/'evidence-index.json'
  index.write_text(json.dumps({'files':{'../test-results.txt':'unused'}}))
  with self.assertRaises(ValueError):check_evidence(self.data)


if __name__=='__main__':unittest.main()

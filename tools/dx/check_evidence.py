#!/usr/bin/env python3
"""Check individual evidence records, exact bindings, transcripts and regression inventories."""
import argparse,hashlib,json,re
from pathlib import Path
from guards import require
def check_evidence(data):
 inventory=json.loads((data/'evidence-index.json').read_text())
 root=(data/'evidence').resolve()
 require(inventory['files'], 'Empty evidence inventory')
 for rel,digest in inventory['files'].items():
  path=(root/rel).resolve()
  require(path.is_relative_to(root), f'Evidence path escapes public directory: {rel}')
  require(not {'private','issuers.json'} & set(Path(rel).parts), f'Private evidence path: {rel}')
  require(hashlib.sha256(path.read_bytes()).hexdigest()==digest, f'Evidence hash mismatch: {rel}')
 return inventory

def check(data):
 m=json.loads((data/'manifest.json').read_text());require(len(m['runs'])==12, 'Expected twelve branches')
 count=0
 for entry in m['runs']:
  root=data/'runs'/entry['id'];p=root/'run.json';require(hashlib.sha256(p.read_bytes()).hexdigest()==entry['sha256'], 'Run hash mismatch')
  run=json.loads(p.read_text());require(run['report']['pending_queue_items']==0, 'Pending work remains')
  metrics=run['report']['primary_metrics']
  require(metrics.get('discretionary_onboarding_events',metrics.get('coordination_events'))==0, 'Unexpected discretionary onboarding')
  for a in run['actions']:
   count+=1
   raw=[json.loads(line) for line in (root/('events.jsonl' if a['stream']=='primary' else 'peer-events.jsonl')).read_text().splitlines()]
   e=next(e for e in raw if e['sequence']==a['sequence']);require(e['hash']==a['event_hash'] and e['data']['decision']==a['decision'], 'Decision/event mismatch')
   require(a['payload']==json.loads(bytes(a['intent']['effect']['canonical_payload'])), 'Payload binding mismatch')
   for evidence in a['snapshot']['evidence']:
    value=run['objects'][evidence['content_sha256']]
    h=hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest();require(h==evidence['content_sha256'], 'Evidence hash mismatch')
   if a['decision']['kind']!='permitted':require(a['receipt'] is None and a['ticket'] is None, 'Unpermitted dispatch')
   if a['receipt']:
    require(a['receipt']['decision']==a['decision'] and a['ticket']['attempt_id']==a['receipt']['attempt_id'], 'Receipt binding mismatch')
  exception=[a for a in run['actions'] if a['intent']['proposal_id']=='exception']
  require([a['decision']['kind'] for a in exception]==['decision_required','permitted'], 'Exception decision sequence mismatch')
  require(not exception[0]['receipt'] and exception[1]['receipt'], 'Exception receipt sequence mismatch')
 host=json.loads((data/'host.json').read_text());require(len(host['cases'])==7, 'Expected seven host cases')
 for c in host['cases']:
  if c['id'].startswith('after-'):
   require(c['exit_code']==86 and c['before']['record']['ticket']==c['after']['record']['ticket'], 'Crash attempt changed')
   require(c['after']==c['after_second_recovery'] and c['after']['replay_occurrence_present'], 'Recovery replay changed')
 require(not m.get('downloads'), 'Archive downloads must not be advertised')
 require(not list(data.glob('*.tar.gz')), 'Retired archive bundles remain public')
 for name,key in [('test-results.txt','workspace_passed'),('kernel-test-results.txt','kernel_passed')]:
  transcript=(data/name).read_text()
  passed=sum(map(int,re.findall(r'test result: ok\. (\d+) passed',transcript)))
  require('FAILED' not in transcript and passed>0 and m['validation'][key]==passed, 'Test transcript/count mismatch')
 require(m['validation']['governance_crash_cases']>0, 'Missing governance crash cases')
 inventory=check_evidence(data)
 require(inventory['case_directories']==m['validation']['case_directories'], 'Case directory count mismatch')
 require(inventory['governance_crash_cases']==m['validation']['governance_crash_cases'], 'Crash case count mismatch')
 require(hashlib.sha256((data/'test-results.txt').read_bytes()).hexdigest()==m['tests']['transcript_sha256'], 'Transcript hash mismatch')
 print(f'PASS: {len(m["runs"])} branches, {count} exact decision checkpoints, 7 host cases, {len(inventory["files"])} evidence files.')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('data',type=Path);check(p.parse_args().data)

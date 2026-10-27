#!/usr/bin/env python3
"""Replay solver witnesses from a direct checkpoint as labeled interventions."""
import argparse,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('harness',type=Path);p.add_argument('binary',type=Path);p.add_argument('checkpoint',type=Path);p.add_argument('analysis',type=Path)
p.add_argument('--branch',required=True,type=lambda s:int(s,0));p.add_argument('--budget',type=int,default=1000)
a=p.parse_args()
s=json.loads(a.analysis.read_text());cp=json.loads(a.checkpoint.read_text())
if s['image_sha256']!=cp['image_sha256']:raise SystemExit('image mismatch')
if cp['state']['pc']!=int(s['slice']['start'],16):raise SystemExit('checkpoint PC must equal slice start')
register=int(s['slice']['input_register'][1:]);out=[]
for candidate in s['result_candidates']:
    with tempfile.TemporaryDirectory() as d:
        obs=Path(d)/'run.jsonl';graph=Path(d)/'graph.json'
        command=[str(a.harness.resolve()),'run',str(a.binary.resolve()),'--restore',str(a.checkpoint.resolve()),'--set-reg',f"{register}={candidate['witness']}",'--max-insns',str(a.budget),'--observe',str(obs),'--observe-range',f"{cp['state']['pc']:#x}:{a.branch+4:#x}",'--json',str(graph),'--quiet']
        r=subprocess.run(command,capture_output=True,text=True)
        if r.returncode:out.append({'candidate':candidate,'status':'execution_error','error':r.stderr});continue
        rows=[json.loads(line) for line in obs.read_text().splitlines()]
        branch=next((r for r in rows if r.get('type')=='instruction' and int(r['pc'],16)==a.branch),None)
        end=int(s['slice']['end_exclusive'],16); result_reg=int(s['slice']['result_register'][1:])
        end_record=next((r for r in rows if r.get('type')=='instruction' and int(r['pc'],16)==end),None)
        observed_result=end_record['before']['x'][result_reg] if end_record else None
        expected=int(candidate['result'],16)
        status='branch_not_reached'
        if branch and end_record:
            status='reached_branch_via_checkpoint_intervention' if int(observed_result,16)==expected else 'solver_result_mismatch'
        out.append({'candidate':candidate,'status':status,'observed_result':observed_result,'branch_pc':f'{a.branch:#x}','observed_target':branch['after']['pc'] if branch else None,'speculative':branch['speculative'] if branch else None,'stop':json.loads(graph.read_text())['run_records'][0]['stop']})
print(json.dumps({'schema':1,'kind':'checkpoint_intervention_replays','image_sha256':s['image_sha256'],'cases':out,'limitations':['register values are injected after checkpoint restore','intervened executions do not establish reachability from function entry','external model and PAC assumptions remain in force']},indent=2))

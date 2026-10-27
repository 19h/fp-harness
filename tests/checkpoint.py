#!/usr/bin/env python3
"""Compare an exact checkpoint continuation against uninterrupted execution."""
import json, subprocess, sys, tempfile
from pathlib import Path
harness,binary=(str(Path(x).resolve()) for x in sys.argv[1:])
def run(*args, ok=True):
    p=subprocess.run([harness,*args],capture_output=True,text=True)
    if ok and p.returncode:raise AssertionError(p.stderr)
    if not ok and not p.returncode:raise AssertionError('expected failure')
    return p
with tempfile.TemporaryDirectory() as d:
    d=Path(d); cp=d/'state.json'; a=d/'original.jsonl';b=d/'restored.jsonl';ga=d/'original.json';gb=d/'restored.json'
    run('run',binary,'--entry','0x100e18c0c','--x1','0x530000000','--x3','0x530000800','--x4','0x530001000','--max-insns','5000','--checkpoint-at','0x100e18e78','--checkpoint',str(cp),'--observe',str(a),'--json',str(ga),'--quiet')
    run('run',binary,'--restore',str(cp),'--max-insns','5000','--observe',str(b),'--json',str(gb),'--quiet')
    checkpoint=json.loads(cp.read_text()); ordinal=checkpoint['ordinal']
    original=[json.loads(l) for l in a.read_text().splitlines()];restored=[json.loads(l) for l in b.read_text().splitlines()]
    oi=[r for r in original if r['type']=='instruction' and r['ordinal']>=ordinal];ri=[r for r in restored if r['type']=='instruction']
    assert len(oi)==len(ri)>0
    for n,(x,y) in enumerate(zip(oi,ri)):
        assert x['ordinal']==y['ordinal']+ordinal
        for key in ('pc','raw','before','after','memory','read_pages','status','speculative'):
            assert x[key]==y[key],(n,key,x['pc'])
    oc=[r for r in original if r['type']=='model_call' and r['ordinal']>ordinal];rc=[r for r in restored if r['type']=='model_call']
    assert len(oc)==len(rc)
    for x,y in zip(oc,rc):
        assert x['ordinal']==y['ordinal']+ordinal
        for key in ('pc','name','args','before','after','memory','returned','modeled','detail'): assert x[key]==y[key],key
    x=json.loads(ga.read_text())['run_records'][0];y=json.loads(gb.read_text())['run_records'][0]
    assert x['result_x0']==y['result_x0'] and x['stop']==y['stop']
    intervened=d/'intervened.jsonl'
    run('run',binary,'--restore',str(cp),'--set-reg','0=0','--max-insns','5000','--observe',str(intervened),'--observe-range','0x100e18e78:0x100e18e9c','--quiet')
    obs=[json.loads(l) for l in intervened.read_text().splitlines()]
    branch=next(r for r in obs if r.get('pc')=='0x100e18e98')
    assert branch['after']['pc']=='0x100e18e9c' and branch['speculative'] is True
    assert obs[0]['interventions']==[{'register':0,'value':'0x0'}]
    proof=d/'proof.json'
    run('analyze',str(a),'--binary',binary,'--start','0x100e18e78','--end','0x100e18e90','--symbolic-reg','0','--result-reg','8','--out',str(proof))
    root=Path(__file__).resolve().parents[1]
    explored=subprocess.run([sys.executable,str(root/'scripts/concolic_replay.py'),harness,binary,str(cp),str(proof),'--branch','0x100e18e98','--budget','100'],capture_output=True,text=True,check=True)
    cases=json.loads(explored.stdout)['cases']
    assert {c['observed_target'] for c in cases}=={'0x100e18e9c','0x100e18ee4'}
    assert all(c['status']=='reached_branch_via_checkpoint_intervention' and c['speculative'] for c in cases)
    checkpoint['image_sha256']='0'*64;cp.write_text(json.dumps(checkpoint))
    run('run',binary,'--restore',str(cp),'--quiet',ok=False)
    print(f'direct checkpoint: {len(ri)} instruction states and {len(rc)} model calls match; intervention labeled; bad hash rejected')

#!/usr/bin/env python3
"""Target-specific capture, proof, replay, and fail-closed regression."""
import json, subprocess, sys, tempfile
from pathlib import Path
harness, binary = map(lambda x:str(Path(x).resolve()),sys.argv[1:])
base=['run',binary,'--entry','0x100e18c0c','--x1','0x530000000','--x3','0x530000800','--x4','0x530001000','--max-insns','5000','--quiet']

def run(*args, ok=True):
    proc=subprocess.run([harness,*args],capture_output=True,text=True)
    if ok and proc.returncode:raise AssertionError(proc.stderr)
    if not ok and not proc.returncode:raise AssertionError('expected a rejected analysis')
    return proc

info=json.loads(run('inspect',binary,'--json').stdout)
assert info['fixups']['rebase']==5317 and info['pointer_format']==12
with tempfile.TemporaryDirectory() as d:
    d=Path(d)
    baseline, small, graph, normal = (d / n for n in ('base.jsonl','small.jsonl','instrumented.json','normal.json'))
    run(*base,'--json',str(normal))
    run(*base,'--observe',str(baseline),'--observe-pages','--observe-range','0x100e18e74:0x100e18e9c','--json',str(graph))
    run(*base,'--heap-size','0x1000','--observe',str(small),'--observe-pages','--observe-range','0x100e18e74:0x100e18e9c')
    a=json.loads(normal.read_text())['run_records'][0]; b=json.loads(graph.read_text())['run_records'][0]
    for key in ('instructions','events','calls','stop','result_x0'):assert a[key]==b[key],key
    proof=d/'proof.json'
    analysis=['analyze',str(baseline),'--binary',binary,'--start','0x100e18e78','--end','0x100e18e90','--symbolic-reg','0','--result-reg','8']
    run(*analysis,'--resolve-table','--replay',str(small),'--out',str(proof))
    result=json.loads(proof.read_text()); rel=result['zero_test_relation']
    assert rel['when_true']=='0x537' and rel['when_false']=='0x52b' and result['exhaustive_under_assumptions']
    entries={x['index']:x for x in result['target_evidence']['entries']}
    assert entries['0x537']['target']=='0x100e18e9c' and entries['0x52b']['target']=='0x100e18ee4'
    assert all(x['status']=='observed_in_modeled_execution' for x in entries.values())
    target=d/'target.json'
    run('analyze',str(baseline),'--binary',binary,'--start','0x100e18e78','--end','0x100e18e94','--out',str(target))
    r=json.loads(target.read_text());assert r['zero_test_relation']['when_true']=='0x100e18e9c' and r['zero_test_relation']['when_false']=='0x100e18ee4'
    assert r['memory_assumptions'][0]['exhaustive_address_domain']
    # A store cannot be silently treated as a pure symbolic operation.
    run('analyze',str(baseline),'--binary',binary,'--start','0x100e18e74','--end','0x100e18e90',ok=False)
    # Reject incompatible frozen state in the second recorded run.
    altered=[json.loads(line) for line in small.read_text().splitlines()]
    next(r for r in altered if r.get('pc')=='0x100e18e78')['before']['x'][1]='0x1234'
    bad=d/'bad.jsonl';bad.write_text(''.join(json.dumps(r)+'\n' for r in altered))
    run(*analysis,'--resolve-table','--replay',str(bad),ok=False)
    # Reject a fabricated instruction even if the observation header is unchanged.
    altered=[json.loads(line) for line in baseline.read_text().splitlines()]
    next(r for r in altered if r.get('pc')=='0x100e18e80')['raw']='0xd503201f'
    bad.write_text(''.join(json.dumps(r)+'\n' for r in altered))
    run('analyze',str(bad),'--binary',binary,'--start','0x100e18e78','--end','0x100e18e90',ok=False)
    print('instrumented parity, two replayed targets, SMT proof and rejection checks: PASS')

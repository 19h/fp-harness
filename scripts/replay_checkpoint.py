#!/usr/bin/env python3
"""Re-execute from the recorded initial state and verify a checkpoint prefix.

This is a replay checkpoint, not a direct CPU snapshot: the prefix is executed
again in a fresh machine. All instruction and model-call records up to the
requested boundary are compared, including guest and model memory events.
"""
import argparse, hashlib, json, subprocess, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('harness',type=Path)
p.add_argument('binary',type=Path)
p.add_argument('observation',type=Path)
p.add_argument('--ordinal',type=int,required=True,help='checkpoint immediately before this retired instruction')
a=p.parse_args()
rows=[json.loads(line) for line in a.observation.read_text().splitlines()]
h=rows[0]
if h.get('schema')!=1 or h.get('type')!='header' or h.get('capture_range') is not None:
    raise SystemExit('a full, unfiltered observation is required')
if hashlib.sha256(a.harness.read_bytes()).hexdigest()!=h.get('harness_sha256'):
    raise SystemExit('harness SHA-256 does not match observation')
if hashlib.sha256(a.binary.read_bytes()).hexdigest()!=h['image_sha256']:
    raise SystemExit('binary SHA-256 does not match observation')
if a.ordinal<0:
    raise SystemExit('ordinal must be nonnegative')
args=[str(a.harness.resolve()),'run',str(a.binary.resolve()),'--entry',h['entry'],'--heap-size',str(h['heap_size']),'--max-insns',str(h['budget']),'--quiet']
for i,x in enumerate(h['args']): args += [f'--x{i}',x]
for w in h['writes']: args += [f"--w{w['width']*8}",f"{w['address']}={w['value']}"]
if h.get('restored_from'): raise SystemExit('replay from an existing direct checkpoint is not supported')
if h.get('observe_pages'): args.append('--observe-pages')
with tempfile.TemporaryDirectory() as d:
    path=Path(d)/'replay.jsonl'
    subprocess.run(args+['--observe',str(path)],check=True,stdout=subprocess.DEVNULL)
    replay=[json.loads(line) for line in path.read_text().splitlines()]

def prefix(records):
    ins=[r for r in records if r.get('type')=='instruction' and r['ordinal'] < a.ordinal]
    calls=[r for r in records if r.get('type')=='model_call' and r['ordinal'] <= a.ordinal]
    boundary=[r for r in records if r.get('type')=='instruction' and r['ordinal']==a.ordinal]
    if len(boundary)!=1 or len(ins)!=a.ordinal:
        raise SystemExit('checkpoint is absent or observation is incomplete')
    return ins,calls,boundary[0]['before']
expected=prefix(rows);actual=prefix(replay)
for name,left,right in zip(('instructions','model calls','boundary state'),expected,actual):
    if left!=right:
        if isinstance(left,list):
            at=next((i for i,(x,y) in enumerate(zip(left,right)) if x!=y),min(len(left),len(right)))
            raise SystemExit(f'checkpoint mismatch in {name} at record {at}')
        raise SystemExit(f'checkpoint mismatch in {name}')
print(json.dumps({'status':'verified_replay_checkpoint','ordinal':a.ordinal,'pc':expected[2]['pc'],'instructions':len(expected[0]),'model_calls':len(expected[1]),'binary_sha256':h['image_sha256'],'method':'fresh execution from entry; prefix and checkpoint state compared','limit':'not a direct architectural snapshot or independent native validation'},indent=2))

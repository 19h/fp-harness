#!/usr/bin/env python3
"""Fit small register-effect hypotheses to observed dispatcher regions.

These are finite-sample hypotheses; correlated registers can create equivalent
fits. No inferred expression is presented as a universal semantic summary.
"""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('regions',type=Path)
p.add_argument('--register',required=True,type=int,help='output X register, 0..30')
p.add_argument('--width',type=int,choices=(32,64),default=64)
a=p.parse_args()
if not 0<=a.register<=30:raise SystemExit('register must be 0..30')
d=json.loads(a.regions.read_text()); rs=[r for r in d['regions'] if r['status']=='observed']
if len(rs)<3:raise SystemExit('at least three complete non-counterfactual regions are required')
if len({r['entry'] for r in rs}) != 1 or len({tuple(r['instruction_pcs']) for r in rs}) != 1:
    raise SystemExit('regions must have the same entry and instruction path')
mask=(1<<a.width)-1
samples=[([int(x,16)&mask for x in r['entry_state']['x']],int(r['exit_state']['x'][a.register],16)&mask) for r in rs]
out=[y for _,y in samples];candidates=[]
if len(set(out))==1:candidates.append({'operation':'constant','value':f'{out[0]:#x}'})
for src in range(31):
    xs=[x[src] for x,_ in samples]
    if len(set(xs)) < 2: continue
    if all(x==y for x,y in zip(xs,out)):candidates.append({'operation':'copy','source':f'x{src}'})
    delta=(out[0]-xs[0])&mask
    if delta and all(((x+delta)&mask)==y for x,y in zip(xs,out)):candidates.append({'operation':'add','source':f'x{src}','constant':f'{delta:#x}'})
    xormask=out[0]^xs[0]
    if xormask and all((x^xormask)==y for x,y in zip(xs,out)):candidates.append({'operation':'xor','source':f'x{src}','constant':f'{xormask:#x}'})
print(json.dumps({'schema':1,'image_sha256':d['image_sha256'],'dispatch':d['dispatch'],'output':f'x{a.register}','width_bits':a.width,'observations':len(samples),'distinct_outputs':len(set(out)),'candidates':candidates,'status':'finite_sample_hypotheses','limitations':['no solver proof or independent validation','candidate agreement does not establish equivalent handler semantics','memory effects and unobserved paths are excluded','correlated input registers can create indistinguishable hypotheses']},indent=2))

#!/usr/bin/env python3
"""Summarize observed dispatcher-to-dispatcher regions, without assuming a VM."""
import argparse, collections, json
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('observation',type=Path)
p.add_argument('--dispatch',required=True,type=lambda s:int(s,0))
p.add_argument('--vpc-reg',type=int,help='optional analyst-selected virtual-PC candidate register, 0..30')
a=p.parse_args()
if a.vpc_reg is not None and not 0<=a.vpc_reg<=30:raise SystemExit('vpc-reg must be 0..30')
rows=[json.loads(l) for l in a.observation.read_text().splitlines()]
h=rows[0]
if h.get('capture_range') is not None:raise SystemExit('full, unfiltered observation required')
ins=sorted((r for r in rows if r.get('type')=='instruction'),key=lambda r:r['ordinal'])
if any(r['ordinal']!=i for i,r in enumerate(ins)):raise SystemExit('instruction coverage is incomplete')
calls=[r for r in rows if r.get('type')=='model_call']
dispatches=[r for r in ins if int(r['pc'],16)==a.dispatch]
regions=[]
for first,last in zip(dispatches,dispatches[1:]):
    begin,end=first['ordinal']+1,last['ordinal']
    path=ins[begin:end]
    if any(r['speculative'] for r in path): status='counterfactual'
    else: status='observed'
    before=first['after']; after=last['before']
    changes={f'x{i}':{'before':x,'after':y} for i,(x,y) in enumerate(zip(before['x'],after['x'])) if x!=y}
    for key in ('sp','pstate','fpcr','fpsr','tpidr','tpidrro'):
        if before[key]!=after[key]:changes[key]={'before':before[key],'after':after[key]}
    for i,(x,y) in enumerate(zip(before['v'],after['v'])):
        if x!=y:changes[f'v{i}']={'before':x,'after':y}
    writes=[{'ordinal':r['ordinal'],'pc':r['pc'],**m} for r in path for m in r['memory'] if m['kind']=='write']
    model_calls=[c for c in calls if begin<=c['ordinal']<=end]
    regions.append({'ordinal_start':begin,'ordinal_end_exclusive':end,'entry':before['pc'],'return_to_dispatch':last['pc'],'instructions':len(path),'status':status,'vpc_candidate_before':before['x'][a.vpc_reg] if a.vpc_reg is not None else None,'vpc_candidate_after':after['x'][a.vpc_reg] if a.vpc_reg is not None else None,'entry_state':before,'exit_state':after,'register_changes':changes,'memory_writes':writes,'model_calls':model_calls,'instruction_pcs':[r['pc'] for r in path]})
print(json.dumps({'schema':1,'image_sha256':h['image_sha256'],'dispatch':f'{a.dispatch:#x}','vpc_reg_candidate':a.vpc_reg,'dispatch_occurrences':len(dispatches),'complete_regions':len(regions),'regions':regions,'limitations':['dispatcher and virtual-PC interpretation are analyst supplied and not verified','one observed trace; register deltas and writes do not prove general handler semantics','model calls and counterfactual events remain explicit']},indent=2))

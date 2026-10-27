#!/usr/bin/env python3
"""Rank byte-fetch and indirect-dispatch correlations in an observed trace.

These are hypotheses. Table lookups and ordinary loops can have the same shape.
"""
import argparse, collections, json
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('observation',type=Path)
p.add_argument('--min-occurrences',type=int,default=3)
p.add_argument('--window',type=int,default=128)
a=p.parse_args()
rows=[json.loads(l) for l in a.observation.read_text().splitlines()]
if rows[0].get('capture_range') is not None: raise SystemExit('full, unfiltered observation required')
ins=sorted((r for r in rows if r.get('type')=='instruction'),key=lambda r:r['ordinal'])
if any(r['ordinal'] != i for i,r in enumerate(ins)): raise SystemExit('instruction coverage is incomplete')
# Identify branches solely from raw A64 BR/BLR/PAuth encoding. Conditional
# opcodes and RET are excluded; this is a candidate-ranking heuristic.
def branch(r):
    raw=int(r['raw'],16)
    return (raw & 0xfe000000)==0xd6000000 and ((raw & 0xfffffc1f)==0xd61f0000 or (raw & 0xfffffc1f)==0xd63f0000 or (raw & 0xffe00000)==0xd7000000)
by_pc=collections.defaultdict(list)
for i,r in enumerate(ins):
    for access in r['memory']:
        if access['kind']=='read' and access['ok'] and len(access['bytes'])==2:
            address=int(access['address'],16)
            regs=[n for n,x in enumerate(r['before']['x']) if int(x,16)==address]
            if regs:
                future=next((q for q in ins[i+1:i+1+a.window] if branch(q)),None)
                by_pc[r['pc']].append((address,regs,future))
out=[]
for pc,events in by_pc.items():
    if len(events)<a.min_occurrences: continue
    counts=collections.Counter(n for _,regs,_ in events for n in regs)
    dispatch=collections.Counter(q['pc'] for _,_,q in events if q is not None)
    out.append({'fetch_pc':pc,'occurrences':len(events),'distinct_byte_addresses':len({addr for addr,_,_ in events}),'register_equals_address':dict(counts),'nearby_indirect_transfers':dict(dispatch),'classification':'candidate_only'})
out.sort(key=lambda x:(-x['occurrences'],x['fetch_pc']))
print(json.dumps({'schema':1,'image_sha256':rows[0]['image_sha256'],'method':'observed one-byte reads whose address equals a register, correlated with following indirect transfer','hypotheses':out,'limitations':['no bytecode or virtual machine is established','offset or encrypted bytecode fetches can be missed','native tables and loops can generate false positives']},indent=2))

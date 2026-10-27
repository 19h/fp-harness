#!/usr/bin/env python3
"""Export a conditional CFG overlay from a proved index and observed table."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('proof',type=Path);p.add_argument('--json',type=Path,required=True);p.add_argument('--dot',type=Path,required=True)
a=p.parse_args();d=json.loads(a.proof.read_text())
relation=d.get('zero_test_relation');table=d.get('target_evidence')
if not relation or not table or not d.get('exhaustive_under_assumptions'):raise SystemExit('an exhaustive two-way index proof and table evidence are required')
entries={e['index']:e for e in table['entries']}
outputs=[]
for side,label in (('when_true',relation['predicate']),('when_false','not ('+relation['predicate']+')')):
    index=relation[side];e=entries.get(index)
    if not e or not e.get('target'):raise SystemExit(f'unresolved table entry {index}')
    sites={x['branch_pc'] for x in e['observations']}
    # A snapshot-only entry does not carry an observed branch site; use the
    # common site established by other entries, never invent one.
    if not sites:sites={x['branch_pc'] for x in table['runs']}
    if len(sites)!=1:raise SystemExit('branch site is ambiguous')
    outputs.append({'from':next(iter(sites)),'to':e['target'],'condition':label,'index':index,'classification':e['status'],'observations':e['observations'],'evidence':'SMT-proved index under slice assumptions; target from observed page snapshot'})
result={'schema':1,'kind':'semantic_cfg_overlay','image_sha256':d['image_sha256'],'solver':d['solver'],'lifter':d['lifter'],'slice':d['slice'],'edges':outputs,'assumptions':d['assumptions']+table['assumptions'],'limits':['overlay does not prove whole-function path feasibility','page snapshots do not prove table invariance','native PAC behavior is not modeled']}
a.json.write_text(json.dumps(result,indent=2)+'\n')
lines=['digraph semantic_cfg {','  rankdir=LR;','  node [shape=box];']
for e in outputs:
    label=f"{e['condition']} / index {e['index']} / {e['classification']}"
    lines.append(f"  \"{e['from']}\" -> \"{e['to']}\" [label=\"{label}\"];")
lines.append('}')
a.dot.write_text('\n'.join(lines)+'\n')

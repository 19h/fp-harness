#!/usr/bin/env python3
"""Print a compact, ordered control-flow projection of one recorded run."""
import argparse
import json
from collections import Counter
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('report', type=Path)
p.add_argument('--run', type=int, default=0)
a = p.parse_args()
d = json.loads(a.report.read_text())
r = d['run_records'][a.run]
print(f"image: {d['image_path']}; entry: {d['entry']}; run: {a.run}")
print(f"heap: {d['heap_size_bytes']} B; initial writes: {len(d['initial_writes'])}")
print(f"x0..x7: {', '.join(r['args'])}")
print(f"instructions: {r['instructions']}; conditional occurrences: {r['conditional_occurrences']}; redirects: {r['redirects']}")
print(f"stop: {r['stop']}; x0: {r['result_x0']}")
print('events:', dict(Counter(e['kind'] for e in r['events'])))
print('\nControl projection (sequential indirect branches omitted; all events remain in JSON):')
calls = iter(r['calls'])
omitted = 0
for e in r['events']:
    if e['kind'] == 'Indirect' and int(e['target'], 16) == int(e['pc'], 16) + 4:
        omitted += 1
        continue
    mark = ' [counterfactual]' if e['speculative'] else ''
    detail = ''
    if e['kind'] == 'CallImport':
        c = next(calls)
        detail = f"; {c['name']}: {c['detail']}"
    elif e['evidence']:
        detail = f"; {e['evidence']}"
    print(f"  {e['pc']} -> {e['target']}  {e['kind']}{mark}{detail}")
print(f"omitted sequential indirect branch occurrences: {omitted}")

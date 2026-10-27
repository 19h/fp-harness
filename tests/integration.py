#!/usr/bin/env python3
"""End-to-end evidence checks on the supplied image."""
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

harness, image = sys.argv[1:]

def execute(args):
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / 'report.json'
        trace = Path(d) / 'trace.txt'
        subprocess.run([harness, 'run', image, '--quiet', '--json', str(report), '--trace', str(trace), *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return json.loads(report.read_text()), trace.read_text()

base = ['--entry','0x100e18c0c','--x1','0x530000000','--x3','0x530000800','--x4','0x530001000','--max-insns','5000']
small, _ = execute(base)
large, _ = execute(base + ['--heap-size','0x41000000'])
a, b = small['run_records'][0], large['run_records'][0]
assert small['heap_size_bytes'] == 64 * 1024 * 1024
assert large['heap_size_bytes'] == 0x41000000
assert any('malloc(0x40000000) -> 0x0' in c['detail'] for c in a['calls'])
assert any(c['name'] == '_malloc' and 'malloc(0x40000000)' in c['detail'] and c['result'] != '0x0' for c in b['calls'])
assert 'returned to sentinel' in a['stop']
assert 'instruction budget' in b['stop']
for d in (small, large):
    pcs = [i['pc'] for block in d['blocks'] for i in block['insns']]
    assert all(n == 1 for n in Counter(pcs).values()), 'overlapping blocks'
print('heap sensitivity, stop reasons, and non-overlapping blocks: PASS')

branch, _ = execute(['--entry','0x100004530','--x0','0x530000000','--x1','0x530000800','--w32','0x530000000=0x80000000','--w32','0x530000004=0x40','--w32','0x530000018=1','--w32','0x530000024=0x01000000','--w32','0x530000028=0x1000','--w32','0x53000003c=0x1000','--w32','0x530000040=1','--read','0x530000800:64','--read','0:8','--max-insns','5000','--explore-depth','3','--explore-runs','15'])
assert len(branch['run_records']) == branch['runs']
mem = branch['run_records'][0]['memory']
assert len(bytes.fromhex(mem[0]['data_hex'])) == 64 and mem[0]['error'] is None
assert mem[1]['data_hex'] is None and mem[1]['error'] is not None
assert any(r['redirects'] and any(e['speculative'] for e in r['events']) for r in branch['run_records'])
assert any(e['forced'] for e in branch['edges'])
assert all(b['forced_taken'] + b['forced_not_taken'] == 0 or not b['invariant'] for b in branch['branches'])
print('forced-path provenance and branch statistics: PASS')

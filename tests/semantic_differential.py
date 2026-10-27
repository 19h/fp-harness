#!/usr/bin/env python3
"""Compare the generated target-slice expression against Unicorn for seeded inputs."""
import json, random, subprocess, sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
import unicorn.arm64_const as reg

observation, proof = sys.argv[1:]
rows = [json.loads(line) for line in Path(observation).read_text().splitlines()]
p = json.loads(Path(proof).read_text())
start, end = int(p['slice']['start'],16), int(p['slice']['end_exclusive'],16)
segment = [r for r in rows if r.get('type') == 'instruction' and start <= int(r['pc'],16) < end]
assert len(segment) == (end-start)//4
code = b''.join(int(r['raw'],16).to_bytes(4,'little') for r in segment)
initial = segment[0]['before']
u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
page = start & ~4095
u.mem_map(page, 4096)
u.mem_write(start, code)
seen = {page}
for record in segment:
    for captured in record.get('read_pages', []):
        base = int(captured['base'], 16)
        if base not in seen:
            u.mem_map(base, 4096)
            u.mem_write(base, bytes.fromhex(captured['bytes']))
            seen.add(base)
regs = [getattr(reg, f'UC_ARM64_REG_X{i}') for i in range(31)]
rng = random.Random(0xfaf00d)
inputs = [0,1,0xffffffff,0x100000000,0xffffffffffffffff] + [rng.getrandbits(64) for _ in range(251)]
actual=[]
for val in inputs:
    for i, r in enumerate(regs):
        u.reg_write(r, val if i == 0 else int(initial['x'][i],16))
    u.reg_write(reg.UC_ARM64_REG_SP, int(initial['sp'],16))
    u.reg_write(reg.UC_ARM64_REG_NZCV, int(initial['pstate'],16) & 0xf0000000)
    u.emu_start(start, end, count=len(segment))
    actual.append(u.reg_read(reg.UC_ARM64_REG_X8))
script=['(set-logic QF_BV)','(declare-fun sym () (_ BitVec 64))',f"(define-fun out () (_ BitVec 64) {p['expression_smtlib']})"]
for val in inputs:
    script += ['(push)', f'(assert (= sym #x{val:016x}))', '(check-sat)', '(get-value (out))', '(pop)']
out=subprocess.run(['z3','-in','-smt2'],input='\n'.join(script)+'\n',text=True,capture_output=True,check=True).stdout
import re
predicted=[int(x,16) for x in re.findall(r'#x([0-9a-fA-F]{16})',out)]
assert len(predicted)==len(actual), (len(predicted),len(actual),out[:200])
for inp,a,b in zip(inputs,actual,predicted):
    assert a==b, f'input={inp:#x} unicorn={a:#x} lifted={b:#x}'
print(f'{len(inputs)} seeded inputs: Unicorn x8 equals SMIR-derived expression')

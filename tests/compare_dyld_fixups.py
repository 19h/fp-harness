#!/usr/bin/env python3
"""Compare the target's decoded fixups with Apple's dyld_info (macOS/Xcode)."""
import re
import subprocess
import sys

harness, image = sys.argv[1:]
ours = {}
for line in subprocess.check_output([harness, 'fixups', image], text=True).splitlines():
    parts = line.split('\t')
    addr = int(parts[0], 16)
    if addr in ours:
        raise SystemExit(f'duplicate harness fixup: {addr:#x}')
    ours[addr] = parts[1:]

pattern = re.compile(r'^\s*\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(auth-rebase|rebase|auth-bind|bind)\s+(.*)$')
seen, errors = set(), []
output = subprocess.check_output(['xcrun', 'dyld_info', '-fixups', image], text=True)
for line in output.splitlines():
    m = pattern.match(line)
    if not m:
        continue
    addr, kind, info = int(m[1], 16), m[2], m[3]
    if addr in seen:
        errors.append(f'{addr:#x}: duplicate dyld row')
    seen.add(addr)
    actual = ours.get(addr)
    if not actual or actual[0] != kind:
        errors.append(f'{addr:#x}: kind {actual} != {kind}')
    elif kind.endswith('rebase'):
        if int(actual[1], 16) != int(info.split()[0], 16):
            errors.append(f'{addr:#x}: target {actual[1]} != {info}')
    else:
        symbol = info.split()[0].split('/')[-1]
        addend = re.search(r' ([+-]) (0x[0-9a-fA-F]+)', info)
        expected = (int(addend[2], 16) * (1 if addend[1] == '+' else -1)) if addend else 0
        if actual[1] != symbol or int(actual[2]) != expected:
            errors.append(f'{addr:#x}: bind {actual[1:3]} != {info}')
extra = set(ours) - seen
if extra:
    errors.append(f'{len(extra)} fixups absent from dyld_info')
print(f'dyld rows={len(seen)} harness rows={len(ours)} mismatches={len(errors)}')
for error in errors[:20]:
    print(error)
if errors or not seen:
    raise SystemExit(1)

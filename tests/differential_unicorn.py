#!/usr/bin/env python3
"""Compare two real dispatch traces against Unicorn, with dyld_info rebases.

This fixture contains no PAC operations or imports. It does not validate the
arm64e PAC policy, external models, or other target functions.
"""
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP

harness, image = sys.argv[1:]
data = Path(image).read_bytes()
assert struct.unpack_from('<I', data)[0] == 0xfeedfacf, 'fixture expects a thin Mach-O'
ncmds = struct.unpack_from('<I', data, 16)[0]
segments = []
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', data, off)
    if cmd == 0x19:
        name = data[off+8:off+24].split(b'\0')[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+24)
        if name != '__PAGEZERO' and vmsize:
            segments.append((vmaddr, vmsize, fileoff, filesize))
    off += size
fixups = subprocess.check_output(['xcrun', 'dyld_info', '-fixups', image], text=True)
rebases = []
for line in fixups.splitlines():
    m = re.match(r'^\s*\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(?:auth-rebase|rebase)\s+(0x[0-9a-fA-F]+)', line)
    if m:
        rebases.append((int(m[1], 16), int(m[2], 16)))

for selector, expected in ((0x4b0, 0x100004530), (0x500, 0)):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for va, size, fileoff, filesize in segments:
        start = va & ~0xfff
        end = (va + size + 0xfff) & ~0xfff
        uc.mem_map(start, end - start)
        if filesize:
            uc.mem_write(va, data[fileoff:fileoff+filesize])
    for address, value in rebases:
        uc.mem_write(address, struct.pack('<Q', value))
    stack, scratch, sentinel = 0x520000000, 0x530000000, 0x500008000
    uc.mem_map(stack, 8 << 20)
    uc.mem_map(scratch, 64 << 10)
    uc.mem_map(sentinel, 0x1000)
    uc.mem_write(scratch + 0x14, struct.pack('<I', selector))
    uc.reg_write(UC_ARM64_REG_X0, scratch)
    uc.reg_write(UC_ARM64_REG_X1, scratch + 0x800)
    sp = stack + (8 << 20) - 0x1000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X29, sp)
    uc.reg_write(UC_ARM64_REG_X30, sentinel)
    trace = []
    def hook(uc, address, size, _):
        if address == sentinel:
            uc.emu_stop()
        else:
            trace.append(address)
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x1000044fc, sentinel + 4, count=1000)
    result = uc.reg_read(UC_ARM64_REG_X0)
    with tempfile.TemporaryDirectory() as d:
        report, path = str(Path(d)/'run.json'), str(Path(d)/'trace.txt')
        subprocess.run([harness, 'run', image, '--entry', '0x1000044fc', '--x0', hex(scratch), '--x1', hex(scratch+0x800), '--w32', f'{scratch+0x14:#x}={selector:#x}', '--max-insns', '1000', '--quiet', '--json', report, '--trace', path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rax = json.loads(Path(report).read_text())['run_records'][0]
        other = [int(line.split(':',1)[0], 16) for line in Path(path).read_text().splitlines() if line.startswith('0x')]
    assert trace == other, f'{selector:#x}: trace mismatch: {trace} != {other}'
    assert result == int(rax['result_x0'], 16) == expected, f'{selector:#x}: result mismatch'
    assert 'returned to sentinel' in rax['stop'], rax['stop']
    print(f'selector={selector:#x}: {len(trace)} instruction PCs and x0={result:#x} agree')

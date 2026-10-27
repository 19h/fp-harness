#!/usr/bin/env python3
"""A temporary patched image checks checkpointing across a model memory write."""
import json,subprocess,sys,tempfile
from pathlib import Path
harness,binary=(str(Path(x).resolve()) for x in sys.argv[1:])
def invoke(*args):
    p=subprocess.run([harness,*args],text=True,capture_output=True)
    if p.returncode:raise AssertionError(p.stderr)
    return p.stdout
fixups=invoke('fixups',binary).splitlines()
slots=[int(p[4],16) for line in fixups if len(p:=line.split('\t'))==5 and p[2]=='_memcpy' and int(p[3])==0]
assert slots, 'fixture requires a zero-addend memcpy bind'
with tempfile.TemporaryDirectory() as d:
    d=Path(d); fixture=d/'image.arm64e';cp=d/'checkpoint.json';obs=d/'obs.jsonl';base=d/'base.json';restored=d/'restored.json'
    data=bytearray(Path(binary).read_bytes())
    # stp x29,x30,[sp,#-16]!; ldr x16,[x3]; blr x16;
    # ldp x29,x30,[sp],#16; ret. All patches are confined to this copy.
    for i,word in enumerate((0xa9bf7bfd,0xf9400070,0xd63f0200,0xa8c17bfd,0xd65f03c0)):
        data[0x44fc+4*i:0x4500+4*i]=word.to_bytes(4,'little')
    fixture.write_bytes(data)
    scratch=0x530000000;dst=scratch+0x100;src=scratch+0x200;slotptr=scratch+0x300
    value=0x1122334455667788
    invoke('run',str(fixture),'--entry','0x1000044fc','--x0',hex(dst),'--x1',hex(src),'--x2','8','--x3',hex(slotptr),'--w64',f'{src:#x}={value:#x}','--w64',f'{slotptr:#x}={slots[0]:#x}','--max-insns','100','--checkpoint-at','0x100004508','--checkpoint',str(cp),'--observe',str(obs),'--read',f'{dst:#x}:8','--json',str(base),'--quiet')
    checkpoint=json.loads(cp.read_text())
    assert any(addr==dst and bytes(buf)==value.to_bytes(8,'little') for addr,buf in checkpoint['writes'])
    calls=[json.loads(line) for line in obs.read_text().splitlines() if '"type":"model_call"' in line]
    assert len(calls)==1 and calls[0]['name']=='_memcpy'
    assert any(m['kind']=='write' and m['address']==hex(dst) and m['bytes']==value.to_bytes(8,'little').hex() for m in calls[0]['memory'])
    invoke('run',str(fixture),'--restore',str(cp),'--max-insns','100','--read',f'{dst:#x}:8','--json',str(restored),'--quiet')
    a=json.loads(base.read_text())['run_records'][0];b=json.loads(restored.read_text())['run_records'][0]
    assert a['memory'][0]['data_hex']==b['memory'][0]['data_hex']==value.to_bytes(8,'little').hex()
    assert a['result_x0']==b['result_x0'] and 'returned to sentinel' in b['stop']
    print('checkpoint restores guest stack and modeled memcpy write: PASS')

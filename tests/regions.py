#!/usr/bin/env python3
"""Exercise dynamic region summaries and VM-hypothesis labeling."""
import json,subprocess,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
observation=Path(sys.argv[1]).resolve()
def call(script,*args,check=True):
    return subprocess.run([sys.executable,str(root/'scripts'/script),*map(str,args)],capture_output=True,text=True,check=check)
regions=json.loads(call('handler_trace.py',observation,'--dispatch','0x100e1b5f4','--vpc-reg','9').stdout)
assert regions['dispatch_occurrences']==18 and regions['complete_regions']==17
assert all(r['status']=='observed' and r['instructions']==62 for r in regions['regions'])
with tempfile.TemporaryDirectory() as d:
    d=Path(d);profile=d/'regions.json';profile.write_text(json.dumps(regions))
    fits=json.loads(call('infer_effects.py',profile,'--register','9').stdout)
    assert fits['status']=='finite_sample_hypotheses' and fits['observations']==17
    assert fits['candidates']==[{'operation':'constant','value':'0x30002004'}]
    # Positive control: repeated byte reads followed by an indirect branch.
    fake=[{'type':'header','schema':1,'capture_range':None,'image_sha256':'0'*64}]
    for i in range(3):
        regs=['0x0']*31;regs[0]=hex(0x2000+i)
        fake.append({'type':'instruction','ordinal':2*i,'pc':'0x1000','raw':'0x39400000','before':{'x':regs},'memory':[{'kind':'read','ok':True,'address':hex(0x2000+i),'bytes':'01'}]})
        fake.append({'type':'instruction','ordinal':2*i+1,'pc':'0x1004','raw':'0xd61f0000','before':{'x':regs},'memory':[]})
    trace=d/'synthetic.jsonl';trace.write_text(''.join(json.dumps(x)+'\n' for x in fake))
    scan=json.loads(call('vm_scan.py',trace).stdout)
    assert len(scan['hypotheses'])==1 and scan['hypotheses'][0]['classification']=='candidate_only'
    fake[0]['capture_range']=['0x1000','0x1008'];trace.write_text(''.join(json.dumps(x)+'\n' for x in fake))
    assert call('vm_scan.py',trace,check=False).returncode!=0
print('region effects, finite-sample labels and VM-scan positive control: PASS')

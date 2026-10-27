//! Dynamic backward provenance over the recorded instruction and memory stream.
//! Unsupported dependencies become explicit boundaries; this is not a proof.
use rax::smir::ir::ops::OpKind;
use rax::smir::ir::types::{ArchReg, ArmReg, SourceArch, SrcOperand, VReg};
use rax::smir::lift::{aarch64::Aarch64Lifter, LiftContext, SmirLifter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

fn hex(v: &Value) -> Result<u64, String> {
    let s = v.as_str().ok_or("expected hex string")?;
    u64::from_str_radix(s.strip_prefix("0x").ok_or("expected 0x")?, 16).map_err(|e| e.to_string())
}
fn add_operand(out: &mut Vec<VReg>, src: &SrcOperand) {
    out.extend(
        src.regs()
            .into_iter()
            .filter(|r| !matches!(r, VReg::Imm(_))),
    );
}
fn deps(op: &OpKind) -> Option<(Vec<VReg>, bool, bool)> {
    let mut r = Vec::new();
    let (mut reads_flags, mut writes_flags) = (false, false);
    match op {
        OpKind::Mov { src, .. } => add_operand(&mut r, src),
        OpKind::Add {
            src1, src2, flags, ..
        }
        | OpKind::Sub {
            src1, src2, flags, ..
        }
        | OpKind::And {
            src1, src2, flags, ..
        }
        | OpKind::Or {
            src1, src2, flags, ..
        }
        | OpKind::Xor {
            src1, src2, flags, ..
        }
        | OpKind::MulU {
            src1, src2, flags, ..
        }
        | OpKind::MulS {
            src1, src2, flags, ..
        } => {
            r.push(*src1);
            add_operand(&mut r, src2);
            writes_flags = flags.updates_any();
        }
        OpKind::Shl {
            src, amount, flags, ..
        }
        | OpKind::Shr {
            src, amount, flags, ..
        }
        | OpKind::Sar {
            src, amount, flags, ..
        } => {
            r.push(*src);
            add_operand(&mut r, amount);
            writes_flags = flags.updates_any();
        }
        OpKind::Cmp { src1, src2, .. }
        | OpKind::Cmn { src1, src2, .. }
        | OpKind::Test { src1, src2, .. } => {
            r.push(*src1);
            add_operand(&mut r, src2);
            writes_flags = true;
        }
        OpKind::MulAdd {
            acc, src1, src2, ..
        }
        | OpKind::MulSub {
            acc, src1, src2, ..
        } => r.extend([*acc, *src1, *src2]),
        OpKind::Neg { src, flags, .. } => {
            r.push(*src);
            writes_flags = flags.updates_any();
        }
        OpKind::TestCondition { .. } | OpKind::SetCC { .. } => {
            reads_flags = true;
        }
        OpKind::Select {
            cond,
            src_true,
            src_false,
            ..
        } => {
            r.extend([*cond, *src_true, *src_false]);
        }
        OpKind::ZeroExtend { src, .. }
        | OpKind::SignExtend { src, .. }
        | OpKind::Truncate { src, .. }
        | OpKind::Not { src, .. } => r.push(*src),
        OpKind::Load { addr, .. } => r.extend(addr.regs()),
        OpKind::Store { src, addr, .. } => {
            r.push(*src);
            r.extend(addr.regs());
        }
        OpKind::Nop => {}
        _ => return None,
    }
    r.retain(|r| !matches!(r, VReg::Imm(_)));
    Some((r, reads_flags, writes_flags))
}
fn event_bytes(event: &Value) -> Result<Vec<u64>, String> {
    let addr = hex(&event["address"])?;
    let text = event["bytes"].as_str().ok_or("missing access bytes")?;
    if text.len() % 2 != 0 || event["ok"] != true {
        return Err("faulted or malformed memory event".into());
    }
    (0..text.len() / 2)
        .map(|n| addr.checked_add(n as u64).ok_or("address overflow".into()))
        .collect()
}

pub fn analyze(
    path: &str,
    branch_pc: u64,
    occurrence: usize,
    limit: usize,
    binary_override: Option<&str>,
) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let rows: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let header = rows.first().ok_or("empty observation")?;
    if header["type"] != "header" || header["schema"] != 1 {
        return Err("unsupported observation".into());
    }
    let binary = binary_override
        .or_else(|| header["image_path"].as_str())
        .ok_or("missing binary path")?;
    let bytes = std::fs::read(binary).map_err(|e| e.to_string())?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if header["image_sha256"] != digest {
        return Err("observation image SHA-256 mismatch".into());
    }
    let image = crate::image::load(binary)?;
    let mut events: Vec<&Value> = rows
        .iter()
        .filter(|r| r["type"] == "instruction" || r["type"] == "model_call")
        .collect();
    events.sort_by_key(|r| {
        (
            r["ordinal"].as_u64().unwrap_or(u64::MAX),
            if r["type"] == "model_call" { 0 } else { 1 },
        )
    });
    let roots: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["type"] == "instruction" && hex(&r["pc"]).ok() == Some(branch_pc))
        .collect();
    let (root_index, root) = roots
        .get(occurrence)
        .copied()
        .ok_or("branch occurrence not recorded")?;
    let raw = hex(&root["raw"])? as u32;
    if image.bytes_at(branch_pc, 4) != Some(raw.to_le_bytes().as_slice()) {
        return Err("branch bytes differ from image".into());
    }
    let target_reg = match crate::decode::classify(raw, branch_pc) {
        crate::decode::Flow::Br { rt } | crate::decode::Flow::Blr { rt } if rt < 31 => rt,
        _ => return Err("root must be an indirect branch/call".into()),
    };
    let mut needed = HashSet::from([VReg::Arch(ArchReg::Arm(ArmReg::X(target_reg)))]);
    let mut memory = BTreeSet::new();
    let mut flags = false;
    let mut nodes = Vec::new();
    let mut boundaries = Vec::new();
    let mut lifter = Aarch64Lifter::strict();
    let mut ctx = LiftContext::new(SourceArch::Aarch64);
    let mut considered = 0usize;
    for event in events[..root_index].iter().rev() {
        if considered >= limit {
            boundaries.push(json!({"reason":"instruction budget"}));
            break;
        }
        if needed.is_empty() && memory.is_empty() && !flags {
            break;
        }
        if event["type"] == "model_call" {
            let x0 = VReg::Arch(ArchReg::Arm(ArmReg::X(0)));
            let mut reason = Vec::new();
            if needed.remove(&x0) {
                reason.push("x0 is an external model result");
            }
            let mut hit = false;
            for m in event["memory"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|m| m["kind"] == "write")
            {
                for addr in event_bytes(m)? {
                    if memory.remove(&addr) {
                        hit = true;
                    }
                }
            }
            if hit {
                reason.push("external model wrote required memory");
            }
            if !reason.is_empty() {
                boundaries.push(json!({"kind":"model_call","pc":event["pc"],"name":event["name"],"args":event["args"],"reason":reason}));
            }
            continue;
        }
        considered += 1;
        let pc = hex(&event["pc"])?;
        let raw = hex(&event["raw"])? as u32;
        if image.bytes_at(pc, 4) != Some(raw.to_le_bytes().as_slice()) {
            return Err(format!("{pc:#x}: instruction bytes differ from image"));
        }
        if event["speculative"] != false || event["status"] != "Yield" {
            boundaries.push(json!({"pc":format!("{pc:#x}"),"reason":"non-retired or counterfactual instruction"}));
            break;
        }
        // RAX strict lifting does not model authenticated branch instructions
        // without PAuth execution state. In this harness's disabled-key policy,
        // a non-linking branch changes PC/BTYPE but does not define a GPR,
        // NZCV, or guest memory. This is a concrete-policy boundary only.
        if matches!(
            crate::decode::classify(raw, pc),
            crate::decode::Flow::Br { .. }
        ) && event["memory"].as_array().is_some_and(|m| m.is_empty())
            && event["before"]["x"] == event["after"]["x"]
            && ((hex(&event["before"]["pstate"])? ^ hex(&event["after"]["pstate"])?) & 0xf000_0000)
                == 0
        {
            continue;
        }
        let lift = match lifter.lift_insn(pc, &raw.to_le_bytes(), &mut ctx) {
            Ok(l) => l,
            Err(e) => {
                boundaries.push(
                    json!({"pc":format!("{pc:#x}"),"reason":format!("unsupported lift {e:?}")}),
                );
                break;
            }
        };
        let accesses = event["memory"].as_array().ok_or("missing memory events")?;
        let mut relevant = false;
        let mut unresolved = None;
        for op in lift.ops.iter().rev() {
            let write_hit = if op.kind.writes_memory() {
                accesses
                    .iter()
                    .filter(|m| m["kind"] == "write")
                    .map(event_bytes)
                    .collect::<Result<Vec<_>, _>>()?
                    .iter()
                    .any(|xs| xs.iter().any(|a| memory.contains(a)))
            } else {
                false
            };
            let dest_hit = op.kind.dests().iter().any(|d| needed.contains(d));
            let Some((src, reads_flags, writes_flags)) = deps(&op.kind) else {
                unresolved = Some(format!("unsupported dependency operation {:?}", op.kind));
                break;
            };
            let flag_hit = flags && writes_flags;
            if !dest_hit && !write_hit && !flag_hit {
                continue;
            }
            relevant = true;
            for d in op.kind.dests() {
                needed.remove(&d);
            }
            if flag_hit {
                flags = false;
            }
            if reads_flags {
                flags = true;
            }
            for r in src {
                needed.insert(r);
            }
            if matches!(op.kind, OpKind::Load { .. }) && dest_hit {
                let reads: Vec<_> = accesses.iter().filter(|m| m["kind"] == "read").collect();
                if reads.len() != 1 {
                    unresolved = Some("load has ambiguous recorded accesses".into());
                    break;
                }
                for addr in event_bytes(reads[0])? {
                    memory.insert(addr);
                }
            }
            if matches!(op.kind, OpKind::Store { .. }) && write_hit {
                for m in accesses.iter().filter(|m| m["kind"] == "write") {
                    for addr in event_bytes(m)? {
                        memory.remove(&addr);
                    }
                }
            }
        }
        if relevant {
            nodes.push(json!({"ordinal":event["ordinal"],"pc":format!("{pc:#x}"),"raw":format!("{raw:#010x}"),"ops":lift.ops.iter().map(|o|format!("{:?}",o.kind)).collect::<Vec<_>>(),"memory":event["memory"]}));
        }
        if let Some(reason) = unresolved {
            boundaries.push(json!({"pc":format!("{pc:#x}"),"reason":reason}));
            break;
        }
    }
    nodes.reverse();
    let mut regs: Vec<String> = needed.iter().map(|r| format!("{r:?}")).collect();
    regs.sort();
    Ok(
        json!({"schema":1,"kind":"dynamic_backward_slice","image_sha256":digest,"observation_harness_sha256":header["harness_sha256"],"root":{"pc":format!("{branch_pc:#x}"),"ordinal":root["ordinal"],"target_reg":format!("x{target_reg}"),"observed_target":root["after"]["pc"]},"nodes":nodes,"unresolved_boundaries":boundaries,"entry_dependencies":{"registers":regs,"flags":flags,"memory_bytes":memory.iter().map(|a|format!("{a:#x}")).collect::<Vec<_>>()},"trace_scope":header["capture_range"],"limitations":["concrete path dependencies only; not a proof of all paths","unknown instruction dependencies terminate the slice","external models are opaque boundaries","authenticated non-linking branches are skipped only under disabled-PAC concrete policy; BTYPE and native PAC behavior are not recovered"]}),
    )
}

//! Fail-closed, trace-scoped SMIR bit-vector analysis. Unsupported operations
//! stop the slice; concrete initial registers other than the selected symbolic
//! register are fixed to the recorded values.
use rax::smir::ir::ops::OpKind;
use rax::smir::ir::types::{
    Address, ArchReg, ArmReg, Condition, ExtendOp, ShiftOp, SourceArch, SrcOperand, VReg,
};
use rax::smir::lift::{aarch64::Aarch64Lifter, LiftContext, SmirLifter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

fn bv(v: u64) -> String {
    format!("#x{v:016x}")
}
fn crop(v: &str, n: u32) -> Result<String, String> {
    match n {
        64 => Ok(v.into()),
        8 | 16 | 32 => Ok(format!("((_ extract {} 0) {v})", n - 1)),
        _ => Err(format!("unsupported width {n}")),
    }
}
fn widen(v: String, n: u32) -> Result<String, String> {
    match n {
        64 => Ok(v),
        8 | 16 | 32 => Ok(format!("((_ zero_extend {}) {v})", 64 - n)),
        _ => Err(format!("unsupported width {n}")),
    }
}
fn parse_hex(v: &Value) -> Result<u64, String> {
    let s = v.as_str().ok_or("expected hex string")?;
    u64::from_str_radix(s.strip_prefix("0x").ok_or("expected 0x")?, 16).map_err(|e| e.to_string())
}

struct Symbolic {
    regs: HashMap<VReg, String>,
    n: String,
    z: String,
    c: String,
    v: String,
}
impl Symbolic {
    fn from_state(v: &Value, reg: u8) -> Result<Self, String> {
        let xs = v["x"].as_array().ok_or("missing register state")?;
        if xs.len() != 31 || reg > 30 {
            return Err("invalid register state".into());
        }
        let mut regs = HashMap::new();
        for (i, val) in xs.iter().enumerate() {
            regs.insert(
                VReg::Arch(ArchReg::Arm(ArmReg::X(i as u8))),
                if i == reg as usize {
                    "sym".into()
                } else {
                    bv(parse_hex(val)?)
                },
            );
        }
        regs.insert(
            VReg::Arch(ArchReg::Arm(ArmReg::Sp)),
            bv(parse_hex(&v["sp"])?),
        );
        let p = parse_hex(&v["pstate"])?;
        let bit = |n| {
            if p & (1u64 << n) != 0u64 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        };
        Ok(Self {
            regs,
            n: bit(31),
            z: bit(30),
            c: bit(29),
            v: bit(28),
        })
    }
    fn reg(&self, r: VReg) -> Result<String, String> {
        match r {
            VReg::Imm(x) => Ok(bv(x as u64)),
            _ => self
                .regs
                .get(&r)
                .cloned()
                .ok_or_else(|| format!("uninitialized register {r:?}")),
        }
    }
    fn operand(&self, o: &SrcOperand, w: u32) -> Result<String, String> {
        match o {
            SrcOperand::Reg(r) => crop(&self.reg(*r)?, w),
            SrcOperand::Imm(v) | SrcOperand::Imm64(v) => crop(&bv(*v as u64), w),
            SrcOperand::Shifted { reg, shift, amount } => {
                let a = crop(&self.reg(*reg)?, w)?;
                let b = crop(&bv(u64::from(*amount)), w)?;
                let op = match shift {
                    ShiftOp::Lsl => "bvshl",
                    ShiftOp::Lsr => "bvlshr",
                    ShiftOp::Asr => "bvashr",
                    ShiftOp::Ror => {
                        return Ok(format!("((_ rotate_right {}) {a})", u32::from(*amount) % w))
                    }
                    _ => return Err(format!("unsupported shift {shift:?}")),
                };
                Ok(format!("({op} {a} {b})"))
            }
            SrcOperand::Extended { reg, extend, shift } => {
                let (bits, signed) = match extend {
                    ExtendOp::Uxtb => (8, false),
                    ExtendOp::Uxth => (16, false),
                    ExtendOp::Uxtw => (32, false),
                    ExtendOp::Uxtx => (64, false),
                    ExtendOp::Sxtb => (8, true),
                    ExtendOp::Sxth => (16, true),
                    ExtendOp::Sxtw => (32, true),
                    ExtendOp::Sxtx => (64, true),
                };
                if bits > w {
                    return Err("extension wider than operation".into());
                }
                let a = crop(&self.reg(*reg)?, bits)?;
                let a = if bits == w {
                    a
                } else {
                    format!(
                        "((_ {}_extend {}) {a})",
                        if signed { "sign" } else { "zero" },
                        w - bits
                    )
                };
                Ok(format!("(bvshl {a} {})", crop(&bv(u64::from(*shift)), w)?))
            }
        }
    }
    fn put(&mut self, dst: VReg, v: String, w: u32) -> Result<(), String> {
        self.regs.insert(dst, widen(v, w)?);
        Ok(())
    }
    fn cond(&self, c: Condition) -> Result<String, String> {
        let (n, z, cflag, v) = (&self.n, &self.z, &self.c, &self.v);
        Ok(match c {
            Condition::Eq => z.clone(),
            Condition::Ne => format!("(not {z})"),
            Condition::Ult => format!("(not {cflag})"),
            Condition::Uge => cflag.clone(),
            Condition::Ugt => format!("(and {cflag} (not {z}))"),
            Condition::Ule => format!("(or (not {cflag}) {z})"),
            Condition::Slt => format!("(xor {n} {v})"),
            Condition::Sge => format!("(= {n} {v})"),
            Condition::Sgt => format!("(and (not {z}) (= {n} {v}))"),
            Condition::Sle => format!("(or {z} (xor {n} {v}))"),
            Condition::Negative => n.clone(),
            Condition::Positive => format!("(not {n})"),
            Condition::Overflow => v.clone(),
            Condition::NoOverflow => format!("(not {v})"),
            Condition::Always => "true".into(),
            _ => return Err(format!("unsupported condition {c:?}")),
        })
    }
    fn op(&mut self, op: &OpKind) -> Result<(), String> {
        match op {
            OpKind::Mov { dst, src, width } => {
                let w = width.bits();
                let val = self.operand(src, w)?;
                self.put(*dst, val, w)?;
            }
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                flags,
            }
            | OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                flags,
            }
            | OpKind::And {
                dst,
                src1,
                src2,
                width,
                flags,
            }
            | OpKind::Or {
                dst,
                src1,
                src2,
                width,
                flags,
            }
            | OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                if flags.updates_any() {
                    return Err("flag-writing arithmetic unsupported".into());
                }
                let w = width.bits();
                let a = crop(&self.reg(*src1)?, w)?;
                let b = self.operand(src2, w)?;
                let oper = match op {
                    OpKind::Add { .. } => "bvadd",
                    OpKind::Sub { .. } => "bvsub",
                    OpKind::And { .. } => "bvand",
                    OpKind::Or { .. } => "bvor",
                    _ => "bvxor",
                };
                self.put(*dst, format!("({oper} {a} {b})"), w)?;
            }
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                flags,
            }
            | OpKind::Shr {
                dst,
                src,
                amount,
                width,
                flags,
            }
            | OpKind::Sar {
                dst,
                src,
                amount,
                width,
                flags,
            } => {
                if flags.updates_any() {
                    return Err("flag-writing shift unsupported".into());
                }
                let w = width.bits();
                let a = crop(&self.reg(*src)?, w)?;
                let b = self.operand(amount, w)?;
                let oper = match op {
                    OpKind::Shl { .. } => "bvshl",
                    OpKind::Shr { .. } => "bvlshr",
                    _ => "bvashr",
                };
                self.put(*dst, format!("({oper} {a} {b})"), w)?;
            }
            OpKind::MulU {
                dst_lo,
                dst_hi: None,
                src1,
                src2,
                width,
                flags,
            }
            | OpKind::MulS {
                dst_lo,
                dst_hi: None,
                src1,
                src2,
                width,
                flags,
            } => {
                if flags.updates_any() {
                    return Err("flag-writing multiply unsupported".into());
                }
                let w = width.bits();
                let a = crop(&self.reg(*src1)?, w)?;
                let b = self.operand(src2, w)?;
                self.put(*dst_lo, format!("(bvmul {a} {b})"), w)?;
            }
            OpKind::MulAdd {
                dst,
                acc,
                src1,
                src2,
                width,
            }
            | OpKind::MulSub {
                dst,
                acc,
                src1,
                src2,
                width,
            } => {
                let w = width.bits();
                let a = crop(&self.reg(*acc)?, w)?;
                let b = crop(&self.reg(*src1)?, w)?;
                let c = crop(&self.reg(*src2)?, w)?;
                let operator = if matches!(op, OpKind::MulAdd { .. }) {
                    "bvadd"
                } else {
                    "bvsub"
                };
                self.put(*dst, format!("({operator} {a} (bvmul {b} {c}))"), w)?;
            }
            OpKind::Not { dst, src, width } => {
                let w = width.bits();
                let a = crop(&self.reg(*src)?, w)?;
                self.put(*dst, format!("(bvnot {a})"), w)?;
            }
            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } => {
                if flags.updates_any() {
                    return Err("flag-writing negation unsupported".into());
                }
                let w = width.bits();
                let a = crop(&self.reg(*src)?, w)?;
                self.put(*dst, format!("(bvneg {a})"), w)?;
            }
            OpKind::Cmp { src1, src2, width } => {
                let w = width.bits();
                let a = crop(&self.reg(*src1)?, w)?;
                let b = self.operand(src2, w)?;
                let d = format!("(bvsub {a} {b})");
                self.z = format!("(= {d} (_ bv0 {w}))");
                self.n = format!("(= ((_ extract {} {}) {d}) #b1)", w - 1, w - 1);
                self.c = format!("(bvuge {a} {b})");
                self.v=format!("(and (not (= ((_ extract {} {}) {a}) ((_ extract {} {}) {b}))) (not (= ((_ extract {} {}) {a}) ((_ extract {} {}) {d}))))",w-1,w-1,w-1,w-1,w-1,w-1,w-1,w-1);
            }
            OpKind::TestCondition { dst, cond } => {
                let c = self.cond(*cond)?;
                self.put(
                    *dst,
                    format!("(ite {c} #x0000000000000001 #x0000000000000000)"),
                    64,
                )?;
            }
            OpKind::Select {
                dst,
                cond,
                src_true,
                src_false,
                width,
            } => {
                let w = width.bits();
                let c = self.reg(*cond)?;
                let t = crop(&self.reg(*src_true)?, w)?;
                let f = crop(&self.reg(*src_false)?, w)?;
                self.put(
                    *dst,
                    format!("(ite (not (= {c} #x0000000000000000)) {t} {f})"),
                    w,
                )?;
            }
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } => {
                let from = from_width.bits();
                let to = to_width.bits();
                let n = to.checked_sub(from).ok_or("invalid sign extension")?;
                let a = crop(&self.reg(*src)?, from)?;
                let value = if n == 0 {
                    a
                } else {
                    format!("((_ sign_extend {n}) {a})")
                };
                self.put(*dst, value, to)?;
            }
            OpKind::Truncate {
                dst, src, to_width, ..
            } => {
                let w = to_width.bits();
                let a = crop(&self.reg(*src)?, w)?;
                self.put(*dst, a, w)?;
            }
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width,
            } => {
                let a = crop(&self.reg(*src)?, from_width.bits())?;
                let n = to_width
                    .bits()
                    .checked_sub(from_width.bits())
                    .ok_or("invalid zero extension")?;
                let v = if n == 0 {
                    a
                } else {
                    format!("((_ zero_extend {n}) {a})")
                };
                self.put(*dst, v, to_width.bits())?;
            }
            _ => return Err(format!("unsupported SMIR operation {op:?}")),
        }
        Ok(())
    }
}
fn solve(solver: &str, script: &str) -> Result<String, String> {
    let mut child = Command::new(solver)
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("solver {solver}: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() || stdout.contains("(error") {
        return Err(format!(
            "solver error: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}
fn hx(s: &str) -> Vec<u64> {
    s.split(|c: char| !(c.is_ascii_hexdigit() || c == '#' || c == 'x'))
        .filter_map(|part| part.strip_prefix("#x"))
        .filter_map(|h| u64::from_str_radix(h, 16).ok())
        .collect()
}
fn query(solver: &str, expr: &str, constraint: &str) -> Result<(String, Vec<u64>), String> {
    let head=format!("(set-option :timeout 5000)\n(set-logic QF_BV)\n(declare-fun sym () (_ BitVec 64))\n(define-fun out () (_ BitVec 64) {expr})\n(assert {constraint})\n");
    let status = solve(solver, &format!("{head}(check-sat)\n"))?;
    let status = status.trim().to_string();
    if status == "sat" {
        let model = solve(
            solver,
            &format!("{head}(check-sat)\n(get-value (sym out))\n"),
        )?;
        Ok((status, hx(&model)))
    } else {
        Ok((status, vec![]))
    }
}

pub fn analyze(
    path: &str,
    start: u64,
    end: u64,
    symbolic: u8,
    result: u8,
    solver: &str,
    binary_override: Option<&str>,
    replay_paths: &[String],
    resolve: bool,
) -> Result<Value, String> {
    if start >= end || symbolic > 30 || result > 30 {
        return Err("invalid slice or register".into());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let rows: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let version_out = Command::new(solver)
        .arg("--version")
        .output()
        .map_err(|e| format!("solver {solver}: {e}"))?;
    if !version_out.status.success() {
        return Err(format!("solver {solver} version query failed"));
    }
    let solver_version = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_string();
    let header = rows.first().ok_or("empty observation")?;
    if header["type"] != "header" || header["schema"] != 1 {
        return Err("unsupported observation schema".into());
    }
    let binary = binary_override
        .or_else(|| header["image_path"].as_str())
        .ok_or("missing binary path")?;
    let image_bytes = std::fs::read(binary).map_err(|e| format!("{binary}: {e}"))?;
    let digest = format!("{:x}", Sha256::digest(&image_bytes));
    if header["image_sha256"] != digest {
        return Err("observation image SHA-256 mismatch".into());
    }
    let image = crate::image::load(binary)?;
    let mut selected = Vec::new();
    for r in &rows {
        if r["type"] == "instruction" {
            let pc = parse_hex(&r["pc"])?;
            if pc >= start && pc < end {
                selected.push(r);
            }
        }
    }
    if selected.is_empty() {
        return Err("no instructions in slice".into());
    }
    for (i, r) in selected.iter().enumerate() {
        let pc = parse_hex(&r["pc"])?;
        let raw = parse_hex(&r["raw"])? as u32;
        if image.bytes_at(pc, 4) != Some(raw.to_le_bytes().as_slice()) {
            return Err(format!("instruction bytes at {pc:#x} differ from image"));
        }
        let accesses = r["memory"].as_array().ok_or("missing memory events")?;
        if accesses
            .iter()
            .any(|e| e["kind"] != "read" || e["ok"] != true)
        {
            return Err(format!(
                "unsupported or faulted memory operation at {pc:#x}"
            ));
        }
        if i > 0
            && (r["ordinal"].as_u64() != selected[i - 1]["ordinal"].as_u64().map(|n| n + 1)
                || r["before"] != selected[i - 1]["after"])
        {
            return Err(format!("non-contiguous recorded machine state at {pc:#x}"));
        }
        if parse_hex(&r["after"]["pc"])? != pc.wrapping_add(4) {
            return Err(format!("non-fallthrough state at {pc:#x}"));
        }
        if pc != start + 4 * i as u64 || r["speculative"] != false || r["status"] != "Yield" {
            return Err(format!(
                "slice is not a contiguous non-speculative retired sequence at {pc:#x}"
            ));
        }
    }
    if parse_hex(&selected.last().unwrap()["pc"])? + 4 != end {
        return Err("slice does not reach exclusive end".into());
    }
    let first = selected[0];
    let mut sm = Symbolic::from_state(&first["before"], symbolic)?;
    let init = parse_hex(&first["before"]["x"][symbolic as usize])?;
    let mut lifter = Aarch64Lifter::strict();
    let mut ctx = LiftContext::new(SourceArch::Aarch64);
    let mut lifts = Vec::new();
    let mut divergences = Vec::new();
    let mut memory_assumptions = Vec::new();
    for r in &selected {
        let pc = parse_hex(&r["pc"])?;
        let raw = parse_hex(&r["raw"])? as u32;
        let lift = lifter
            .lift_insn(pc, &raw.to_le_bytes(), &mut ctx)
            .map_err(|e| format!("lift {pc:#x}: {e:?}"))?;
        if !matches!(
            lift.control_flow,
            rax::smir::lift::ControlFlow::Fallthrough | rax::smir::lift::ControlFlow::NextInsn
        ) {
            return Err(format!("non-fallthrough at {pc:#x}"));
        }
        let mut loads = 0usize;
        for op in &lift.ops {
            match &op.kind {
                OpKind::Load {
                    dst,
                    addr,
                    width,
                    sign,
                } => {
                    let assumption = observed_load(&mut sm, *dst, addr, *width, *sign, r, solver)
                        .map_err(|e| format!("{pc:#x}: {e}"))?;
                    memory_assumptions.push(assumption);
                    loads += 1;
                }
                _ => sm.op(&op.kind).map_err(|e| format!("{pc:#x}: {e}"))?,
            }
        }
        if loads != r["memory"].as_array().unwrap().len() {
            return Err(format!("{pc:#x}: lifted loads and observed reads differ"));
        }
        for i in 0..31 {
            let got = sm.reg(VReg::Arch(ArchReg::Arm(ArmReg::X(i))))?;
            let want = parse_hex(&r["after"]["x"][i as usize])?;
            divergences.push(format!("(not (= {got} {}))", bv(want)));
        }
        let p = parse_hex(&r["after"]["pstate"])?;
        for (expr, bit) in [(&sm.n, 31), (&sm.z, 30), (&sm.c, 29), (&sm.v, 28)] {
            let want = if (p & (1u64 << bit)) != 0u64 {
                "true"
            } else {
                "false"
            };
            divergences.push(format!("(not (= {expr} {want}))"));
        }
        if r["before"]["v"] != r["after"]["v"]
            || r["before"]["sp"] != r["after"]["sp"]
            || r["before"]["fpcr"] != r["after"]["fpcr"]
            || r["before"]["fpsr"] != r["after"]["fpsr"]
            || (parse_hex(&r["before"]["pstate"])? & !0xf000_0000) != (p & !0xf000_0000)
        {
            return Err(format!("unsupported architectural effect at {pc:#x}"));
        }
        lifts.push(json!({"pc":format!("{pc:#x}"),"raw":format!("{raw:#010x}"),"ops":lift.ops.iter().map(|op|format!("{:?}",op.kind)).collect::<Vec<_>>() }));
    }
    let expr = sm.reg(VReg::Arch(ArchReg::Arm(ArmReg::X(result))))?;
    let observed = parse_hex(&selected.last().unwrap()["after"]["x"][result as usize])?;
    let (check, _) = query(
        solver,
        &expr,
        &format!("(and (= sym {}) (or {}))", bv(init), divergences.join(" ")),
    )?;
    if check != "unsat" {
        return Err(format!("lift fails observed concrete value check: {check}"));
    }
    let mut cases = Vec::new();
    let mut blocked = Vec::new();
    let mut exhaustive = false;
    for _ in 0..16 {
        let constraint = if blocked.is_empty() {
            "true".into()
        } else {
            format!("(and {})", blocked.join(" "))
        };
        let (status, values) = query(solver, &expr, &constraint)?;
        if status == "unsat" {
            exhaustive = true;
            break;
        }
        if status != "sat" {
            break;
        }
        if values.len() != 2 {
            return Err(format!("unrecognized solver model: {values:?}"));
        }
        let (value, input) = (values[1], values[0]);
        cases.push(json!({"result":format!("{value:#x}"),"witness":format!("{input:#x}"),"status":"solver_candidate_not_replayed"}));
        blocked.push(format!("(not (= out {}))", bv(value)));
    }
    let mut relation = Value::Null;
    if cases.len() == 2 && exhaustive {
        let (_, zero) = query(solver, &expr, "(= sym #x0000000000000000)")?;
        let (_, nonzero) = query(solver, &expr, "(not (= sym #x0000000000000000))")?;
        if zero.len() == 2 && nonzero.len() == 2 {
            let form = format!(
                "(ite (= sym #x0000000000000000) {} {})",
                bv(zero[1]),
                bv(nonzero[1])
            );
            let (s, _) = query(solver, &expr, &format!("(not (= out {form}))"))?;
            if s == "unsat" {
                relation = json!({"predicate":format!("x{symbolic} == 0"),"when_true":format!("{:#x}",zero[1]),"when_false":format!("{:#x}",nonzero[1]),"proof":"unsat for negated relation"});
            }
        }
    }
    let mut all_paths = vec![path.to_string()];
    all_paths.extend(replay_paths.iter().cloned());
    let target_evidence = if resolve {
        resolve_table(
            &all_paths, header, first, end, symbolic, result, &cases, &image, &selected, &expr,
            solver,
        )?
    } else {
        Value::Null
    };
    Ok(
        json!({"target_evidence":target_evidence,"solver":{"command":solver,"version":solver_version,"timeout_ms":5000},"lifter":"RAX ee96791b42237862178f1774afaf0f1ee8570ce9 strict AArch64 SMIR","schema":1,"image_sha256":header["image_sha256"],"observation_harness_sha256":header["harness_sha256"],"slice":{"start":format!("{start:#x}"),"end_exclusive":format!("{end:#x}"),"input_register":format!("x{symbolic}"),"result_register":format!("x{result}"),"initial_input":format!("{init:#x}"),"observed_result":format!("{observed:#x}"),"instructions":selected.len()},"assumptions":["all non-symbolic initial registers and flags fixed to recorded state","straight-line slice only; bounded loads are specialized to recorded page snapshots","RAX strict SMIR lift semantics are assumed; checked against recorded registers and flags at every slice instruction","solver witness does not establish reachability from function entry"],"lift":lifts,"memory_assumptions":memory_assumptions,"expression_smtlib":expr,"concrete_consistency":check,"result_candidates":cases,"exhaustive_under_assumptions":exhaustive,"zero_test_relation":relation}),
    )
}

/// Resolve an immediately following `LDR Xt,[Xn,Wm,UXTW #3]` only when the
/// actual observed page, access, and later indirect transfer corroborate it.
fn resolve_table(
    paths: &[String],
    baseline_header: &Value,
    baseline_first: &Value,
    end: u64,
    symbolic: u8,
    index_reg: u8,
    candidates: &[Value],
    image: &crate::image::Image,
    baseline_slice: &[&Value],
    expr: &str,
    solver: &str,
) -> Result<Value, String> {
    let mut runs = Vec::new();
    let mut values: HashMap<u64, (u64, Vec<Value>)> = HashMap::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let rows: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let header = rows.first().ok_or("empty replay observation")?;
        if header["schema"] != 1 || header["image_sha256"] != baseline_header["image_sha256"] {
            return Err(format!("{path}: observation image/schema mismatch"));
        }
        let instructions: Vec<&Value> =
            rows.iter().filter(|r| r["type"] == "instruction").collect();
        let replay_slice: Vec<_> = instructions
            .iter()
            .filter(|r| hex_in_range(r, baseline_slice))
            .copied()
            .collect();
        if replay_slice.len() != baseline_slice.len() {
            return Err(format!("{path}: slice length differs"));
        }
        for (i, (record, reference)) in replay_slice.iter().zip(baseline_slice.iter()).enumerate() {
            let pc = parse_hex(&record["pc"])?;
            let raw = parse_hex(&record["raw"])? as u32;
            if record["pc"] != reference["pc"]
                || record["raw"] != reference["raw"]
                || record["status"] != "Yield"
                || record["speculative"] != false
                || image.bytes_at(pc, 4) != Some(raw.to_le_bytes().as_slice())
                || parse_hex(&record["after"]["pc"])? != pc + 4
            {
                return Err(format!("{path}: mismatched replay slice at {pc:#x}"));
            }
            if i > 0
                && (record["ordinal"].as_u64()
                    != replay_slice[i - 1]["ordinal"].as_u64().map(|n| n + 1)
                    || record["before"] != replay_slice[i - 1]["after"])
            {
                return Err(format!("{path}: noncontiguous replay state at {pc:#x}"));
            }
        }
        let first = instructions
            .iter()
            .find(|r| r["pc"] == baseline_first["pc"])
            .ok_or_else(|| format!("{path}: slice entry missing"))?;
        let b = &baseline_first["before"];
        let a = &first["before"];
        for key in ["sp", "pstate", "v", "fpcr", "fpsr", "tpidr", "tpidrro"] {
            if a[key] != b[key] {
                return Err(format!("{path}: frozen initial {key} differs"));
            }
        }
        for i in 0..31 {
            if i != symbolic as usize && a["x"][i] != b["x"][i] {
                return Err(format!("{path}: frozen x{i} differs"));
            }
        }
        let matches: Vec<_> = instructions
            .iter()
            .enumerate()
            .filter(|(_, r)| r["pc"] == format!("{end:#x}"))
            .collect();
        if matches.len() != 1 {
            return Err(format!("{path}: expected one table-load observation"));
        }
        let (load_idx, load) = matches[0];
        if load["speculative"] != false || load["status"] != "Yield" {
            return Err(format!("{path}: table load is speculative or faulted"));
        }
        let raw = parse_hex(&load["raw"])? as u32;
        if raw & 0xffe0_fc00 != 0xf860_5800 {
            return Err(format!(
                "{path}: following instruction is not LDR Xt,[Xn,Wm,UXTW #3]"
            ));
        }
        if image.bytes_at(end, 4) != Some(raw.to_le_bytes().as_slice()) {
            return Err(format!("{path}: table-load bytes differ from image"));
        }
        let rn = ((raw >> 5) & 31) as usize;
        let rm = ((raw >> 16) & 31) as u8;
        let rt = (raw & 31) as usize;
        if rm != index_reg || rn == 31 || rt == 31 {
            return Err(format!("{path}: table load register mismatch"));
        }
        let base = parse_hex(&load["before"]["x"][rn])?;
        let observed_index = parse_hex(&load["before"]["x"][rm as usize])? as u32 as u64;
        let input = parse_hex(&first["before"]["x"][symbolic as usize])?;
        let (check, _) = query(
            solver,
            expr,
            &format!(
                "(and (= sym {}) (not (= out {})))",
                bv(input),
                bv(observed_index)
            ),
        )?;
        if check != "unsat" {
            return Err(format!(
                "{path}: observed index does not match slice expression ({check})"
            ));
        }
        let address = base
            .checked_add(observed_index * 8)
            .ok_or("table address overflow")?;
        let reads = load["memory"].as_array().ok_or("load access missing")?;
        let read = reads
            .iter()
            .find(|r| {
                r["kind"] == "read"
                    && r["ok"] == true
                    && parse_hex(&r["address"]).ok() == Some(address)
            })
            .ok_or_else(|| format!("{path}: observed load access mismatch"))?;
        let bytes = read["bytes"].as_str().ok_or("missing load bytes")?;
        if bytes.len() != 16 {
            return Err(format!("{path}: expected 8-byte table load"));
        }
        let parse_bytes = |hex: &str| -> Result<Vec<u8>, String> {
            if hex.len() % 2 != 0 {
                return Err("invalid byte string".into());
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
                .collect()
        };
        let loaded = u64::from_le_bytes(parse_bytes(bytes)?.try_into().map_err(|_| "bad pointer")?);
        if parse_hex(&load["after"]["x"][rt])? != loaded {
            return Err(format!("{path}: loaded register mismatch"));
        }
        let mut transfer = None;
        let mut prior = load;
        for r in instructions.iter().skip(load_idx + 1).take(8) {
            if r["ordinal"].as_u64() != prior["ordinal"].as_u64().map(|n| n + 1)
                || r["before"] != prior["after"]
            {
                return Err(format!("{path}: noncontiguous branch-region state"));
            }
            prior = r;
            if r["speculative"] != false || r["status"] != "Yield" {
                break;
            }
            let pc = parse_hex(&r["pc"])?;
            let raw = parse_hex(&r["raw"])? as u32;
            if image.bytes_at(pc, 4) != Some(raw.to_le_bytes().as_slice()) {
                return Err(format!(
                    "{path}: branch-region instruction differs from image"
                ));
            }
            if parse_hex(&r["before"]["x"][rt])? != loaded {
                break;
            }
            if matches!(crate::decode::classify(raw,pc),crate::decode::Flow::Br{rt:r} if r as usize==rt)
            {
                let target = parse_hex(&r["after"]["pc"])?;
                if target != loaded {
                    return Err(format!(
                        "{path}: indirect transfer does not match loaded target"
                    ));
                }
                transfer = Some((pc, target));
                break;
            }
        }
        let (branch, target) =
            transfer.ok_or_else(|| format!("{path}: no corroborating indirect branch"))?;
        let origin = if header["restored_from"].is_null() {
            "observed_from_entry_in_modeled_execution"
        } else {
            "observed_after_checkpoint_restore"
        };
        let evidence = json!({"observation":path,"entry":header["entry"],"heap_size":header["heap_size"],"initial_symbolic_input":format!("{input:#x}"),"index":format!("{observed_index:#x}"),"table_address":format!("{address:#x}"),"branch_pc":format!("{branch:#x}"),"target":format!("{target:#x}"),"status":origin});
        for candidate in candidates {
            let idx = parse_hex(&candidate["result"])?;
            if idx > u32::MAX as u64 {
                continue;
            }
            let addr = base.checked_add(idx * 8).ok_or("table address overflow")?;
            for page in load["read_pages"]
                .as_array()
                .ok_or("missing page snapshots")?
            {
                let pagebase = parse_hex(&page["base"])?;
                let data = parse_bytes(page["bytes"].as_str().ok_or("missing page bytes")?)?;
                if let Some(off) = addr
                    .checked_sub(pagebase)
                    .and_then(|v| usize::try_from(v).ok())
                {
                    if let Some(slice) = data.get(off..off.saturating_add(8)) {
                        let val = u64::from_le_bytes(slice.try_into().unwrap());
                        if let Some((prior, _)) = values.get(&idx) {
                            if *prior != val {
                                return Err(format!(
                                    "{path}: table snapshot differs for index {idx:#x}"
                                ));
                            }
                        }
                        let entry = values.entry(idx).or_insert((val, vec![]));
                        if idx == observed_index && val != target {
                            return Err(format!(
                                "{path}: observed table value disagrees with page snapshot"
                            ));
                        }
                        if idx == observed_index && val == target {
                            entry.1.push(evidence.clone());
                        }
                    }
                }
            }
        }
        runs.push(evidence);
    }
    let table=candidates.iter().map(|c|{let idx=parse_hex(&c["result"]).unwrap();match values.get(&idx){Some((val,obs))=>json!({"index":format!("{idx:#x}"),"target":format!("{val:#x}"),"status":if obs.is_empty(){"snapshot_only"}else{"observed_in_modeled_execution"},"observations":obs}),None=>json!({"index":format!("{idx:#x}"),"target":null,"status":"unresolved_outside_snapshot"})}}).collect::<Vec<_>>();
    Ok(
        json!({"kind":"observed_indexed_pointer_table","load_pc":format!("{end:#x}"),"entries":table,"runs":runs,"assumptions":["table values are snapshots from modeled executions, not proven invariant","PAC keys disabled; observed target is not hardware authentication evidence"]}),
    )
}

/// Lower a single bounded read to an ITE over all solver-enumerated addresses.
/// Snapshot bytes are assumptions, not general facts about mutable memory.
fn observed_load(
    sm: &mut Symbolic,
    dst: VReg,
    addr: &Address,
    width: rax::smir::ir::types::MemWidth,
    sign: rax::smir::ir::types::SignExtend,
    record: &Value,
    solver: &str,
) -> Result<Value, String> {
    let addr_expr = match addr {
        Address::Direct(r) => sm.reg(*r)?,
        Address::BaseOffset { base, offset, .. } => {
            format!("(bvadd {} {})", sm.reg(*base)?, bv(*offset as u64))
        }
        Address::Absolute(a) => bv(*a),
        _ => return Err(format!("unsupported load address {addr:?}")),
    };
    let bytes = width.bytes() as usize;
    if !matches!(bytes, 1 | 2 | 4 | 8) {
        return Err("unsupported load width".into());
    }
    let reads = record["memory"].as_array().ok_or("missing memory events")?;
    if reads.len() != 1 || reads[0]["kind"] != "read" || reads[0]["ok"] != true {
        return Err("requires exactly one successful read".into());
    }
    let observed_addr = parse_hex(&reads[0]["address"])?;
    let observed_bytes = reads[0]["bytes"].as_str().ok_or("missing read bytes")?;
    if observed_bytes.len() != bytes * 2 {
        return Err("read width mismatch".into());
    }
    let mut blocked = Vec::new();
    let mut locations = Vec::new();
    let mut exhausted = false;
    for _ in 0..16 {
        let constraint = if blocked.is_empty() {
            "true".into()
        } else {
            format!("(and {})", blocked.join(" "))
        };
        let (status, vals) = query(solver, &addr_expr, &constraint)?;
        if status == "unsat" {
            exhausted = true;
            break;
        }
        if status != "sat" || vals.len() != 2 {
            return Err(format!("address enumeration {status}: {vals:?}"));
        }
        let address = vals[1];
        let mut found = None;
        for page in record["read_pages"]
            .as_array()
            .ok_or("missing read page snapshot")?
        {
            let base = parse_hex(&page["base"])?;
            let hex = page["bytes"].as_str().ok_or("missing page bytes")?;
            if let Some(offset) = address
                .checked_sub(base)
                .and_then(|v| usize::try_from(v).ok())
            {
                if let Some(chunk) = hex.get(
                    offset.saturating_mul(2)..offset.saturating_mul(2).saturating_add(bytes * 2),
                ) {
                    let data = (0..bytes)
                        .map(|i| {
                            u8::from_str_radix(&chunk[2 * i..2 * i + 2], 16)
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut raw = [0u8; 8];
                    raw[..bytes].copy_from_slice(&data);
                    found = Some(u64::from_le_bytes(raw));
                    break;
                }
            }
        }
        let raw =
            found.ok_or_else(|| format!("candidate load address {address:#x} not captured"))?;
        if address == observed_addr {
            let data = (0..bytes)
                .map(|i| {
                    u8::from_str_radix(&observed_bytes[2 * i..2 * i + 2], 16)
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut actual = [0; 8];
            actual[..bytes].copy_from_slice(&data);
            if raw != u64::from_le_bytes(actual) {
                return Err("read and page snapshot disagree".into());
            }
        }
        let value = if matches!(sign, rax::smir::ir::types::SignExtend::Sign) && bytes < 8 {
            let shift = 64 - bytes * 8;
            (((raw << shift) as i64) >> shift) as u64
        } else {
            raw
        };
        locations.push((address, value));
        blocked.push(format!("(not (= out {}))", bv(address)));
    }
    if !exhausted {
        return Err("load address domain exceeds 16 values or solver returned unknown".into());
    }
    if !locations.iter().any(|(a, _)| *a == observed_addr) {
        return Err("observed read address absent from symbolic domain".into());
    }
    let mut value = bv(0);
    for (address, entry) in locations.iter().rev() {
        value = format!(
            "(ite (= {addr_expr} {}) {} {value})",
            bv(*address),
            bv(*entry)
        );
    }
    sm.regs.insert(dst, value);
    Ok(
        json!({"pc":record["pc"],"width_bytes":bytes,"addresses":locations.iter().map(|(a,v)|json!({"address":format!("{a:#x}"),"value":format!("{v:#x}")})).collect::<Vec<_>>(),"exhaustive_address_domain":true,"status":"values_assumed_from_observed_page_snapshot"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rax::smir::ir::flags::FlagUpdate;
    use rax::smir::ir::types::{ExtendOp, OpWidth};

    #[test]
    fn extended_signed_operand_obeys_32_bit_wrap() {
        let x0 = VReg::Arch(ArchReg::Arm(ArmReg::X(0)));
        let x1 = VReg::Arch(ArchReg::Arm(ArmReg::X(1)));
        let state = json!({"x":vec!["0x0";31],"sp":"0x0","pstate":"0x0"});
        let mut sm = Symbolic::from_state(&state, 0).unwrap();
        sm.op(&OpKind::Add {
            dst: x1,
            src1: x0,
            src2: SrcOperand::Extended {
                reg: x0,
                extend: ExtendOp::Sxtb,
                shift: 1,
            },
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        })
        .unwrap();
        let expr = sm.reg(x1).unwrap();
        // 0x80 + (sign_extend(0x80) << 1) modulo 2^32 = 0xffffff80.
        let (status, _) = query(
            "z3",
            &expr,
            &format!(
                "(and (= sym {}) (not (= out {})))",
                bv(0x80),
                bv(0xffff_ff80)
            ),
        )
        .unwrap();
        assert_eq!(status, "unsat");
    }
    #[test]
    fn sign_extension_and_multiply_add_are_width_bounded() {
        let x0 = VReg::Arch(ArchReg::Arm(ArmReg::X(0)));
        let x1 = VReg::Arch(ArchReg::Arm(ArmReg::X(1)));
        let x2 = VReg::Arch(ArchReg::Arm(ArmReg::X(2)));
        let state = json!({"x":vec!["0x0";31],"sp":"0x0","pstate":"0x0"});
        let mut sm = Symbolic::from_state(&state, 0).unwrap();
        sm.op(&OpKind::SignExtend {
            dst: x1,
            src: x0,
            from_width: OpWidth::W8,
            to_width: OpWidth::W64,
        })
        .unwrap();
        sm.op(&OpKind::MulAdd {
            dst: x2,
            acc: x0,
            src1: x1,
            src2: x0,
            width: OpWidth::W64,
        })
        .unwrap();
        let expr = sm.reg(x2).unwrap();
        let (status, _) = query(
            "z3",
            &expr,
            &format!("(and (= sym {}) (not (= out {})))", bv(0xff), bv(0)),
        )
        .unwrap();
        assert_eq!(status, "unsat");
    }
}

fn hex_in_range(record: &Value, baseline: &[&Value]) -> bool {
    let Some(first) = baseline.first().and_then(|r| parse_hex(&r["pc"]).ok()) else {
        return false;
    };
    let Some(last) = baseline.last().and_then(|r| parse_hex(&r["pc"]).ok()) else {
        return false;
    };
    parse_hex(&record["pc"]).is_ok_and(|pc| pc >= first && pc <= last)
}

//! A64 control-flow classification.
//!
//! Only the bits that matter to a control-flow reconstructor are decoded
//! here: direct and conditional branches, register branches (including the
//! arm64e authenticated forms), calls, returns, and the EL0 traps. Operand
//! text comes from the RAX decoder; branch targets come from the encoding so
//! the reconstruction does not depend on disassembler formatting.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// `B.cond`, `CBZ`, `CBNZ`, `TBZ`, `TBNZ`; `alternate` is the not-taken
    /// address. `rt` is the tested register (CBZ/TBZ) or 31 for flag tests.
    Cond {
        target: u64,
        alternate: u64,
        cond: u8,
        rt: u8,
        bit: Option<u8>,
    },
    /// Unconditional direct `B`.
    Uncond {
        target: u64,
    },
    /// `BL`.
    CallDirect {
        target: u64,
    },
    /// `BR`/`BRAA`/`BRAB` and friends.
    Br {
        rt: u8,
    },
    /// `BLR`/`BLRAA`/`BLRAB`.
    Blr {
        rt: u8,
    },
    /// `RET`/`RETAA`/`RETAB`.
    Ret {
        rt: u8,
    },
    Svc {
        imm: u16,
    },
    Brk {
        imm: u16,
    },
    Wfi,
    Other,
}

impl Flow {}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Classify one A64 instruction at `pc`.
pub fn classify(raw: u32, pc: u64) -> Flow {
    // B / BL: 000101 / 100101 in bits 31:26.
    if (raw & 0x7c00_0000) == 0x1400_0000 {
        let target = pc.wrapping_add(sign_extend(u64::from(raw & 0x03ff_ffff) << 2, 28));
        if raw & 0x8000_0000 != 0 {
            return Flow::CallDirect { target };
        }
        return Flow::Uncond { target };
    }
    // B.cond: 0101010 0 imm19 0 cond.
    if (raw & 0xff00_0010) == 0x5400_0000 {
        let cond = (raw & 0xf) as u8;
        let target = pc.wrapping_add(sign_extend(u64::from((raw >> 5) & 0x7ffff) << 2, 21));
        if cond >= 0xe {
            // AL / NV behave as an unconditional direct branch.
            return Flow::Uncond { target };
        }
        return Flow::Cond {
            target,
            alternate: pc.wrapping_add(4),
            cond,
            rt: 31,
            bit: None,
        };
    }
    // CBZ / CBNZ: sf 011010 0/1 imm19 Rt.
    if (raw & 0x7e00_0000) == 0x3400_0000 {
        let target = pc.wrapping_add(sign_extend(u64::from((raw >> 5) & 0x7ffff) << 2, 21));
        return Flow::Cond {
            target,
            alternate: pc.wrapping_add(4),
            cond: if raw & 0x0100_0000 != 0 { 1 } else { 0 },
            rt: (raw & 31) as u8,
            bit: None,
        };
    }
    // TBZ / TBNZ: b5 011011 0/1 b40 imm14 Rt.
    if (raw & 0x7e00_0000) == 0x3600_0000 {
        let b5 = (raw >> 31) & 1;
        let b40 = (raw >> 19) & 0x1f;
        let bit = ((b5 << 5) | b40) as u8;
        let target = pc.wrapping_add(sign_extend(u64::from((raw >> 5) & 0x3fff) << 2, 16));
        return Flow::Cond {
            target,
            alternate: pc.wrapping_add(4),
            cond: if raw & 0x0100_0000 != 0 { 1 } else { 0 },
            rt: (raw & 31) as u8,
            bit: Some(bit),
        };
    }
    // Branch (register), including the arm64e authenticated forms:
    // 1101011x ... Rn 000000. Plain BR/BLR/RET are matched exactly; the
    // PAC variants are identified by mnemonic because their opc fields and
    // optional modifier registers differ.
    if (raw & 0xfe00_0000) == 0xd600_0000 {
        let rt = ((raw >> 5) & 31) as u8;
        if (raw & 0xffff_fc1f) == 0xd61f_0000 {
            return Flow::Br { rt };
        }
        if (raw & 0xffff_fc1f) == 0xd63f_0000 {
            return Flow::Blr { rt };
        }
        if (raw & 0xffff_fc1f) == 0xd65f_0000 {
            return Flow::Ret { rt };
        }
        let m = mnemonic(raw);
        if m.starts_with("blr") {
            return Flow::Blr { rt };
        }
        if m.starts_with("ret") {
            return Flow::Ret { rt: 30 };
        }
        if m.starts_with("br") {
            return Flow::Br { rt };
        }
    }
    // SVC #imm16.
    if (raw & 0xffe0_001f) == 0xd400_0001 {
        return Flow::Svc {
            imm: ((raw >> 5) & 0xffff) as u16,
        };
    }
    // BRK #imm16.
    if (raw & 0xffe0_001f) == 0xd420_0000 {
        return Flow::Brk {
            imm: ((raw >> 5) & 0xffff) as u16,
        };
    }
    // WFI / WFE / YIELD.
    if raw == 0xd503_207f || raw == 0xd503_205f || raw == 0xd503_203f {
        return Flow::Wfi;
    }
    Flow::Other
}

/// Mnemonic text from the RAX A64 decoder. Kept best-effort: unknown words
/// report `udf`.
pub fn mnemonic(raw: u32) -> String {
    use rax::isa::arm::decoder::aarch64::Aarch64Decoder;
    match Aarch64Decoder::decode(raw) {
        Ok(d) => format!("{:?}", d.mnemonic).to_ascii_lowercase(),
        Err(_) => "udf".to_string(),
    }
}

/// RAX-decoded operand text in A64 assembly syntax.
pub fn disasm(raw: u32) -> String {
    // UBFM's LSL alias encodes (immr, imms); RAX's generic operand
    // formatter exposes those raw fields rather than the assembly shift.
    let sf = (raw >> 31) & 1;
    let n = (raw >> 22) & 1;
    let immr = (raw >> 16) & 63;
    let imms = (raw >> 10) & 63;
    let width = if sf == 0 { 32 } else { 64 };
    if (raw & 0x7f80_0000) == 0x5300_0000 && n == sf && immr > 0 && immr < width && imms + 1 == immr
    {
        let name = |r: u32| {
            if r == 31 {
                if sf == 0 {
                    "wzr".into()
                } else {
                    "xzr".into()
                }
            } else {
                format!("{}{r}", if sf == 0 { "w" } else { "x" })
            }
        };
        return format!(
            "lsl {}, {}, #{}",
            name(raw & 31),
            name((raw >> 5) & 31),
            width - immr
        );
    }
    use rax::isa::arm::decoder::aarch64::Aarch64Decoder;
    use rax::isa::arm::decoder::operand::{AddressingMode, MemOffset, Operand, ShiftAmount};
    fn reg(r: &rax::isa::arm::decoder::operand::Register) -> String {
        r.name()
    }
    fn shift_amount(a: &ShiftAmount) -> String {
        match a {
            ShiftAmount::Immediate(n) => format!("#{n}"),
            ShiftAmount::Register(r) => reg(r),
        }
    }
    fn operand(o: &Operand) -> String {
        match o {
            Operand::Reg(r) => reg(r),
            Operand::Imm(i) => {
                if i.shift == 0 {
                    format!("#{}", i.value)
                } else {
                    format!("#{}, lsl #{}", i.value, i.shift)
                }
            }
            Operand::ShiftedReg(s) => format!(
                "{}, {:?}, {}",
                reg(&s.reg),
                s.shift_type,
                shift_amount(&s.amount)
            ),
            Operand::ExtendedReg(e) => {
                format!("{}, {:?} #{}", reg(&e.reg), e.extend_type, e.shift)
            }
            Operand::Mem(m) => {
                let base = reg(&m.base);
                let inner = match &m.offset {
                    MemOffset::None => base.clone(),
                    MemOffset::Imm(v) => format!("{base}, #{v}"),
                    MemOffset::Reg(r) => format!("{base}, {}", reg(r)),
                    MemOffset::ShiftedReg(s) => format!(
                        "{base}, {}, {:?} {}",
                        reg(&s.reg),
                        s.shift_type,
                        shift_amount(&s.amount)
                    ),
                    MemOffset::ExtendedReg(e) => {
                        format!("{base}, {}, {:?} #{}", reg(&e.reg), e.extend_type, e.shift)
                    }
                };
                match m.mode {
                    AddressingMode::Offset => format!("[{inner}]"),
                    AddressingMode::PreIndex => format!("[{inner}]!"),
                    AddressingMode::PostIndex => match &m.offset {
                        MemOffset::Imm(v) => format!("[{base}], #{v}"),
                        _ => format!("[{base}], {inner}"),
                    },
                }
            }
            Operand::Label(v) => format!("#{v:+#x}"),
            Operand::RegList(l) => {
                let regs: Vec<String> = (0..16)
                    .filter(|i| l.contains(*i))
                    .map(|i| format!("x{i}"))
                    .collect();
                format!("{{{}}}", regs.join(", "))
            }
            Operand::Cond(c) => format!("{c:?}").to_ascii_lowercase(),
            Operand::SysReg(n) => format!("sysreg({n})"),
            other => format!("{other:?}"),
        }
    }
    match Aarch64Decoder::decode(raw) {
        Ok(d) => {
            let ops = d
                .operands
                .iter()
                .map(operand)
                .collect::<Vec<_>>()
                .join(", ");
            let m = format!("{:?}", d.mnemonic).to_ascii_lowercase();
            if ops.is_empty() {
                m
            } else {
                format!("{m} {ops}")
            }
        }
        Err(_) => format!("udf {raw:#010x}"),
    }
}

pub fn condition_name(cond: u8) -> &'static str {
    match cond & 0xf {
        0 => "eq",
        1 => "ne",
        2 => "hs",
        3 => "lo",
        4 => "mi",
        5 => "pl",
        6 => "vs",
        7 => "vc",
        8 => "hi",
        9 => "ls",
        10 => "ge",
        11 => "lt",
        12 => "gt",
        13 => "le",
        14 => "al",
        _ => "nv",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lsl_alias_uses_shift_amount() {
        assert_eq!(disasm(0x531b6909), "lsl w9, w8, #5");
    }
    #[test]
    fn register_branches_use_rn_bits() {
        assert_eq!(classify(0xd61f_0200, 0), Flow::Br { rt: 16 });
        assert_eq!(classify(0xd63f_0220, 0), Flow::Blr { rt: 17 });
        assert_eq!(classify(0xd65f_03c0, 0), Flow::Ret { rt: 30 });
    }
}

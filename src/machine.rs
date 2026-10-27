//! Guest machine construction and deterministic single-step interrogation.
//!
//! One `Machine` is a fresh process image: mapped segments, applied chained
//! fixups, an import trap page, a stack, a scratch page, and a heap for the
//! small external-call models. `run` executes from a chosen entry point and
//! records every retired instruction plus every control-flow decision.

use std::collections::BTreeMap;

use crate::observed::{MemoryEvent, ObservedCpu, State};
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, ArmVersion};
use rax::isa::arm::common::features::ArmFeatures;
use rax::user::cpu::aarch64::{A64Exit, A64UserCpu};
use rax::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};

use crate::decode::{self, Flow};
use crate::image::{FixupKind, Image};
use crate::runtime::{self, ModelCall, Runtime};

pub const TRAP_BASE: u64 = 0x0000_0005_0000_0000;
pub const TRAP_STRIDE: u64 = 16;
pub const SHADOW_BASE: u64 = 0x0000_0005_0001_0000;
pub const SHADOW_STRIDE: u64 = 64;
pub const STACK_BASE: u64 = 0x0000_0005_2000_0000;
pub const SCRATCH_BASE: u64 = 0x0000_0005_3000_0000;
pub const HEAP_BASE: u64 = 0x0000_0005_4000_0000;
pub const RET_SENTINEL: u64 = 0x0000_0005_0000_8000;

const PAGE: u64 = 4096;
const VA_LIMIT: u64 = 1 << 47;

enum Engine {
    Standard(A64UserCpu),
    Observed(ObservedCpu),
}
impl Engine {
    fn core(&self) -> &AArch64Cpu {
        match self {
            Self::Standard(c) => c.core(),
            Self::Observed(c) => c.core(),
        }
    }
    fn core_mut(&mut self) -> &mut AArch64Cpu {
        match self {
            Self::Standard(c) => c.core_mut(),
            Self::Observed(c) => c.core_mut(),
        }
    }
    fn pc(&self) -> u64 {
        match self {
            Self::Standard(c) => c.pc(),
            Self::Observed(c) => c.pc(),
        }
    }
    fn sp(&self) -> u64 {
        match self {
            Self::Standard(c) => c.sp(),
            Self::Observed(c) => c.sp(),
        }
    }
    fn set_sp(&mut self, v: u64) {
        match self {
            Self::Standard(c) => c.set_sp(v),
            Self::Observed(c) => c.set_sp(v),
        }
    }
    fn run(&mut self, n: u64) -> A64Exit {
        match self {
            Self::Standard(c) => c.run(n),
            Self::Observed(c) => c.run(n),
        }
    }
    fn events(&mut self) -> Vec<MemoryEvent> {
        match self {
            Self::Standard(_) => vec![],
            Self::Observed(c) => c.take_events(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub ordinal: u64,
    pub pc: u64,
    pub raw: u32,
    pub before: State,
    pub after: State,
    pub memory: Vec<MemoryEvent>,
    pub read_pages: Vec<(u64, Vec<u8>)>,
    pub status: String,
    pub speculative: bool,
}

#[derive(Clone, Debug)]
pub struct Step {
    pub pc: u64,
    pub insn: u32,
    pub next: u64,
    /// Execution depended on at least one counterfactual branch redirect.
    pub speculative: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    CondTaken,
    CondNotTaken,
    Uncond,
    CallDirect,
    CallImport,
    CallIndirect,
    Indirect,
    Return,
    Syscall,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub pc: u64,
    pub insn: u32,
    pub target: u64,
    pub kind: EventKind,
    pub forced: bool,
    /// For an import call, the trap slot that was entered (the call target);
    /// zero otherwise.
    pub call_site: u64,
    /// Tested value (CBZ/TBZ register, NZCV for flag tests), when available.
    pub evidence: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Stop {
    Returned { pc: u64 },
    Budget { pc: u64 },
    Escaped { pc: u64 },
    Undefined { pc: u64, reason: String },
    Fault { pc: u64, reason: String },
    Breakpoint { pc: u64, imm: u16 },
    Exception { pc: u64, ec: u8, iss: u32 },
    FatalModel { pc: u64, reason: String },
    Interna(String),
}

impl Stop {
    pub fn name(&self) -> String {
        match self {
            Stop::Returned { pc } => format!("returned to sentinel from {pc:#x}"),
            Stop::Budget { pc } => format!("instruction budget at {pc:#x}"),
            Stop::Escaped { pc } => format!("escaped image at {pc:#x}"),
            Stop::Undefined { pc, reason } => format!("undefined at {pc:#x}: {reason}"),
            Stop::Fault { pc, reason } => format!("fault at {pc:#x}: {reason}"),
            Stop::Breakpoint { pc, imm } => format!("brk #{imm} at {pc:#x}"),
            Stop::Exception { pc, ec, iss } => {
                format!("exception at {pc:#x}: ec={ec:#x} iss={iss:#x}")
            }
            Stop::FatalModel { pc, reason } => format!("runtime model stop at {pc:#x}: {reason}"),
            Stop::Interna(s) => format!("internal: {s}"),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub state: State,
    pub sregs: rax::vm::vcpu::Aarch64SystemRegisters,
    pub heap_next: u64,
    pub heap_end: u64,
    pub allocs: Vec<(u64, u64)>,
    pub writes: Vec<(u64, Vec<u8>)>,
    pub ordinal: u64,
    pub original_entry: u64,
    pub args: [u64; 8],
    pub initial_writes: Vec<(u64, u64, u8)>,
    pub image_sha256: String,
    pub harness_sha256: String,
    pub schema: u32,
}

#[derive(Clone, Debug)]
pub struct RunResult {
    pub entry: u64,
    pub args: [u64; 8],
    pub requested_prefix: Vec<bool>,
    pub observations: Vec<Observation>,
    pub checkpoint: Option<Checkpoint>,
    pub memory: Vec<(u64, Result<Vec<u8>, String>)>,
    pub steps: Vec<Step>,
    pub events: Vec<Event>,
    pub stop: Stop,
    pub result_x0: u64,
    pub calls: Vec<ModelCall>,
    pub warnings: Vec<String>,
    pub forced_branches: usize,
    pub cond_branches: usize,
    pub ret: u64,
    pub sp: u64,
    pub last_pc: u64,
}

pub struct Machine {
    pub image: Image,
    pub space: AddressSpace,
    traps: BTreeMap<u64, usize>,
    pub import_names: Vec<String>,
    pub got_imports: Vec<(u64, String)>,
    pub stack_top: u64,
    pub stack_size: u64,
    pub scratch: u64,
    pub scratch_size: u64,
    pub heap: (u64, u64),
}

impl Machine {
    pub fn build(
        image: Image,
        stack_size: u64,
        scratch_size: u64,
        heap_size: u64,
    ) -> Result<Self, String> {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: VA_LIMIT,
            arena_bytes: 1 << 30,
            reserved_phys: Vec::new(),
        })
        .map_err(|e| format!("address space: {e:?}"))?;

        // 1. Map file-backed and zero-fill segments at their Mach-O VMAs.
        for seg in &image.segments {
            if seg.name == "__PAGEZERO" || seg.vmsize == 0 {
                continue;
            }
            let start = seg.vmaddr & !(PAGE - 1);
            let end = align_up(seg.vmaddr + seg.vmsize, PAGE);
            let perms = prot_perms(seg.initprot);
            space
                .map(
                    start,
                    end - start,
                    Mapping::anonymous(perms).named(format!("[{}]", seg.name)),
                )
                .map_err(|e| format!("map {} at {start:#x}: {e:?}", seg.name))?;
            if seg.filesize > 0 {
                let src_off = seg.fileoff;
                let len = seg.filesize.min(seg.vmsize) as usize;
                let src = image
                    .bytes
                    .get(src_off as usize..src_off as usize + len)
                    .ok_or_else(|| format!("segment {} file bytes", seg.name))?;
                space
                    .write_raw(seg.vmaddr, src)
                    .map_err(|e| format!("write {}: {e:?}", seg.name))?;
            }
        }

        // 2. Stack, scratch, heap.
        let stack_top = STACK_BASE + stack_size;
        space
            .map(
                STACK_BASE,
                stack_size,
                Mapping::anonymous(Perms::READ | Perms::WRITE).named("[stack]"),
            )
            .map_err(|e| format!("map stack: {e:?}"))?;
        space
            .map(
                SCRATCH_BASE,
                scratch_size,
                Mapping::anonymous(Perms::READ | Perms::WRITE).named("[scratch]"),
            )
            .map_err(|e| format!("map scratch: {e:?}"))?;
        space
            .map(
                HEAP_BASE,
                heap_size,
                Mapping::anonymous(Perms::READ | Perms::WRITE).named("[heap]"),
            )
            .map_err(|e| format!("map heap: {e:?}"))?;

        // 3. Import traps and shadow data objects.
        let trap_pages = align_up((image.imports.len() as u64 * TRAP_STRIDE).max(1), PAGE);
        let shadow_pages = align_up((image.imports.len() as u64 * SHADOW_STRIDE).max(1), PAGE);
        space
            .map(
                TRAP_BASE,
                trap_pages + PAGE,
                Mapping::anonymous(Perms::READ | Perms::EXEC).named("[import-traps]"),
            )
            .map_err(|e| format!("map trap page: {e:?}"))?;
        space
            .map(
                SHADOW_BASE,
                shadow_pages,
                Mapping::anonymous(Perms::READ | Perms::WRITE).named("[import-shadows]"),
            )
            .map_err(|e| format!("map shadow page: {e:?}"))?;

        let mut traps = BTreeMap::new();
        let mut import_names = Vec::new();
        for (i, imp) in image.imports.iter().enumerate() {
            let slot = TRAP_BASE + i as u64 * TRAP_STRIDE;
            let shadow = SHADOW_BASE + i as u64 * SHADOW_STRIDE;
            space
                .write_raw(slot, &shadow.to_le_bytes())
                .map_err(|e| format!("trap slot: {e:?}"))?;
            traps.insert(slot, i);
            import_names.push(imp.name.clone());
        }

        // 4. Chained fixups. PAC is disabled for the interrogation (keys are
        //    cleared below), so authenticated pointers are materialised as raw
        //    addresses; AUT*/RET*/LDRAA then decode as their non-PAC forms.
        let mut got_imports = Vec::new();
        for fix in &image.fixups {
            let value = match fix.kind {
                FixupKind::Rebase { target, high8 } => {
                    let mut v = image.base.wrapping_add(target);
                    if high8 != 0 {
                        v |= u64::from(high8) << 56;
                    }
                    v
                }
                FixupKind::AuthRebase { target, .. } => image.base.wrapping_add(target),
                FixupKind::Bind { ordinal, addend } => bind_value(&image, ordinal, addend, &traps)?,
                FixupKind::AuthBind { ordinal, .. } => bind_value(&image, ordinal, 0, &traps)?,
            };
            space
                .write_raw(fix.addr, &value.to_le_bytes())
                .map_err(|e| format!("fixup at {:#x}: {e:?}", fix.addr))?;
            if let Some(i) = traps.get(&value) {
                got_imports.push((fix.addr, import_names[*i].clone()));
            }
        }

        Self::post_map(
            space,
            image,
            traps,
            import_names,
            got_imports,
            stack_top,
            stack_size,
            scratch_size,
            heap_size,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn post_map(
        space: AddressSpace,
        image: Image,
        traps: BTreeMap<u64, usize>,
        import_names: Vec<String>,
        got_imports: Vec<(u64, String)>,
        stack_top: u64,
        stack_size: u64,
        scratch_size: u64,
        heap_size: u64,
    ) -> Result<Self, String> {
        Ok(Self {
            image,
            space,
            traps,
            import_names,
            got_imports,
            stack_top,
            stack_size,
            scratch: SCRATCH_BASE,
            scratch_size,
            heap: (HEAP_BASE, heap_size),
        })
    }

    fn fresh_cpu(&self, observe: bool) -> Result<Engine, String> {
        let cfg = AArch64Config {
            version: ArmVersion::V8_3A,
            features: ArmFeatures::armv8_3_base(),
            ..AArch64Config::v8_2()
        };
        let mut cpu = if observe {
            Engine::Observed(ObservedCpu::new(&self.space, cfg))
        } else {
            Engine::Standard(A64UserCpu::with_config(&self.space, cfg))
        };
        // Disable the A/B key-enable bits: PAC instructions become NOPs and
        // every pointer we materialise stays a plain VA.
        let mut controls = cpu.core().pauth_controls();
        // SCTLR_EL1: EnIA(31), EnIB(30), EnDA(27), EnDB(13).
        controls.sctlr[1] = disable_pauth_keys(controls.sctlr[1]);
        cpu.core_mut()
            .set_pauth_controls(controls)
            .map_err(|e| format!("pauth controls: {e:?}"))?;
        Ok(cpu)
    }

    /// Run from `entry` with `args` in X0..X7. `forced` holds the desired
    /// outcome of each conditional branch occurrence; when it disagrees with
    /// the architectural outcome the PC is redirected to the other target
    /// (conditional branches have no other architectural effect, so this is
    /// exact).
    pub fn run(
        &self,
        entry: u64,
        args: &[u64; 8],
        max_insns: u64,
        forced: &[bool],
    ) -> Result<RunResult, String> {
        self.run_observed(entry, args, max_insns, forced, None, false, None, None, &[])
    }

    pub fn run_observed(
        &self,
        entry: u64,
        args: &[u64; 8],
        max_insns: u64,
        forced: &[bool],
        capture: Option<(u64, u64)>,
        observe_pages: bool,
        checkpoint_at: Option<u64>,
        restore: Option<&Checkpoint>,
        overrides: &[(u8, u64)],
    ) -> Result<RunResult, String> {
        let instrumented = capture.is_some() || checkpoint_at.is_some() || restore.is_some();
        let mut cpu = self.fresh_cpu(instrumented)?;
        for (i, v) in args.iter().enumerate() {
            cpu.core_mut().set_x(i as u8, *v);
        }
        // Leave 4 KiB above SP for caller-passed stack arguments
        // ([sp, #0x4C0] is common in this image) and below SP for frames.
        let sp = self.stack_top - 0x1000;
        cpu.set_sp(sp);
        cpu.core_mut().set_pc(entry);
        cpu.core_mut().set_x(30, RET_SENTINEL);
        // A zero canary slot and a plausible frame pointer.
        cpu.core_mut().set_x(29, sp);

        let mut rt = Runtime::new(self.heap.0, self.heap.1);
        if let Some(cp) = restore {
            if cp.heap_end != self.heap.0 + self.heap.1
                || cp.heap_next < self.heap.0
                || cp.heap_next > cp.heap_end
            {
                return Err("checkpoint heap layout mismatch".into());
            }
            for (addr, data) in &cp.writes {
                self.space
                    .write(*addr, data)
                    .map_err(|e| format!("restore write {addr:#x}: {e:?}"))?;
            }
            cpu.core_mut()
                .import_sregs(&cp.sregs)
                .map_err(|e| format!("restore system state: {e:?}"))?;
            cp.state.restore(cpu.core_mut())?;
            for (reg, value) in overrides {
                if *reg > 30 {
                    return Err("override register out of range".into());
                }
                cpu.core_mut().set_x(*reg, *value);
            }
            rt.heap_next = cp.heap_next;
            rt.heap_end = cp.heap_end;
            rt.allocs = cp.allocs.clone();
        }
        rt.record = capture.is_some() || checkpoint_at.is_some();
        let mut write_journal: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut saved_checkpoint: Option<Checkpoint> = None;
        let mut checkpoint_hidden_state_safe = true;
        let mut steps: Vec<Step> = Vec::new();
        let mut observations: Vec<Observation> = Vec::new();
        let mut events = Vec::new();
        let mut calls = Vec::new();
        let mut warnings = Vec::new();
        let mut cond_index = 0usize;
        let mut forced_branches = 0usize;
        let mut tainted = !overrides.is_empty();
        if tainted {
            warnings.push("register intervention after checkpoint restore; downstream execution is counterfactual".into());
        }
        let stop;

        let mut executed = 0u64;
        loop {
            let pc = cpu.pc();
            if checkpoint_at == Some(pc) && saved_checkpoint.is_none() {
                if tainted {
                    return Err("cannot checkpoint a forced execution".into());
                }
                if !checkpoint_hidden_state_safe {
                    return Err("checkpoint unavailable after event/wait hint: hidden event state is not serialized".into());
                }
                match &cpu {
                    Engine::Observed(c) if c.exclusive_active() => {
                        return Err("cannot checkpoint with an active exclusive reservation".into())
                    }
                    Engine::Standard(_) => {
                        return Err("checkpoint requires instrumented CPU".into())
                    }
                    _ => {}
                }
                saved_checkpoint = Some(Checkpoint {
                    state: State::capture(cpu.core()),
                    sregs: cpu.core().export_sregs(),
                    heap_next: rt.heap_next,
                    heap_end: rt.heap_end,
                    allocs: rt.allocs.clone(),
                    writes: write_journal.clone(),
                    ordinal: executed,
                    original_entry: entry,
                    args: *args,
                    initial_writes: Vec::new(),
                    image_sha256: String::new(),
                    harness_sha256: String::new(),
                    schema: 1,
                });
            }
            if pc == RET_SENTINEL {
                stop = Stop::Returned {
                    pc: steps.last().map(|s| s.pc).unwrap_or(pc),
                };
                break;
            }
            if let Some(&idx) = self.traps.get(&pc) {
                let name = self.import_names[idx].clone();
                let caller = cpu.core().get_x(30);
                let (call_pc, call_insn) =
                    steps.last().map(|s| (s.pc, s.insn)).unwrap_or((entry, 0));
                let mut call_args = [0u64; 8];
                for (i, value) in call_args.iter_mut().enumerate() {
                    *value = cpu.core().get_x(i as u8);
                }
                let before_model = capture.map(|_| State::capture(cpu.core()));
                let outcome = runtime::call(&name, cpu.core_mut(), &self.space, &mut rt);
                let after_model = capture.map(|_| State::capture(cpu.core()));
                let memory = std::mem::take(&mut rt.journal);
                if checkpoint_at.is_some() && saved_checkpoint.is_none() {
                    for m in &memory {
                        if m.write && m.ok {
                            write_journal.push((m.address, m.bytes.clone()));
                        }
                    }
                }
                calls.push(ModelCall {
                    caller_pc: call_pc,
                    ordinal: executed,
                    args: call_args,
                    memory,
                    before: before_model,
                    after: after_model,
                    name: name.clone(),
                    modeled: outcome.modeled,
                    returned: outcome.returned,
                    detail: outcome.detail.clone(),
                });
                events.push(Event {
                    pc: call_pc,
                    insn: call_insn,
                    target: self.strip(caller),
                    kind: EventKind::CallImport,
                    forced: tainted,
                    call_site: pc,
                    evidence: Some(name.clone()),
                });
                if !outcome.modeled {
                    warnings.push(format!("unmodelled import {name} at {call_pc:#x}; stopped"));
                }
                if let Some(reason) = outcome.fatal {
                    stop = Stop::FatalModel { pc, reason };
                    break;
                }
                cpu.core_mut().set_pc(self.strip(caller));
                continue;
            }
            if !self.image.contains_exec(pc) {
                stop = Stop::Escaped { pc };
                break;
            }
            let mut bytes = [0u8; 4];
            if self.space.fetch(pc, &mut bytes).is_err() {
                stop = Stop::Fault {
                    pc,
                    reason: "instruction fetch fault".into(),
                };
                break;
            }
            let insn = u32::from_le_bytes(bytes);
            if matches!(insn, 0xd503_205f | 0xd503_207f | 0xd503_209f | 0xd503_20bf) {
                checkpoint_hidden_state_safe = false;
            }
            let flow = decode::classify(insn, pc);

            let evidence = match flow {
                Flow::Cond { rt, bit, .. } => {
                    if let Some(b) = bit {
                        let v = if rt == 31 { 0 } else { cpu.core().get_x(rt) };
                        Some(format!("x{rt}={v:#x} bit{b}={}", (v >> b) & 1))
                    } else if (insn & 0xff00_0010) == 0x5400_0000 {
                        Some(format!("nzcv={:x}", cpu.core().nzcv_bits()))
                    } else {
                        let value = if rt == 31 { 0 } else { cpu.core().get_x(rt) };
                        let value = if insn >> 31 == 0 {
                            value & 0xffff_ffff
                        } else {
                            value
                        };
                        Some(format!(
                            "{}{}={value:#x}",
                            if insn >> 31 == 0 { "w" } else { "x" },
                            rt
                        ))
                    }
                }
                Flow::Br { rt } | Flow::Blr { rt } => {
                    Some(format!("x{rt}={:#x}", cpu.core().get_x(rt)))
                }
                Flow::Ret { rt } => Some(format!("x{rt}={:#x}", cpu.core().get_x(rt))),
                _ => None,
            };

            if executed >= max_insns {
                stop = Stop::Budget { pc };
                break;
            }

            let selected = capture.map(|(lo, hi)| pc >= lo && pc < hi).unwrap_or(false);
            let before = selected.then(|| State::capture(cpu.core()));
            let exit = cpu.run(1);
            let memory = cpu.events();
            if checkpoint_at.is_some() && saved_checkpoint.is_none() {
                for m in &memory {
                    if m.write && m.ok {
                        write_journal.push((m.address, m.bytes.clone()));
                    }
                }
            }
            executed += 1;
            let next = cpu.pc();
            if let Some(before) = before {
                let mut read_pages = Vec::new();
                if observe_pages && !memory.iter().any(|m| m.write) {
                    for event in memory.iter().filter(|m| m.ok && !m.write) {
                        let page = event.address & !4095;
                        if !read_pages.iter().any(|(base, _)| *base == page)
                            && read_pages.len() < 16
                        {
                            let mut bytes = vec![0; 4096];
                            if self.space.read(page, &mut bytes).is_ok() {
                                read_pages.push((page, bytes));
                            }
                        }
                    }
                }
                observations.push(Observation {
                    ordinal: executed - 1,
                    pc,
                    raw: insn,
                    before,
                    after: State::capture(cpu.core()),
                    memory,
                    read_pages,
                    status: format!("{exit:?}"),
                    speculative: tainted,
                });
            }

            match exit {
                A64Exit::Yield => {}
                A64Exit::Svc { imm, .. } => {
                    stop = Stop::Exception {
                        pc,
                        ec: 0x15,
                        iss: u32::from(imm),
                    };
                    break;
                }
                A64Exit::Brk { imm, .. } => {
                    stop = Stop::Breakpoint { pc, imm };
                    break;
                }
                A64Exit::Undefined { reason, .. } => {
                    stop = Stop::Undefined { pc, reason };
                    break;
                }
                A64Exit::Exception { ec, iss, .. } => {
                    stop = Stop::Exception { pc, ec, iss };
                    break;
                }
                A64Exit::Fault(f) => {
                    stop = Stop::Fault {
                        pc,
                        reason: format!("{f:?}"),
                    };
                    break;
                }
                A64Exit::Internal(s) => {
                    stop = Stop::Interna(s);
                    break;
                }
            }

            steps.push(Step {
                pc,
                insn,
                next,
                speculative: tainted,
            });
            match flow {
                Flow::Cond {
                    target, alternate, ..
                } => {
                    if target == alternate {
                        stop = Stop::Interna(format!(
                            "ambiguous conditional outcomes at {pc:#x}: both successors equal"
                        ));
                        break;
                    }
                    let taken = next == target;
                    if next != target && next != alternate {
                        stop = Stop::Escaped { pc: next };
                        break;
                    }

                    let mut final_taken = taken;
                    if cond_index < forced.len() {
                        let want = forced[cond_index];
                        if want != taken {
                            // Conditional branches only write the PC, so
                            // redirecting is architecturally exact.
                            cpu.core_mut().set_pc(if want { target } else { alternate });

                            final_taken = want;
                            forced_branches += 1;
                            tainted = true;
                            if let Some(step) = steps.last_mut() {
                                step.next = cpu.pc();
                                step.speculative = true;
                            }
                            if selected {
                                if let Some(obs) = observations.last_mut() {
                                    obs.after.pc = cpu.pc();
                                    obs.speculative = true;
                                }
                            }
                        }
                    }
                    events.push(Event {
                        pc,
                        insn,
                        target: if final_taken { target } else { alternate },
                        kind: if final_taken {
                            EventKind::CondTaken
                        } else {
                            EventKind::CondNotTaken
                        },
                        forced: tainted,
                        call_site: 0,
                        evidence,
                    });
                    cond_index += 1;
                }
                Flow::Uncond { target } => {
                    if next != target {
                        warnings.push(format!(
                            "unconditional branch at {pc:#x} landed at {next:#x}, expected {target:#x}"
                        ));
                    }
                    events.push(Event {
                        pc,
                        insn,
                        target,
                        kind: EventKind::Uncond,
                        forced: tainted,
                        call_site: 0,
                        evidence: None,
                    });
                }
                Flow::CallDirect { target } => {
                    events.push(Event {
                        pc,
                        insn,
                        target,
                        kind: EventKind::CallDirect,
                        forced: tainted,
                        call_site: 0,
                        evidence: None,
                    });
                }
                Flow::Blr { rt } | Flow::Br { rt } => {
                    let kind = if matches!(flow, Flow::Blr { .. }) {
                        EventKind::CallIndirect
                    } else {
                        EventKind::Indirect
                    };
                    // A branch into an import slot is recorded on the next
                    // iteration as an import call attributed to this
                    // instruction; do not also emit a bare indirect edge.
                    if !self.traps.contains_key(&next) {
                        events.push(Event {
                            pc,
                            insn,
                            target: next,
                            kind,
                            forced: tainted,
                            call_site: 0,
                            evidence: evidence.clone(),
                        });
                    }
                    let _ = rt;
                }
                Flow::Ret { .. } => {
                    events.push(Event {
                        pc,
                        insn,
                        target: next,
                        kind: EventKind::Return,
                        forced: tainted,
                        call_site: 0,
                        evidence,
                    });
                }
                _ => {}
            }
        }

        let result_x0 = cpu.core().get_x(0);
        let ret = cpu.core().get_x(30);
        let sp = cpu.sp();
        let last_pc = cpu.pc();
        Ok(RunResult {
            entry,
            args: *args,
            requested_prefix: forced.to_vec(),
            observations,
            checkpoint: saved_checkpoint,
            memory: Vec::new(),
            steps,
            events,
            stop,
            result_x0,
            calls,
            warnings,
            forced_branches,
            cond_branches: cond_index,
            ret,
            sp,
            last_pc,
        })
    }

    pub fn strip(&self, pointer: u64) -> u64 {
        // 47-bit user VA; clear the PAC/TBI tag byte.
        pointer & 0x0000_ffff_ffff_ffff
    }

    pub fn import_slot(&self, idx: usize) -> u64 {
        TRAP_BASE + idx as u64 * TRAP_STRIDE
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.space.read(addr, &mut b).ok()?;
        Some(u64::from_le_bytes(b))
    }

    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        let mut data = vec![0; len];
        self.space
            .read(addr, &mut data)
            .map_err(|e| format!("read {addr:#x}: {e:?}"))?;
        Ok(data)
    }

    pub fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), String> {
        self.space
            .write(addr, data)
            .map_err(|e| format!("write {addr:#x}: {e:?}"))
    }
}

fn bind_value(
    image: &Image,
    ordinal: u32,
    addend: i64,
    _traps: &BTreeMap<u64, usize>,
) -> Result<u64, String> {
    let imp = image
        .imports
        .get(ordinal as usize)
        .ok_or_else(|| format!("bind ordinal {ordinal} out of range"))?;
    // Self-binds resolve against the image's own symbol table.
    if imp.lib_ordinal == 0 {
        if let Some(&addr) = image.symbols.get(&imp.name) {
            return Ok(addr
                .wrapping_add(imp.addend as u64)
                .wrapping_add(addend as u64));
        }
    }
    // Imports are assigned trap slots in import-table order, so the ordinal
    // is the slot index.
    let slot = TRAP_BASE + u64::from(ordinal) * TRAP_STRIDE;
    Ok(slot
        .wrapping_add(imp.addend as u64)
        .wrapping_add(addend as u64))
}

pub fn prot_perms(prot: u32) -> Perms {
    let mut p = Perms::empty();
    if prot & 1 != 0 {
        p |= Perms::READ;
    }
    if prot & 2 != 0 {
        p |= Perms::WRITE;
    }
    if prot & 4 != 0 {
        p |= Perms::EXEC;
    }
    p
}

pub fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn disable_pauth_keys(sctlr: u64) -> u64 {
    sctlr & !((1 << 31) | (1 << 30) | (1 << 27) | (1 << 13))
}

#[cfg(test)]
mod tests {
    #[test]
    fn disables_exact_pauth_key_bits() {
        let got = super::disable_pauth_keys(u64::MAX);
        for bit in [31, 30, 27, 13] {
            assert_eq!(got & (1u64 << bit), 0, "bit {bit}");
        }
        assert_ne!(got & (1u64 << 26), 0);
    }
}

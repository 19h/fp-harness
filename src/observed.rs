//! Instrumented EL0 core. Guest memory accesses are captured at the ArmMemory
//! boundary; instruction fetches are deliberately separate from data reads.
use rax::error::MemoryAccessKind;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{AccessType, ArmCpu, ArmError, CpuExit, MemoryFaultType};
use rax::isa::arm::common::memory::{ArmMemory, MemResult, MmioHandler};
use rax::user::cpu::aarch64::{A64Exit, UserArmMemory};
use rax::user::cpu::{AccessFault, AccessFaultKind};
use rax::user::mm::AddressSpace;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct MemoryEvent {
    pub write: bool,
    pub address: u64,
    pub size: usize,
    pub bytes: Vec<u8>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
struct RecordingMemory {
    inner: UserArmMemory,
    events: Arc<Mutex<Vec<MemoryEvent>>>,
    exclusive: Arc<Mutex<Option<(u64, u8)>>>,
}
impl ArmMemory for RecordingMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let result = self.inner.read(addr, buf);
        self.events.lock().unwrap().push(MemoryEvent {
            write: false,
            address: addr,
            size: buf.len(),
            bytes: if result.is_ok() { buf.to_vec() } else { vec![] },
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| format!("{e:?}")),
        });
        result
    }
    fn write(&mut self, addr: u64, buf: &[u8]) -> MemResult<()> {
        let result = self.inner.write(addr, buf);
        self.events.lock().unwrap().push(MemoryEvent {
            write: true,
            address: addr,
            size: buf.len(),
            bytes: buf.to_vec(),
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| format!("{e:?}")),
        });
        result
    }
    fn fetch(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.inner.fetch(addr, buf)
    }
    fn mark_exclusive(&mut self, addr: u64, size: u8) {
        self.inner.mark_exclusive(addr, size);
        *self.exclusive.lock().unwrap() = Some((addr, size));
    }
    fn check_exclusive(&mut self, addr: u64, size: u8) -> bool {
        *self.exclusive.lock().unwrap() = None;
        self.inner.check_exclusive(addr, size)
    }
    fn clear_exclusive(&mut self) {
        self.inner.clear_exclusive();
        *self.exclusive.lock().unwrap() = None;
    }
    fn requires_alignment(&self) -> bool {
        false
    }
    fn register_mmio(&mut self, base: u64, size: u64, handler: Box<dyn MmioHandler>) {
        self.inner.register_mmio(base, size, handler);
    }
    fn unregister_mmio(&mut self, base: u64) {
        self.inner.unregister_mmio(base);
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct State {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub v: [u128; 32],
    pub fpcr: u32,
    pub fpsr: u32,
    pub tpidr: u64,
    pub tpidrro: u64,
}
impl State {
    pub fn restore(&self, cpu: &mut AArch64Cpu) -> Result<(), String> {
        cpu.set_pstate_bits(self.pstate)
            .map_err(|e| format!("restore pstate: {e:?}"))?;
        cpu.set_current_sp(self.sp);
        for (i, v) in self.x.iter().enumerate() {
            cpu.set_x(i as u8, *v);
        }
        for (i, v) in self.v.iter().enumerate() {
            cpu.set_simd(i as u8, *v);
        }
        cpu.set_fpcr_value(self.fpcr);
        cpu.set_fpsr_value(self.fpsr);
        cpu.set_tpidr_el0(self.tpidr);
        cpu.set_tpidrro_el0(self.tpidrro);
        cpu.set_pc(self.pc);
        Ok(())
    }
    pub fn capture(cpu: &AArch64Cpu) -> Self {
        let mut x = [0; 31];
        let mut v = [0; 32];
        for (i, r) in x.iter_mut().enumerate() {
            *r = cpu.get_x(i as u8);
        }
        for (i, r) in v.iter_mut().enumerate() {
            *r = cpu.get_simd(i as u8);
        }
        Self {
            x,
            v,
            sp: cpu.get_sp(),
            pc: cpu.get_pc(),
            pstate: cpu.pstate_bits(),
            fpcr: cpu.fpcr_value(),
            fpsr: cpu.fpsr_value(),
            tpidr: cpu.tpidr_el0(),
            tpidrro: cpu.tpidrro_el0(),
        }
    }
}

pub struct ObservedCpu {
    core: AArch64Cpu,
    events: Arc<Mutex<Vec<MemoryEvent>>>,
    exclusive: Arc<Mutex<Option<(u64, u8)>>>,
}
impl ObservedCpu {
    pub fn new(space: &AddressSpace, mut config: AArch64Config) -> Self {
        config.gic_config = None;
        let events = Arc::new(Mutex::new(Vec::new()));
        let exclusive = Arc::new(Mutex::new(None));
        let mem = RecordingMemory {
            inner: UserArmMemory::new(space.clone()),
            events: events.clone(),
            exclusive: exclusive.clone(),
        };
        let mut core = AArch64Cpu::new(config, Box::new(mem));
        core.enter_el0();
        Self {
            core,
            events,
            exclusive,
        }
    }
    pub fn core(&self) -> &AArch64Cpu {
        &self.core
    }
    pub fn core_mut(&mut self) -> &mut AArch64Cpu {
        &mut self.core
    }
    pub fn pc(&self) -> u64 {
        self.core.get_pc()
    }
    pub fn sp(&self) -> u64 {
        self.core.get_sp()
    }
    pub fn set_sp(&mut self, v: u64) {
        self.core.set_current_sp(v);
    }
    pub fn exclusive_active(&self) -> bool {
        self.exclusive.lock().unwrap().is_some()
    }
    pub fn take_events(&mut self) -> Vec<MemoryEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
    pub fn run(&mut self, budget: u64) -> A64Exit {
        assert_eq!(budget, 1);
        let pc = self.pc();
        match self.core.step() {
            Ok(CpuExit::Continue) => A64Exit::Yield,
            Ok(CpuExit::Svc(imm)) => A64Exit::Svc {
                pc,
                imm: imm as u16,
            },
            Ok(CpuExit::Breakpoint(imm)) => {
                self.core.set_pc(pc);
                A64Exit::Brk {
                    pc,
                    imm: imm as u16,
                }
            }
            Ok(CpuExit::Wfi | CpuExit::Wfe) => {
                self.core.clear_wait();
                A64Exit::Yield
            }
            Ok(CpuExit::Undefined(insn)) => {
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: format!("undefined instruction {insn:#010x}"),
                }
            }
            Ok(CpuExit::Halt) => {
                self.core.clear_halt();
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: "HLT at EL0".into(),
                }
            }
            Ok(CpuExit::Hvc(_) | CpuExit::Smc(_)) => {
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: "HVC/SMC at EL0".into(),
                }
            }
            Ok(other) => A64Exit::Internal(format!("unexpected exit {other:?} at {pc:#x}")),
            Err(ArmError::ArchitecturalException { ec, iss, .. }) => {
                self.core.clear_exclusive_monitor();
                A64Exit::Exception { pc, ec, iss }
            }
            Err(ArmError::MemoryError(info)) => {
                let access = match info.access {
                    AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                    AccessType::Read => MemoryAccessKind::Read,
                    AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
                };
                let kind = match info.fault_type {
                    MemoryFaultType::Translation | MemoryFaultType::AddressSize => {
                        AccessFaultKind::Unmapped
                    }
                    MemoryFaultType::Permission | MemoryFaultType::AccessFlag => {
                        AccessFaultKind::Permission
                    }
                    MemoryFaultType::Alignment | MemoryFaultType::SpAlignment => {
                        AccessFaultKind::Alignment
                    }
                    _ => AccessFaultKind::Bus,
                };
                self.core.set_pc(pc);
                A64Exit::Fault(AccessFault {
                    addr: info.address,
                    access,
                    kind,
                    pc,
                })
            }
            Err(ArmError::UndefinedInstruction(insn)) => {
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: format!("undefined instruction {insn:#010x}"),
                }
            }
            Err(ArmError::InvalidExceptionLevel(_)) => {
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: "EL1 access at EL0".into(),
                }
            }
            Err(ArmError::Unimplemented(what)) => {
                self.core.set_pc(pc);
                A64Exit::Undefined {
                    pc,
                    reason: format!("not implemented: {what}"),
                }
            }
            Err(other) => A64Exit::Internal(format!("{other} at {pc:#x}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    #[test]
    fn checkpoint_state_roundtrips_full_vector_width() {
        let state = State {
            x: [u64::MAX; 31],
            v: [u128::MAX; 32],
            sp: u64::MAX,
            pc: u64::MAX,
            pstate: 0,
            fpcr: 0,
            fpsr: 0,
            tpidr: 0,
            tpidrro: 0,
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        let restored: State = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state, restored);
    }
}

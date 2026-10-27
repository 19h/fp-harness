//! Deterministic models for external imports.
//!
//! The goal is narrow: keep control-flow interrogation inside the target
//! function. Every call that leaves the image lands on a synthetic import
//! slot; the model either emulates a small, well-understood libc/Darwin
//! operation or stops at an unmodelled call. Models are assumptions, and the
//! report records their outcomes for interpreting the resulting path.

use crate::observed::{MemoryEvent, State};
use rax::isa::arm::aarch64::AArch64Cpu;
use rax::user::mm::AddressSpace;

#[derive(Clone, Debug)]
pub struct ModelCall {
    pub caller_pc: u64,
    pub ordinal: u64,
    pub args: [u64; 8],
    pub memory: Vec<MemoryEvent>,
    pub before: Option<State>,
    pub after: Option<State>,
    pub name: String,
    pub modeled: bool,
    pub returned: u64,
    pub detail: String,
}

pub struct Runtime {
    pub heap_next: u64,
    pub heap_end: u64,
    pub allocs: Vec<(u64, u64)>,
    pub journal: Vec<MemoryEvent>,
    pub record: bool,
}

impl Runtime {
    pub fn new(heap_start: u64, heap_size: u64) -> Self {
        Self {
            heap_next: heap_start,
            heap_end: heap_start + heap_size,
            allocs: Vec::new(),
            journal: Vec::new(),
            record: false,
        }
    }

    fn alloc(&mut self, size: u64, align: u64) -> u64 {
        let align = align.max(16).next_power_of_two();
        let base = (self.heap_next + align - 1) & !(align - 1);
        let end = base.saturating_add(size.max(1));
        if end > self.heap_end {
            return 0;
        }
        self.heap_next = end;
        self.allocs.push((base, size));
        base
    }

    fn alloc_size(&self, addr: u64) -> u64 {
        self.allocs
            .iter()
            .rev()
            .find(|(a, _)| *a == addr)
            .map(|(_, s)| *s)
            .unwrap_or(0)
    }
}

pub struct CallOutcome {
    pub returned: u64,
    pub detail: String,
    pub modeled: bool,
    /// A model recognised the call as fatal (e.g. `__stack_chk_fail`).
    pub fatal: Option<String>,
}

fn read_bytes(space: &AddressSpace, addr: u64, len: u64, rt: &mut Runtime) -> Option<Vec<u8>> {
    if len > (64 << 20) {
        return None;
    }
    let mut bytes = vec![0u8; len as usize];
    let result = space.read(addr, &mut bytes);
    if rt.record {
        rt.journal.push(MemoryEvent {
            write: false,
            address: addr,
            size: len as usize,
            bytes: if result.is_ok() {
                bytes.clone()
            } else {
                vec![]
            },
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| format!("{e:?}")),
        });
    }
    result.ok()?;
    Some(bytes)
}
fn write_bytes(space: &AddressSpace, addr: u64, data: &[u8], rt: &mut Runtime) -> bool {
    let result = space.write(addr, data);
    if rt.record {
        rt.journal.push(MemoryEvent {
            write: true,
            address: addr,
            size: data.len(),
            bytes: data.to_vec(),
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| format!("{e:?}")),
        });
    }
    result.is_ok()
}
fn cstring(
    space: &AddressSpace,
    addr: u64,
    limit: u64,
    require_nul: bool,
    rt: &mut Runtime,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut captured = Vec::new();
    for i in 0..limit.min(1 << 20) {
        let mut b = [0u8; 1];
        let address = addr.checked_add(i)?;
        if let Err(e) = space.read(address, &mut b) {
            if rt.record {
                rt.journal.push(MemoryEvent {
                    write: false,
                    address: addr,
                    size: captured.len() + 1,
                    bytes: captured,
                    ok: false,
                    error: Some(format!("{e:?}")),
                });
            }
            return None;
        }
        captured.push(b[0]);
        if b[0] == 0 {
            if rt.record {
                rt.journal.push(MemoryEvent {
                    write: false,
                    address: addr,
                    size: captured.len(),
                    bytes: captured,
                    ok: true,
                    error: None,
                });
            }
            return Some(out);
        }
        out.push(b[0]);
    }
    if rt.record {
        rt.journal.push(MemoryEvent {
            write: false,
            address: addr,
            size: captured.len(),
            bytes: captured,
            ok: true,
            error: None,
        });
    }
    if !require_nul && limit <= 1 << 20 {
        Some(out)
    } else {
        None
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

pub fn call(
    name: &str,
    cpu: &mut AArch64Cpu,
    space: &AddressSpace,
    rt: &mut Runtime,
) -> CallOutcome {
    let x = |cpu: &AArch64Cpu, r: u8| cpu.get_x(r);
    let set0 = |cpu: &mut AArch64Cpu, v: u64| cpu.set_x(0, v);

    // Normalise Mach-O import spellings (one or more leading underscores).
    // Matching on the bare name keeps libc, Darwin, and ObjC families in one
    // table.
    let n = name.trim_start_matches('_');

    let zero = |cpu: &mut AArch64Cpu, detail: &str| {
        set0(cpu, 0);
        CallOutcome {
            returned: 0,
            detail: detail.to_string(),
            modeled: true,
            fatal: None,
        }
    };
    let fail = |detail: String| CallOutcome {
        returned: x(cpu, 0),
        detail: detail.clone(),
        modeled: false,
        fatal: Some(detail),
    };

    match n {
        "memcpy" | "memmove" | "memcpy_chk" | "memmove_chk" | "bcopy" => {
            // bcopy takes (src, dst, len); memcpy takes (dst, src, len).
            let (dst, src, len) = if n == "bcopy" {
                (x(cpu, 1), x(cpu, 0), x(cpu, 2))
            } else {
                (x(cpu, 0), x(cpu, 1), x(cpu, 2))
            };
            if n.ends_with("_chk") && len > x(cpu, 3) {
                return fail(format!("{n}: destination bounds exceeded"));
            }
            let Some(data) = read_bytes(space, src, len, rt) else {
                return fail(format!("{n}: invalid source or size"));
            };
            let ok = write_bytes(space, dst, &data, rt);
            if !ok {
                return fail(format!("{n}: invalid destination"));
            }
            set0(cpu, dst);
            CallOutcome {
                returned: dst,
                detail: format!("{n}({dst:#x},{src:#x},{len:#x}) copied={ok}"),
                modeled: true,
                fatal: None,
            }
        }
        "memset" | "memset_chk" | "bzero" => {
            let (dst, val, len) = if n == "bzero" {
                (x(cpu, 0), 0, x(cpu, 1))
            } else {
                (x(cpu, 0), x(cpu, 1) as u8, x(cpu, 2))
            };
            if len > (64 << 20) || (n.ends_with("_chk") && len > x(cpu, 3)) {
                return fail(format!("{n}: size or destination bounds exceeded"));
            }
            let data = vec![val; len as usize];
            let ok = write_bytes(space, dst, &data, rt);
            if !ok {
                return fail(format!("{n}: invalid destination"));
            }
            set0(cpu, dst);
            CallOutcome {
                returned: dst,
                detail: format!("{n}({dst:#x},{val:#x},{len:#x}) filled={ok}"),
                modeled: true,
                fatal: None,
            }
        }
        "memcmp" | "bcmp" | "strcmp" | "strncmp" => {
            let (a, b) = (x(cpu, 0), x(cpu, 1));
            let (da, db) = if n == "strcmp" {
                (
                    cstring(space, a, 1 << 20, true, rt),
                    cstring(space, b, 1 << 20, true, rt),
                )
            } else if n == "strncmp" {
                let limit = x(cpu, 2);
                (
                    cstring(space, a, limit, false, rt),
                    cstring(space, b, limit, false, rt),
                )
            } else {
                (
                    read_bytes(space, a, x(cpu, 2), rt),
                    read_bytes(space, b, x(cpu, 2), rt),
                )
            };
            let (Some(da), Some(db)) = (da, db) else {
                return fail(format!("{n}: invalid memory or size"));
            };
            let r = match da.cmp(&db) {
                std::cmp::Ordering::Less => 0xffff_ffff_ffff_ffffu64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            set0(cpu, r);
            CallOutcome {
                returned: r,
                detail: format!("{n} -> {r}"),
                modeled: true,
                fatal: None,
            }
        }
        "strlen" => {
            let a = x(cpu, 0);
            let Some(len) = cstring(space, a, 1 << 20, true, rt).map(|s| s.len() as u64) else {
                return fail("strlen: invalid memory or unterminated string".into());
            };
            set0(cpu, len);
            CallOutcome {
                returned: len,
                detail: format!("strlen({a:#x}) -> {len}"),
                modeled: true,
                fatal: None,
            }
        }
        "malloc" | "operator new" | "Znwm" | "Znam" => {
            let size = x(cpu, 0);
            let p = rt.alloc(size, 16);
            set0(cpu, p);
            CallOutcome {
                returned: p,
                detail: format!("malloc({size:#x}) -> {p:#x}"),
                modeled: true,
                fatal: None,
            }
        }
        "calloc" => {
            let (count, size) = (x(cpu, 0), x(cpu, 1));
            let Some(total) = count.checked_mul(size) else {
                set0(cpu, 0);
                return CallOutcome {
                    returned: 0,
                    detail: "calloc overflow".into(),
                    modeled: true,
                    fatal: None,
                };
            };
            let p = rt.alloc(total, 16);
            if p != 0 {
                let zero = vec![0u8; total.min(64 << 20) as usize];
                if !write_bytes(space, p, &zero, rt) {
                    return fail("calloc: destination fault".into());
                }
            }
            set0(cpu, p);
            CallOutcome {
                returned: p,
                detail: format!("calloc({count:#x},{size:#x}) -> {p:#x}"),
                modeled: true,
                fatal: None,
            }
        }
        "realloc" => {
            let (old, size) = (x(cpu, 0), x(cpu, 1));
            let p = rt.alloc(size, 16);
            if p != 0 && old != 0 {
                let old_size = rt.alloc_size(old);
                if !rt.allocs.iter().any(|(address, _)| *address == old) {
                    return fail(format!("realloc: unknown allocation {old:#x}"));
                }
                let copy = old_size.min(size);
                let Some(data) = read_bytes(space, old, copy, rt) else {
                    return fail("realloc: invalid source or size".into());
                };
                if !write_bytes(space, p, &data, rt) {
                    return fail("realloc: invalid destination".into());
                }
            }
            set0(cpu, p);
            CallOutcome {
                returned: p,
                detail: format!("realloc({old:#x},{size:#x}) -> {p:#x}"),
                modeled: true,
                fatal: None,
            }
        }
        "free" | "operator delete" | "ZdlPv" => zero(cpu, "free"),
        "chkstk_darwin" => {
            let v = x(cpu, 0);
            CallOutcome {
                returned: v,
                detail: "chkstk skipped".into(),
                modeled: false,
                fatal: Some("chkstk requires a stack probing model".into()),
            }
        }
        "pthread_mutex_lock"
        | "pthread_mutex_unlock"
        | "os_unfair_lock_lock"
        | "os_unfair_lock_unlock"
        | "os_unfair_recursive_lock_lock"
        | "os_unfair_recursive_lock_unlock"
        | "pthread_rwlock_rdlock"
        | "pthread_rwlock_wrlock"
        | "pthread_rwlock_unlock"
        | "dispatch_semaphore_wait"
        | "dispatch_semaphore_signal" => zero(cpu, n),
        "objc_retain"
        | "objc_release"
        | "objc_autorelease"
        | "objc_autoreleaseReturnValue"
        | "objc_retainAutoreleasedReturnValue"
        | "objc_retainAutorelease"
        | "objc_retainAutoreleaseReturnValue"
        | "CFRetain" => {
            let v = x(cpu, 0);
            set0(cpu, v);
            CallOutcome {
                returned: v,
                detail: format!("{n} passthrough"),
                modeled: true,
                fatal: None,
            }
        }

        "mach_absolute_time" | "clock_gettime_nsec_np" | "mach_continuous_time" => {
            let v = 1_000_000u64;
            set0(cpu, v);
            CallOutcome {
                returned: v,
                detail: format!("{n} -> {v}"),
                modeled: true,
                fatal: None,
            }
        }
        "getpid" | "pthread_self" | "mach_task_self" | "pthread_main_np" => {
            let v = 1u64;
            set0(cpu, v);
            CallOutcome {
                returned: v,
                detail: format!("{n} -> {v}"),
                modeled: true,
                fatal: None,
            }
        }
        "arc4random" | "arc4random_uniform" | "random" | "rand" => {
            // Deterministic by design: the harness must replay its traces.
            let v = if n == "arc4random_uniform" {
                let bound = x(cpu, 0) as u32;
                if bound == 0 {
                    0
                } else {
                    0x5deece66du64 % u64::from(bound)
                }
            } else {
                0x5deece66du64 & 0xffff_ffff
            };
            set0(cpu, v);
            CallOutcome {
                returned: v,
                detail: format!("{n} -> {v:#x}"),
                modeled: true,
                fatal: None,
            }
        }
        "stack_chk_fail" | "abort" | "assert_rtn" => {
            let msg = format!("{n} called");
            CallOutcome {
                returned: 0,
                detail: msg.clone(),
                modeled: true,
                fatal: Some(msg),
            }
        }
        _ => fail(format!("unmodelled import {name}")),
    }
}

pub fn heap_layout(base: u64, size: u64) -> (u64, u64) {
    (align_up(base, 4096), size & !4095)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rax::isa::arm::aarch64::AArch64Config;
    use rax::user::cpu::aarch64::A64UserCpu;
    use rax::user::mm::{Mapping, Perms, SpaceConfig};

    #[test]
    fn memory_models_stop_on_fault_and_honor_bzero_and_strncmp() {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 1 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        space
            .map(
                0x1000,
                0x1000,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        let mut cpu = A64UserCpu::with_config(&space, AArch64Config::v8_2());
        let mut rt = Runtime::new(0x10000, 0x1000);
        space.write(0x1000, b"abcdef\0abcxyz\0").unwrap();
        cpu.core_mut().set_x(0, 0x1000);
        cpu.core_mut().set_x(1, 0x1007);
        cpu.core_mut().set_x(2, 3);
        let cmp = call("_strncmp", cpu.core_mut(), &space, &mut rt);
        assert!(cmp.modeled && cmp.fatal.is_none());
        assert_eq!(cpu.core().get_x(0), 0);
        cpu.core_mut().set_x(0, 0x1000);
        cpu.core_mut().set_x(1, 3);
        assert!(call("_bzero", cpu.core_mut(), &space, &mut rt)
            .fatal
            .is_none());
        let mut data = [0; 4];
        space.read(0x1000, &mut data).unwrap();
        assert_eq!(&data, b"\0\0\0d");
        cpu.core_mut().set_x(0, 0x1000);
        cpu.core_mut().set_x(1, 0);
        cpu.core_mut().set_x(2, 4);
        let bad = call("_memcpy", cpu.core_mut(), &space, &mut rt);
        assert!(!bad.modeled && bad.fatal.is_some());
        let unknown = call("_unknown_test_import", cpu.core_mut(), &space, &mut rt);
        assert!(!unknown.modeled && unknown.fatal.is_some());
    }
}

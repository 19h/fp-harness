//! Minimal, audit-oriented Mach-O reader for arm64e images.
//!
//! Only what the harness needs: segments, LC_MAIN, LC_FUNCTION_STARTS,
//! LC_SYMTAB, dylib ordinals, and `LC_DYLD_CHAINED_FIXUPS`. The chained-fixup
//! decoder accepts ARM64E_USERLAND24 (format 12) from the macOS SDK's
//! `mach-o/fixup-chains.h`, including page-start chains.

use std::collections::HashMap;

pub const IMAGE_BASE_FALLBACK: u64 = 0x1_0000_0000;

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
}

#[derive(Clone, Debug)]
pub struct Import {
    pub name: String,
    /// dyld bind ordinal: 0 = self, -1 = main, -2 = flat, -3 = weak, >0 = dylib.
    pub lib_ordinal: i32,
    pub weak: bool,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixupKind {
    Rebase {
        target: u64,
        high8: u8,
    },
    AuthRebase {
        target: u64,
        diversity: u16,
        addr_div: bool,
        key: u8,
    },
    Bind {
        ordinal: u32,
        addend: i64,
    },
    AuthBind {
        ordinal: u32,
        diversity: u16,
        addr_div: bool,
        key: u8,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Fixup {
    pub addr: u64,
    pub kind: FixupKind,
}

#[derive(Clone, Debug, Default)]
pub struct FixupStats {
    pub rebase: usize,
    pub auth_rebase: usize,
    pub bind: usize,
    pub auth_bind: usize,
}

#[derive(Clone, Debug)]
pub struct Image {
    pub path: String,
    pub bytes: Vec<u8>,
    pub slice_offset: u64,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub base: u64,
    pub segments: Vec<Segment>,
    pub imports: Vec<Import>,
    pub dylibs: Vec<String>,
    pub fixups: Vec<Fixup>,
    pub entry: Option<u64>,
    pub func_starts: Vec<u64>,
    pub symbols: HashMap<String, u64>,
    pub pointer_format: u16,
}

fn u16le(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("short read at {o:#x}"))
}

fn u32le(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("short read at {o:#x}"))
}

fn u64le(b: &[u8], o: usize) -> Result<u64, String> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| format!("short read at {o:#x}"))
}

fn cstr(b: &[u8], o: usize) -> Result<String, String> {
    let rest = b.get(o..).ok_or_else(|| format!("cstr offset {o:#x}"))?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn fixed_name(b: &[u8], o: usize, n: usize) -> String {
    let s = b.get(o..o + n).unwrap_or(&[]);
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn sign_extend_19(v: u64) -> i64 {
    (((v & 0x7ffff) << 45) as i64) >> 45
}

/// Locate and return the arm64e slice, or the thin image itself.
fn select_slice(file: &[u8]) -> Result<(u64, usize, usize, u32, u32), String> {
    if file.len() < 8 {
        return Err("file shorter than 8 bytes".into());
    }
    let magic = u32::from_be_bytes([file[0], file[1], file[2], file[3]]);
    if magic == 0xcafe_babe || magic == 0xcafe_babf {
        let is64 = magic == 0xcafe_babf;
        let n = u32::from_be_bytes([file[4], file[5], file[6], file[7]]) as usize;
        let entsz = if is64 { 32 } else { 20 };
        for i in 0..n {
            let o = 8 + i * entsz;
            let cputype = u32::from_be_bytes(
                file.get(o..o + 4)
                    .ok_or("fat arch header")?
                    .try_into()
                    .unwrap(),
            );
            let cpusub = u32::from_be_bytes(
                file.get(o + 4..o + 8)
                    .ok_or("fat arch subtype")?
                    .try_into()
                    .unwrap(),
            );
            let (off, size) = if is64 {
                (
                    u64::from_be_bytes(file.get(o + 8..o + 16).unwrap().try_into().unwrap()),
                    u64::from_be_bytes(file.get(o + 16..o + 24).unwrap().try_into().unwrap()),
                )
            } else {
                (
                    u32::from_be_bytes(file.get(o + 8..o + 12).unwrap().try_into().unwrap()) as u64,
                    u32::from_be_bytes(file.get(o + 12..o + 16).unwrap().try_into().unwrap())
                        as u64,
                )
            };
            // 0x0100_000c = CPU_TYPE_ARM64; subtype low byte 2 = CPU_SUBTYPE_ARM64E.
            if cputype == 0x0100_000c && (cpusub & 0xff) == 2 {
                let start = off as usize;
                let end = start
                    .checked_add(size as usize)
                    .ok_or("fat slice overflow")?;
                if end > file.len() {
                    return Err("fat slice beyond EOF".into());
                }
                return Ok((off, start, size as usize, cputype, cpusub));
            }
        }
        return Err("no arm64e slice in fat file".into());
    }
    if file.len() < 32 {
        return Err("file shorter than Mach-O header".into());
    }
    let m = file[0..4].try_into().unwrap();
    let magic = u32::from_le_bytes(m);
    if magic != 0xfeed_facf {
        return Err(format!(
            "not a 64-bit little-endian Mach-O (magic {magic:#x})"
        ));
    }
    let cputype = u32le(file, 4)?;
    let cpusub = u32le(file, 8)?;
    if cputype != 0x0100_000c {
        return Err(format!("not arm64 (cputype {cputype:#x})"));
    }
    Ok((0, 0, file.len(), cputype, cpusub))
}

/// Read the 64-bit value stored at a guest VM address, using segment file
/// offsets. Used only while walking fixup chains and reading the symbol table.
fn read_va(image: &Image, addr: u64) -> Option<u64> {
    for s in &image.segments {
        if addr >= s.vmaddr && addr + 8 <= s.vmaddr + s.filesize {
            let o = (s.fileoff + (addr - s.vmaddr)) as usize;
            return image
                .bytes
                .get(o..o + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        }
    }
    None
}

fn bytes_at_va(image: &Image, addr: u64, len: usize) -> Option<&[u8]> {
    for s in &image.segments {
        if addr >= s.vmaddr && addr + len as u64 <= s.vmaddr + s.filesize {
            let o = (s.fileoff + (addr - s.vmaddr)) as usize;
            return image.bytes.get(o..o + len);
        }
    }
    None
}

pub fn load(path: &str) -> Result<Image, String> {
    let file = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let (slice_off, start, size, cputype, cpusubtype) = select_slice(&file)?;
    let slice = &file[start..start + size];

    let ncmds = u32le(slice, 16)? as usize;
    let mut off = 32usize;
    let mut segments = Vec::new();
    let imports = Vec::new();
    let mut dylibs = Vec::new();
    let mut entry = None;
    let mut func_starts = Vec::new();
    let mut symbols = HashMap::new();
    let mut fix_blob: Option<(usize, usize)> = None;

    for _ in 0..ncmds {
        let cmd = u32le(slice, off)?;
        let cmdsize = u32le(slice, off + 4)? as usize;
        if cmdsize < 8 {
            return Err(format!("load command at {off:#x} has size {cmdsize}"));
        }
        match cmd {
            0x19 => {
                // LC_SEGMENT_64
                let name = fixed_name(slice, off + 8, 16);
                let vmaddr = u64le(slice, off + 24)?;
                let vmsize = u64le(slice, off + 32)?;
                let fileoff = u64le(slice, off + 40)?;
                let filesize = u64le(slice, off + 48)?;
                let maxprot = u32le(slice, off + 56)?;
                let initprot = u32le(slice, off + 60)?;
                if filesize > 0 {
                    let a = slice_off + fileoff;
                    let b = a + filesize;
                    if b > file.len() as u64 {
                        return Err(format!("segment {name} file range beyond EOF"));
                    }
                }
                segments.push(Segment {
                    name,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                });
            }
            0x2 => {
                // LC_SYMTAB
                let symoff = u32le(slice, off + 8)? as usize;
                let nsyms = u32le(slice, off + 12)? as usize;
                let stroff = u32le(slice, off + 16)? as usize;
                let strsize = u32le(slice, off + 20)? as usize;
                if stroff + strsize <= slice.len() {
                    for i in 0..nsyms {
                        let n = symoff + i * 16;
                        if n + 16 > slice.len() {
                            break;
                        }
                        let n_strx = u32le(slice, n)? as usize;
                        let n_type = slice[n + 4];
                        let n_value = u64le(slice, n + 8)?;
                        let kind = n_type & 0x0e;
                        if kind == 0x0e || kind == 0x02 {
                            if let Ok(name) = cstr(&slice[stroff..stroff + strsize], n_strx) {
                                if !name.is_empty() && n_value != 0 {
                                    symbols.insert(name, n_value);
                                }
                            }
                        }
                    }
                }
            }
            0x26 => {
                // LC_FUNCTION_STARTS
                let dataoff = u32le(slice, off + 8)? as usize;
                let datasize = u32le(slice, off + 12)? as usize;
                if dataoff + datasize <= slice.len() {
                    let text_base = segments
                        .iter()
                        .find(|s| s.name == "__TEXT")
                        .map(|s| s.vmaddr)
                        .unwrap_or(IMAGE_BASE_FALLBACK);
                    let mut addr = text_base;
                    let mut p = dataoff;
                    let end = dataoff + datasize;
                    while p < end {
                        let mut value = 0u64;
                        let mut shift = 0;
                        loop {
                            let byte = slice[p];
                            p += 1;
                            value |= u64::from(byte & 0x7f) << shift;
                            if byte & 0x80 == 0 || p >= end {
                                break;
                            }
                            shift += 7;
                            if shift >= 64 {
                                break;
                            }
                        }
                        if value == 0 {
                            break;
                        }
                        addr = addr.wrapping_add(value);
                        func_starts.push(addr);
                    }
                }
            }
            0x8000_0034 => {
                // LC_DYLD_CHAINED_FIXUPS
                let dataoff = u32le(slice, off + 8)? as usize;
                let datasize = u32le(slice, off + 12)? as usize;
                fix_blob = Some((dataoff, datasize));
            }
            0x8000_0028 => {
                // LC_MAIN
                let entryoff = u64le(slice, off + 8)?;
                let text = segments.iter().find(|s| s.name == "__TEXT");
                if let Some(t) = text {
                    entry = Some(t.vmaddr + entryoff);
                }
            }
            0xc => {
                // LC_LOAD_DYLIB (and friends share the dylib_command layout)
                let name_off = u32le(slice, off + 8)? as usize;
                if let Ok(name) = cstr(slice, off + name_off) {
                    dylibs.push(name);
                }
            }
            0x8000_001f | 0xd | 0x18_0000 | 0x8000_0023 | 0x8000_0024 | 0x8000_003f => {
                // LC_REEXPORT_DYLIB / LC_LOAD_WEAK_DYLIB / LC_LOAD_UPWARD_DYLIB:
                // keep the dylib ordinal sequence aligned with dyld.
                let name_off = u32le(slice, off + 8)? as usize;
                if let Ok(name) = cstr(slice, off + name_off) {
                    dylibs.push(name);
                }
            }
            _ => {}
        }
        off += cmdsize;
    }

    let base = segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map(|s| s.vmaddr)
        .unwrap_or(IMAGE_BASE_FALLBACK);

    let mut image = Image {
        path: path.to_string(),
        bytes: slice.to_vec(),
        slice_offset: slice_off,
        cputype,
        cpusubtype,
        base,
        segments,
        imports,
        dylibs,
        fixups: Vec::new(),
        entry,
        func_starts,
        symbols,
        pointer_format: 0,
    };

    if let Some((dataoff, datasize)) = fix_blob {
        parse_fixups(&mut image, dataoff, datasize)?;
    }
    Ok(image)
}

fn parse_fixups(image: &mut Image, dataoff: usize, datasize: usize) -> Result<(), String> {
    let b = image
        .bytes
        .get(dataoff..dataoff + datasize)
        .ok_or("chained-fixups blob beyond EOF")?
        .to_vec();
    let b = b.as_slice();
    let version = u32le(b, 0)?;
    if version != 0 {
        return Err(format!("unsupported chained-fixups version {version}"));
    }
    let starts = u32le(b, 4)? as usize;
    let imports_off = u32le(b, 8)? as usize;
    let symbols_off = u32le(b, 12)? as usize;
    let imports_count = u32le(b, 16)? as usize;
    let imports_format = u32le(b, 20)?;
    let symbols_format = u32le(b, 24)?;
    if symbols_format != 0 {
        return Err(format!("compressed symbols unsupported ({symbols_format})"));
    }

    for i in 0..imports_count {
        let (lib, weak, name_off, addend, size) = match imports_format {
            1 | 2 => {
                let o = imports_off + i * if imports_format == 1 { 4 } else { 8 };
                let v = u32le(b, o)?;
                let addend = if imports_format == 2 {
                    u32le(b, o + 4)? as i32 as i64
                } else {
                    0
                };
                (
                    if (v & 0xff) > 0xf0 {
                        (v as u8 as i8) as i32
                    } else {
                        (v & 0xff) as i32
                    },
                    (v >> 8) & 1 != 0,
                    (v >> 9) as usize,
                    addend,
                    if imports_format == 1 { 4 } else { 8 },
                )
            }
            3 => {
                let o = imports_off + i * 16;
                let v = u64le(b, o)?;
                (
                    if (v & 0xffff) > 0xfff0 {
                        (v as u16 as i16) as i32
                    } else {
                        (v & 0xffff) as i32
                    },
                    (v >> 16) & 1 != 0,
                    (v >> 32) as usize,
                    u64le(b, o + 8)? as i64,
                    16,
                )
            }
            other => return Err(format!("unsupported imports_format {other}")),
        };
        let _ = size;
        let name = cstr(b, symbols_off + name_off)?;
        image.imports.push(Import {
            name,
            lib_ordinal: lib,
            weak,
            addend,
        });
    }

    let seg_count = u32le(b, starts)? as usize;
    let info = starts + 4;
    let mut ptr_format_seen = 0u16;
    for seg_index in 0..seg_count {
        let seg_info = u32le(b, info + seg_index * 4)? as usize;
        if seg_info == 0 {
            continue;
        }
        let p = starts + seg_info;
        let _size = u32le(b, p)?;
        let page_size = u16le(b, p + 4)? as u64;
        let pointer_format = u16le(b, p + 6)?;
        if pointer_format != 12 {
            return Err(format!("unsupported chained pointer format {pointer_format}; only ARM64E_USERLAND24 is supported"));
        }
        let segment_offset = u64le(b, p + 8)?;
        let _max_valid = u32le(b, p + 16)?;
        let page_count = u16le(b, p + 20)? as usize;
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(format!("bad fixup page size {page_size:#x}"));
        }
        ptr_format_seen = pointer_format;
        image.pointer_format = pointer_format;
        let starts_arr = p + 22;
        let mut starts_vec = Vec::with_capacity(page_count);
        for i in 0..page_count {
            starts_vec.push(u16le(b, starts_arr + i * 2)?);
        }
        let extra_base = starts_arr;
        for (page, &ps) in starts_vec.iter().enumerate() {
            // 0xFFFF is DYLD_CHAINED_PTR_START_NONE. A value of zero is a
            // real chain start at page offset zero; treating it as "none"
            // silently leaves most of __DATA_CONST unfixed.
            if ps == 0xffff {
                continue;
            }
            let page_addr = image.base + segment_offset + page as u64 * page_size;
            if ps & 0x8000 != 0 {
                // 32-bit multi-start form; entries run until one has the high
                // bit set. Our arm64e images use the single-start form.
                let mut idx = (ps & 0x7fff) as usize;
                loop {
                    let chain = u16le(b, extra_base + idx * 2)?;
                    let off = u64::from(chain & 0x7fff);
                    walk_chain(image, page_addr + off, pointer_format)?;
                    if chain & 0x8000 != 0 {
                        break;
                    }
                    idx += 1;
                }
            } else {
                // `page_start` is a byte offset within the page.
                let off = u64::from(ps);
                walk_chain(image, page_addr + off, pointer_format)?;
            }
        }
    }
    if image.pointer_format == 0 {
        image.pointer_format = ptr_format_seen;
    }
    Ok(())
}

fn walk_chain(image: &mut Image, start: u64, format: u16) -> Result<(), String> {
    let mut addr = start;
    let stride: u64 = match format {
        1 | 9 | 12 | 13 | 14 | 15 => 8,
        _ => 4,
    };
    for _ in 0..1_000_000 {
        let word = read_va(image, addr).ok_or_else(|| {
            format!("fixup chain at {addr:#x} (format {format}) leaves file-backed data")
        })?;
        let auth = word >> 63 != 0;
        let bind = (word >> 62) & 1 != 0;
        let next = (word >> 51) & 0x7ff;
        let kind = decode_fixup(word, format, auth, bind)?;
        image.fixups.push(Fixup { addr, kind });
        if next == 0 {
            return Ok(());
        }
        addr = addr
            .checked_add(next * stride)
            .ok_or("fixup chain address overflow")?;
    }
    Err(format!("fixup chain at {start:#x} did not terminate"))
}

fn decode_fixup(word: u64, format: u16, auth: bool, bind: bool) -> Result<FixupKind, String> {
    match (format, auth, bind) {
        (12, true, false) | (9, true, false) | (1, true, false) | (7, true, false) => {
            Ok(FixupKind::AuthRebase {
                target: word & 0xffff_ffff,
                diversity: ((word >> 32) & 0xffff) as u16,
                addr_div: (word >> 48) & 1 != 0,
                key: ((word >> 49) & 3) as u8,
            })
        }
        (12, false, false) | (9, false, false) | (1, false, false) | (7, false, false) => {
            Ok(FixupKind::Rebase {
                target: word & ((1 << 43) - 1),
                high8: ((word >> 43) & 0xff) as u8,
            })
        }
        (12, false, true) => Ok(FixupKind::Bind {
            ordinal: (word & 0xff_ffff) as u32,
            addend: sign_extend_19(word >> 32),
        }),
        (12, true, true) => Ok(FixupKind::AuthBind {
            ordinal: (word & 0xff_ffff) as u32,
            diversity: ((word >> 32) & 0xffff) as u16,
            addr_div: (word >> 48) & 1 != 0,
            key: ((word >> 49) & 3) as u8,
        }),
        (9, false, true) | (1, false, true) | (7, false, true) => Ok(FixupKind::Bind {
            ordinal: (word & 0xffff) as u32,
            addend: sign_extend_19(word >> 32),
        }),
        (9, true, true) | (1, true, true) | (7, true, true) => Ok(FixupKind::AuthBind {
            ordinal: (word & 0xffff) as u32,
            diversity: ((word >> 32) & 0xffff) as u16,
            addr_div: (word >> 48) & 1 != 0,
            key: ((word >> 49) & 3) as u8,
        }),
        (2, false, false) | (6, false, false) => Ok(FixupKind::Rebase {
            target: word & ((1 << 36) - 1),
            high8: ((word >> 36) & 0xff) as u8,
        }),
        (2, false, true) | (6, false, true) => Ok(FixupKind::Bind {
            ordinal: (word & 0xff_ffff) as u32,
            addend: ((word >> 24) & 0xff) as i64,
        }),
        (other, a, b) => Err(format!(
            "unsupported chained-fixup encoding format {other} auth {a} bind {b}"
        )),
    }
}

impl Image {
    pub fn text_segment(&self) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == "__TEXT")
    }

    pub fn contains_exec(&self, addr: u64) -> bool {
        self.segments
            .iter()
            .any(|s| s.initprot & 4 != 0 && addr >= s.vmaddr && addr < s.vmaddr + s.vmsize)
    }

    pub fn contains_any(&self, addr: u64) -> bool {
        self.segments
            .iter()
            .any(|s| addr >= s.vmaddr && addr < s.vmaddr + s.vmsize)
    }

    pub fn fixup_stats(&self) -> FixupStats {
        let mut s = FixupStats::default();
        for f in &self.fixups {
            match f.kind {
                FixupKind::Rebase { .. } => s.rebase += 1,
                FixupKind::AuthRebase { .. } => s.auth_rebase += 1,
                FixupKind::Bind { .. } => s.bind += 1,
                FixupKind::AuthBind { .. } => s.auth_bind += 1,
            }
        }
        s
    }

    pub fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        bytes_at_va(self, addr, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arm64e_bind_addend_uses_signed_bits_32_to_50() {
        let word = (1u64 << 62) | (0x7ffffu64 << 32) | 0x123456;
        assert_eq!(
            decode_fixup(word, 12, false, true).unwrap(),
            FixupKind::Bind {
                ordinal: 0x123456,
                addend: -1
            }
        );
        let word = (1u64 << 62) | (0x12345u64 << 32) | 17;
        assert_eq!(
            decode_fixup(word, 12, false, true).unwrap(),
            FixupKind::Bind {
                ordinal: 17,
                addend: 0x12345
            }
        );
    }
}

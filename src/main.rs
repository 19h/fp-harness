//! `fp-harness` — a targeted RAX-based control-flow harness for an arm64e
//! Mach-O image (fairplayd.arm64e).
//!
//! Subcommands:
//!   inspect   Parse the image, its imports, fixups, and function starts.
//!   run       Execute from an entry point and reconstruct the CFG.
//!   funcs     List LC_FUNCTION_STARTS.
//!
//! The harness does not boot the process. It maps image segments and
//! materializes supported chained fixups with synthetic imports, then executes
//! from the chosen entry under an explicitly modeled runtime.

mod cfg;
mod decode;
mod image;
mod machine;
mod observed;
mod runtime;
mod semantic;
mod slice;

use std::collections::VecDeque;
use std::process::ExitCode;

use cfg::Graph;
use image::FixupKind;
use machine::{Machine, RunResult};

fn usage() -> ExitCode {
    eprintln!(
        "fp-harness <inspect|fixups|funcs|run|analyze|slice|selftest> <binary> [options]

inspect [--json]
    Summarise segments, dylibs, imports, chained fixups, entry, functions.

funcs [--limit N] [--near ADDR]
    List LC_FUNCTION_STARTS entries.

analyze <observation.jsonl> --start ADDR --end ADDR [--symbolic-reg N]
    [--result-reg N] [--binary PATH] [--resolve-table] [--replay PATH] [--out PATH]
    Lift a bounded slice and query Z3. END is exclusive.

slice <observation.jsonl> --at ADDR [--occurrence N] [--limit N] [--out PATH]
    Recover a concrete-path backward provenance slice.

run --entry ADDR [options]
    Execute from ADDR and emit the reconstructed control flow.

  --x0..--x7 VALUE     seed general registers (hex or decimal)
  --w32 ADDR=VALUE     write a 32-bit value before the run
  --w64 ADDR=VALUE     write a 64-bit value before the run
  --read ADDR:BYTES    capture memory after each run (max 1 MiB per range)
  --max-insns N        instruction budget per run (default 200000)
  --heap-size BYTES    synthetic heap size, page-aligned (default 0x4000000)
  --runs N             repeated runs with varied arguments (default 1)
  --explore-depth N    force both sides of conditional branches, depth N
  --explore-runs N     cap on exploration runs (default 24)
  --dot PATH           write raw CFG as Graphviz
  --simple-dot PATH    write simplified CFG (pruned invariant edges)
  --json PATH          write the full evidence graph as JSON
  --trace PATH         write the retired-instruction trace
  --observe PATH       write baseline state and data-access events as JSONL
  --observe-range A:B  capture guest instruction PCs in [A,B)
  --observe-pages      snapshot readable pages touched by selected data reads
  --checkpoint-at PC   capture state before the first execution at PC
  --checkpoint PATH    write a checkpoint after the baseline run
  --restore PATH       restore a saved checkpoint before execution
  --set-reg N=VALUE    intervene in xN after restoring (counterfactual)
  --quiet              do not print the textual CFG"
    );
    ExitCode::from(2)
}

struct Opts {
    x: [u64; 8],
    writes: Vec<(u64, u64, u8)>,
    reads: Vec<(u64, usize)>,
    max_insns: u64,
    heap_size: u64,
    runs: u64,
    explore_depth: usize,
    explore_runs: usize,
    dot: Option<String>,
    simple_dot: Option<String>,
    json: Option<String>,
    trace: Option<String>,
    observe: Option<String>,
    observe_range: Option<(u64, u64)>,
    observe_pages: bool,
    checkpoint_at: Option<u64>,
    checkpoint: Option<String>,
    restore: Option<String>,
    overrides: Vec<(u8, u64)>,
    quiet: bool,
    limit: usize,
    near: Option<u64>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            x: [0; 8],
            writes: Vec::new(),
            reads: Vec::new(),
            max_insns: 200_000,
            heap_size: 64 << 20,
            runs: 1,
            explore_depth: 0,
            explore_runs: 24,
            dot: None,
            simple_dot: None,
            json: None,
            trace: None,
            observe: None,
            observe_range: None,
            observe_pages: false,
            checkpoint_at: None,
            checkpoint: None,
            restore: None,
            overrides: Vec::new(),
            quiet: false,
            limit: 100,
            near: None,
        }
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map_err(|e| format!("{s}: {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("{s}: {e}"))
    }
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{a} requires a value"))
        };
        match a.as_str() {
            "--x0" | "--x1" | "--x2" | "--x3" | "--x4" | "--x5" | "--x6" | "--x7" => {
                let reg = (a.as_bytes()[3] - b'0') as usize;
                o.x[reg] = parse_u64(&take(&mut i)?)?;
            }
            "--w32" | "--w64" => {
                let spec = take(&mut i)?;
                let (addr, val) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("{a} expects ADDR=VALUE"))?;
                let width = if a == "--w32" { 4 } else { 8 };
                let value = parse_u64(val)?;
                if width == 4 && value > u64::from(u32::MAX) {
                    return Err(format!("{a} value exceeds 32 bits"));
                }
                o.writes.push((parse_u64(addr)?, value, width));
            }
            "--read" => {
                let spec = take(&mut i)?;
                let (addr, len) = spec.split_once(':').ok_or("--read expects ADDR:BYTES")?;
                let len = parse_u64(len)?;
                if len == 0 || len > (1 << 20) || o.reads.len() >= 16 {
                    return Err("--read requires 1..=1048576 bytes and at most 16 ranges".into());
                }
                o.reads.push((parse_u64(addr)?, len as usize));
            }
            "--max-insns" => o.max_insns = parse_u64(&take(&mut i)?)?,
            "--heap-size" => {
                o.heap_size = parse_u64(&take(&mut i)?)?;
                if o.heap_size == 0 || o.heap_size > (4u64 << 30) || o.heap_size % 4096 != 0 {
                    return Err(
                        "--heap-size must be a 4096-byte multiple in 0x1000..=0x100000000".into(),
                    );
                }
            }
            "--runs" => o.runs = parse_u64(&take(&mut i)?)?.max(1),
            "--explore-depth" => o.explore_depth = parse_u64(&take(&mut i)?)?.min(20) as usize,
            "--explore-runs" => o.explore_runs = parse_u64(&take(&mut i)?)?.min(4096) as usize,
            "--dot" => o.dot = Some(take(&mut i)?),
            "--simple-dot" => o.simple_dot = Some(take(&mut i)?),
            "--json" => o.json = Some(take(&mut i)?),
            "--trace" => o.trace = Some(take(&mut i)?),
            "--observe" => o.observe = Some(take(&mut i)?),
            "--checkpoint-at" => o.checkpoint_at = Some(parse_u64(&take(&mut i)?)?),
            "--checkpoint" => o.checkpoint = Some(take(&mut i)?),
            "--restore" => o.restore = Some(take(&mut i)?),
            "--set-reg" => {
                let spec = take(&mut i)?;
                let (n, v) = spec.split_once('=').ok_or("--set-reg expects N=VALUE")?;
                let n = parse_u64(n)?;
                if n > 30 {
                    return Err("--set-reg requires register 0..30".into());
                }
                if o.overrides.iter().any(|(r, _)| u64::from(*r) == n) {
                    return Err("duplicate --set-reg".into());
                }
                o.overrides.push((n as u8, parse_u64(v)?));
            }
            "--observe-range" => {
                let spec = take(&mut i)?;
                let (a, b) = spec
                    .split_once(':')
                    .ok_or("--observe-range expects START:END")?;
                let (a, b) = (parse_u64(a)?, parse_u64(b)?);
                if a >= b {
                    return Err("--observe-range requires START < END".into());
                }
                o.observe_range = Some((a, b));
            }
            "--quiet" => o.quiet = true,
            "--observe-pages" => o.observe_pages = true,
            "--limit" => o.limit = parse_u64(&take(&mut i)?)?.min(1_000_000) as usize,
            "--near" => o.near = Some(parse_u64(&take(&mut i)?)?),
            // Parsed by `run` itself; accepted here so option parsing does not
            // reject it.
            "--entry" => {
                let _ = take(&mut i)?;
            }
            other => return Err(format!("unknown option {other}")),
        }
        i += 1;
    }
    Ok(o)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.len() < 2 {
        return usage();
    }
    let cmd = argv[0].as_str();
    let path = argv[1].as_str();
    let rest = &argv[2..];
    let result = match cmd {
        "inspect" => inspect(path, rest),
        "funcs" => funcs(path, rest),
        "fixups" => fixups(path),
        "run" => run(path, rest),
        "selftest" => selftest(path),
        "analyze" => analyze(path, rest),
        "slice" => slice_command(path, rest),
        _ => {
            eprintln!("unknown subcommand {cmd}");
            return usage();
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &str) -> Result<image::Image, String> {
    let img = image::load(path)?;
    if img.fixups.is_empty() {
        eprintln!("warning: no chained fixups found; pointers may be unbound");
    }
    Ok(img)
}

fn inspect(path: &str, rest: &[String]) -> Result<(), String> {
    let json = rest.iter().any(|a| a == "--json");
    let img = load(path)?;
    let stats = img.fixup_stats();
    if json {
        let segments=img.segments.iter().map(|seg|serde_json::json!({"name":seg.name,"vmaddr":format!("{:#x}",seg.vmaddr),"vmsize":seg.vmsize,"fileoff":seg.fileoff,"filesize":seg.filesize,"initprot":seg.initprot})).collect::<Vec<_>>();
        let result = serde_json::json!({"path":img.path,"cputype":img.cputype,"cpusubtype":img.cpusubtype,"base":format!("{:#x}",img.base),"entry":img.entry.map(|v|format!("{v:#x}")),"pointer_format":img.pointer_format,"fixups":{"rebase":stats.rebase,"auth_rebase":stats.auth_rebase,"bind":stats.bind,"auth_bind":stats.auth_bind},"functions":img.func_starts.len(),"imports":img.imports.len(),"segments":segments});
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("{}", img.path);
    println!(
        "  cputype {:#x} subtype {:#x} base {:#x} entry {:?} pointer-format {}",
        img.cputype,
        img.cpusubtype,
        img.base,
        img.entry.map(|e| format!("{e:#x}")),
        img.pointer_format
    );
    println!(
        "  chained fixups: {} (rebase {}, auth-rebase {}, bind {}, auth-bind {})",
        img.fixups.len(),
        stats.rebase,
        stats.auth_rebase,
        stats.bind,
        stats.auth_bind
    );
    println!(
        "  {} dylibs, {} imports, {} function starts, {} symbols",
        img.dylibs.len(),
        img.imports.len(),
        img.func_starts.len(),
        img.symbols.len()
    );
    println!("\n  segments:");
    for seg in &img.segments {
        println!(
            "    {:<16} {:#012x} size {:#x} file {:#x}+{:#x} prot {:x}",
            seg.name, seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize, seg.initprot
        );
    }
    println!("\n  dylib ordinals:");
    for (i, d) in img.dylibs.iter().enumerate() {
        println!("    {:2}: {}", i + 1, d);
    }
    println!("\n  imports (first 40):");
    for (i, imp) in img.imports.iter().take(40).enumerate() {
        println!(
            "    {:3} lib {:>3} {}{}",
            i,
            imp.lib_ordinal,
            imp.name,
            if imp.weak { " (weak)" } else { "" }
        );
    }
    if img.imports.len() > 40 {
        println!("    ... {} more", img.imports.len() - 40);
    }
    println!("\n  fixups by key:");
    let mut by_key: std::collections::BTreeMap<(u8, bool), usize> = Default::default();
    let mut auth_binds: std::collections::BTreeMap<u8, usize> = Default::default();
    for f in &img.fixups {
        match f.kind {
            FixupKind::AuthRebase { key, .. } => *by_key.entry((key, false)).or_default() += 1,
            FixupKind::AuthBind { key, .. } => {
                *by_key.entry((key, true)).or_default() += 1;
                *auth_binds.entry(key).or_default() += 1;
            }
            _ => {}
        }
    }
    for ((key, bind), n) in by_key {
        println!(
            "    key {} {}: {}",
            key,
            if bind { "auth-bind" } else { "auth-rebase" },
            n
        );
    }
    Ok(())
}

/// TSV dump for independent comparison against dyld_info.
fn fixups(path: &str) -> Result<(), String> {
    let img = load(path)?;
    let machine = Machine::build(img.clone(), 8 << 20, 64 << 10, 64 << 20)?;
    for fix in &img.fixups {
        let value = machine
            .read_u64(fix.addr)
            .ok_or_else(|| format!("unreadable fixup {:#x}", fix.addr))?;
        match fix.kind {
            FixupKind::Rebase { .. } => println!("{:#x}\trebase\t{:#x}", fix.addr, value),
            FixupKind::AuthRebase { .. } => println!("{:#x}\tauth-rebase\t{:#x}", fix.addr, value),
            FixupKind::Bind { ordinal, addend } => {
                let imp = img
                    .imports
                    .get(ordinal as usize)
                    .ok_or("invalid bind ordinal")?;
                println!(
                    "{:#x}\tbind\t{}\t{}\t{:#x}",
                    fix.addr,
                    imp.name,
                    imp.addend.wrapping_add(addend),
                    value
                );
            }
            FixupKind::AuthBind { ordinal, .. } => {
                let imp = img
                    .imports
                    .get(ordinal as usize)
                    .ok_or("invalid auth-bind ordinal")?;
                println!(
                    "{:#x}\tauth-bind\t{}\t{}\t{:#x}",
                    fix.addr, imp.name, imp.addend, value
                );
            }
        }
    }
    Ok(())
}

fn funcs(path: &str, rest: &[String]) -> Result<(), String> {
    let o = parse_opts(rest)?;
    let img = load(path)?;
    let mut shown = 0usize;
    for (i, &f) in img.func_starts.iter().enumerate() {
        if let Some(center) = o.near {
            if f.abs_diff(center) > 0x4000 {
                continue;
            }
        }
        println!("{:5} {:#x}", i, f);
        shown += 1;
        if shown >= o.limit {
            break;
        }
    }
    eprintln!("{} functions ({} shown)", img.func_starts.len(), shown);
    Ok(())
}

fn selftest(path: &str) -> Result<(), String> {
    let img = load(path)?;
    let stats = img.fixup_stats();
    println!(
        "fixups {} (rebase {}, auth-rebase {}, bind {}, auth-bind {})",
        img.fixups.len(),
        stats.rebase,
        stats.auth_rebase,
        stats.bind,
        stats.auth_bind
    );
    let mut failures = 0usize;
    let mut check = |name: &str, got: u64, want: u64| {
        let ok = got == want;
        println!(
            "  {:<42} got {:#x} want {:#x} {}",
            name,
            got,
            want,
            if ok { "PASS" } else { "FAIL" }
        );
        if !ok {
            failures += 1;
        }
    };

    // The image's own chained-fixup table is authoritative: 0x1010b1e20 is
    // an authenticated bind of ___chkstk_darwin and must be materialised.
    let has_chkstk = img
        .fixups
        .iter()
        .any(|f| f.addr == 0x1010b1e20 && matches!(f.kind, FixupKind::AuthBind { .. }));
    check("auth-bind at 0x1010b1e20", u64::from(has_chkstk), 1);

    let build = || Machine::build(img.clone(), 8 << 20, 64 << 10, 64 << 20);

    // Fixture 1: in-range dispatch loads the auth-rebased table entry.
    {
        let m = build()?;
        let scratch = m.scratch;
        m.write_bytes(scratch + 0x14, &0x4B0u32.to_le_bytes())?;
        let r = m.run(
            0x1000044fc,
            &[scratch, scratch + 0x800, 0, 0, 0, 0, 0, 0],
            1000,
            &[],
        )?;
        check(
            "sub_1000044FC returned",
            u64::from(matches!(r.stop, machine::Stop::Returned { .. })),
            1,
        );
        check("sub_1000044FC in-range result", r.result_x0, 0x1000_04530);
    }
    // Fixture 2: out-of-range dispatch returns NULL.
    {
        let m = build()?;
        let scratch = m.scratch;
        m.write_bytes(scratch + 0x14, &0x500u32.to_le_bytes())?;
        let r = m.run(
            0x1000044fc,
            &[scratch, scratch + 0x800, 0, 0, 0, 0, 0, 0],
            1000,
            &[],
        )?;
        check(
            "sub_1000044FC out-of-range returned",
            u64::from(matches!(r.stop, machine::Stop::Returned { .. })),
            1,
        );
        check("sub_1000044FC out-of-range result", r.result_x0, 0);
    }
    // Fixture 3: PACIZA/CSEL path with PAC keys disabled.
    {
        let m = build()?;
        let scratch = m.scratch;
        m.write_bytes(scratch + 0x14, &0xa1ffu32.to_le_bytes())?;
        let r = m.run(0x100005304, &[scratch, 0, 0, 0, 0, 0, 0, 0], 1000, &[])?;
        check(
            "sub_100005304 returned",
            u64::from(matches!(r.stop, machine::Stop::Returned { .. })),
            1,
        );
        check("sub_100005304 PAC-return result", r.result_x0, 0x1000_05324);
    }
    // Fixture 4: chained-fixup density must match dyld_info's 61,737 rows.
    check("chained fixup count", img.fixups.len() as u64, 61_737);
    drop(check);

    if failures == 0 {
        println!("selftest: PASS");
        Ok(())
    } else {
        Err(format!("selftest: {failures} failure(s)"))
    }
}

fn run(path: &str, rest: &[String]) -> Result<(), String> {
    let mut o = parse_opts(rest)?;
    if o.observe.is_none() && (o.observe_range.is_some() || o.observe_pages) {
        return Err("--observe-range and --observe-pages require --observe".into());
    }
    if o.restore.is_some()
        && rest.iter().any(|v| {
            matches!(
                v.as_str(),
                "--entry"
                    | "--heap-size"
                    | "--x0"
                    | "--x1"
                    | "--x2"
                    | "--x3"
                    | "--x4"
                    | "--x5"
                    | "--x6"
                    | "--x7"
            )
        })
    {
        return Err("restore supplies entry, heap and argument registers; use --set-reg for an explicit intervention".into());
    }
    if o.restore.is_none() && !o.overrides.is_empty() {
        return Err("--set-reg requires --restore".into());
    }
    if o.checkpoint.is_some() != o.checkpoint_at.is_some() {
        return Err("--checkpoint and --checkpoint-at must be supplied together".into());
    }
    if o.restore.is_some()
        && (o.checkpoint.is_some() || o.runs != 1 || o.explore_depth != 0 || !o.writes.is_empty())
    {
        return Err("restore does not accept checkpointing, multiple runs, forced exploration or additional writes".into());
    }
    let restored: Option<machine::Checkpoint> = if let Some(file) = &o.restore {
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        let cp: machine::Checkpoint =
            serde_json::from_slice(&bytes).map_err(|e| format!("{file}: {e}"))?;
        if cp.schema != 1
            || cp.image_sha256 != file_sha256(path)?
            || cp.harness_sha256
                != file_sha256(&std::env::current_exe().map_err(|e| e.to_string())?)?
        {
            return Err("checkpoint schema, image, or harness digest mismatch".into());
        }
        o.writes = cp.initial_writes.clone();
        o.heap_size = cp
            .heap_end
            .checked_sub(machine::HEAP_BASE)
            .ok_or("invalid checkpoint heap")?;
        o.x = cp.args;
        Some(cp)
    } else {
        None
    };
    let img = load(path)?;
    let entry = rest
        .windows(2)
        .find(|w| w[0] == "--entry")
        .map(|w| parse_u64(&w[1]))
        .transpose()?
        .or(img.entry)
        .ok_or("no --entry and no LC_MAIN")?;
    let entry = restored.as_ref().map(|c| c.state.pc).unwrap_or(entry);

    let build = |img: &image::Image| -> Result<Machine, String> {
        Machine::build(img.clone(), 8 << 20, 64 << 10, o.heap_size)
    };

    let mut graph = Graph::empty(entry);
    graph.image_path = path.to_owned();
    graph.writes = restored
        .as_ref()
        .map(|c| c.initial_writes.clone())
        .unwrap_or_else(|| o.writes.clone());
    graph.restored_from = o.restore.clone();
    graph.interventions = o.overrides.clone();
    graph.heap_size = o.heap_size;
    let mut first: Option<RunResult> = None;

    let make_seeds = |n: u64| -> Vec<[u64; 8]> {
        let mut v = Vec::new();
        for i in 0..n {
            let mut args = o.x;
            if i > 0 {
                // Deterministic, structurally varied arguments. X0 is kept
                // stable by default because callers usually pass a buffer
                // there; the remaining registers exercise different values.
                for (r, a) in args.iter_mut().enumerate().skip(1) {
                    let mix = (i as u64)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .wrapping_add((r as u64) << 32)
                        .wrapping_add(i);
                    *a ^= mix;
                }
            }
            v.push(args);
        }
        v
    };

    let seeds = make_seeds(o.runs);

    // Baseline runs.
    for (i, args) in seeds.iter().enumerate() {
        let m = build(&img)?;
        let initial_writes = restored
            .as_ref()
            .map(|c| c.initial_writes.as_slice())
            .unwrap_or(&o.writes);
        for (addr, value, width) in initial_writes {
            let bytes = if *width == 4 {
                (*value as u32).to_le_bytes().to_vec()
            } else {
                value.to_le_bytes().to_vec()
            };
            m.write_bytes(*addr, &bytes)?;
        }
        let capture = if i == 0 && o.observe.is_some() {
            Some(o.observe_range.unwrap_or((0, u64::MAX)))
        } else {
            None
        };
        let mut r = m.run_observed(
            entry,
            args,
            o.max_insns,
            &[],
            capture,
            o.observe_pages,
            if i == 0 { o.checkpoint_at } else { None },
            restored.as_ref(),
            &o.overrides,
        )?;
        if let Some(cp) = r.checkpoint.as_mut() {
            cp.initial_writes = o.writes.clone();
            cp.image_sha256 = file_sha256(path)?;
            cp.harness_sha256 = file_sha256(&std::env::current_exe().map_err(|e| e.to_string())?)?;
        }
        r.memory = o
            .reads
            .iter()
            .map(|(a, n)| (*a, m.read_bytes(*a, *n)))
            .collect();
        eprintln!(
            "run {}: {} insns, {} control events, stop: {}",
            i,
            r.steps.len(),
            r.events.len(),
            r.stop.name()
        );
        if first.is_none() {
            first = Some(r.clone());
        }
        graph.add_run(&r);
    }

    // Exploration: force both outcomes of every encountered conditional
    // branch, re-executing from a fresh image for every decision prefix.
    if o.explore_depth > 0 {
        let mut queue: VecDeque<Vec<bool>> = VecDeque::new();
        queue.push_back(Vec::new());
        let mut explored = 0usize;
        while let Some(prefix) = queue.pop_front() {
            if explored >= o.explore_runs {
                break;
            }
            let m = build(&img)?;
            for (addr, value, width) in &o.writes {
                let bytes = if *width == 4 {
                    (*value as u32).to_le_bytes().to_vec()
                } else {
                    value.to_le_bytes().to_vec()
                };
                m.write_bytes(*addr, &bytes)?;
            }
            let mut r = m.run(entry, &seeds[0], o.max_insns, &prefix)?;
            r.memory = o
                .reads
                .iter()
                .map(|(a, n)| (*a, m.read_bytes(*a, *n)))
                .collect();
            explored += 1;
            if !prefix.is_empty() {
                eprintln!(
                    "explore {:?}: {} insns, {} conds, stop: {}, forced {}",
                    prefix,
                    r.steps.len(),
                    r.cond_branches,
                    r.stop.name(),
                    r.forced_branches
                );
            }
            if !prefix.is_empty() {
                graph.add_run(&r);
            }
            if prefix.len() < o.explore_depth
                && prefix.len() < r.cond_branches
                && explored < o.explore_runs
            {
                let mut a = prefix.clone();
                a.push(false);
                let mut b = prefix;
                b.push(true);
                queue.push_back(a);
                queue.push_back(b);
            }
        }
        eprintln!("explored {} forced paths", explored);
    }

    graph.finalize();

    if !o.quiet {
        print!("{}", graph.to_text());
        println!("\nsummary");
        println!("  runs {} / forced paths", graph.runs);
        let invariants = graph
            .branches
            .values()
            .filter(|b| {
                (b.taken == 0 || b.not_taken == 0) && b.forced_taken + b.forced_not_taken == 0
            })
            .count();
        println!(
            "  {} conditional branch sites, {} invariant under exercised inputs",
            graph.branches.len(),
            invariants
        );
        for (id, targets) in graph.dispatchers() {
            println!(
                "  dispatcher B{} at {:#x}: {} indirect targets",
                id,
                graph.blocks[id].start,
                targets.len()
            );
        }
        let pruned = graph.pruned_edges();
        if !pruned.is_empty() {
            println!(
                "  {} never-observed conditional edges pruned from the simplified view",
                pruned.len()
            );
        }
        let unmodeled: Vec<&String> = graph
            .calls
            .values()
            .filter(|c| !c.modeled)
            .map(|c| &c.name)
            .collect();
        if !unmodeled.is_empty() {
            println!(
                "  {} unmodelled imports stopped execution: {}",
                unmodeled.len(),
                unmodeled
                    .iter()
                    .take(12)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if let Some(r) = &first {
            println!("  X0 at stop: {:#x}", r.result_x0);
        }
    }

    if let Some(p) = &o.checkpoint {
        let cp = first
            .as_ref()
            .and_then(|r| r.checkpoint.as_ref())
            .ok_or("checkpoint address was not reached")?;
        let target = std::path::Path::new(p);
        if target == std::path::Path::new(path) {
            return Err("checkpoint path equals target image".into());
        }
        let bytes = serde_json::to_vec(cp).map_err(|e| format!("serialize checkpoint: {e}"))?;
        std::fs::write(p, bytes).map_err(|e| format!("{p}: {e}"))?;
        eprintln!(
            "wrote checkpoint {p} at {:#x}, ordinal {}, {} guest/model writes",
            cp.state.pc,
            cp.ordinal,
            cp.writes.len()
        );
    }

    if let Some(p) = &o.observe {
        let r = first.as_ref().ok_or("missing baseline run")?;
        observe_output(p, path, &o, r)?;
        eprintln!("wrote {p} ({} recorded instructions)", r.observations.len());
    }

    if let Some(p) = &o.dot {
        std::fs::write(p, graph.to_dot(false)).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    }
    if let Some(p) = &o.simple_dot {
        std::fs::write(p, graph.to_dot(true)).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    }
    if let Some(p) = &o.json {
        std::fs::write(p, graph.to_json()).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    }
    if let Some(p) = &o.trace {
        let mut s = String::new();
        if let Some(r) = &first {
            for st in &r.steps {
                s.push_str(&format!(
                    "{:#x}: {:<40} -> {:#x}\n",
                    st.pc,
                    decode::disasm(st.insn),
                    st.next
                ));
            }
            for ev in &r.events {
                s.push_str(&format!(
                    "  event {:#x} {:?} -> {:#x}{}\n",
                    ev.pc,
                    ev.kind,
                    ev.target,
                    if ev.forced { " (forced)" } else { "" }
                ));
            }
            for c in &r.calls {
                s.push_str(&format!(
                    "  call {:#x} {} -> {:#x} ({})\n",
                    c.caller_pc, c.name, c.returned, c.detail
                ));
            }
            s.push_str(&format!("  stop: {}\n", r.stop.name()));
        }
        std::fs::write(p, s).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    }
    Ok(())
}

fn observe_output(path: &str, binary: &str, opts: &Opts, run: &RunResult) -> Result<(), String> {
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::io::{BufWriter, Write};
    let bytes = std::fs::read(binary).map_err(|e| format!("{binary}: {e}"))?;
    let hash = format!("{:x}", Sha256::digest(bytes));
    let file = std::fs::File::create(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = BufWriter::new(file);
    let header = json!({"type":"header","schema":1,"image_sha256":hash,"harness_sha256":file_sha256(&std::env::current_exe().map_err(|e|e.to_string())?)?,"image_path":binary,"entry":format!("{:#x}",run.entry),"args":run.args.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>(),"writes":opts.writes.iter().map(|(a,v,w)|json!({"address":format!("{a:#x}"),"value":format!("{v:#x}"),"width":w})).collect::<Vec<_>>(),"heap_size":opts.heap_size,"restored_from":opts.restore,"interventions":opts.overrides.iter().map(|(r,v)|json!({"register":r,"value":format!("{v:#x}")})).collect::<Vec<_>>(),"budget":opts.max_insns,"capture_range":opts.observe_range.map(|(a,b)|[format!("{a:#x}"),format!("{b:#x}")]),"observe_pages":opts.observe_pages,"stop":run.stop.name(),"scope":"baseline; guest and modeled import data accesses; reads through unmapped or oversized model operations may stop"});
    writeln!(out, "{header}").map_err(|e| e.to_string())?;
    fn state(s: &observed::State) -> serde_json::Value {
        json!({"pc":format!("{:#x}",s.pc),"sp":format!("{:#x}",s.sp),"x":s.x.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>(),"pstate":format!("{:#x}",s.pstate),"v":s.v.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>(),"fpcr":s.fpcr,"fpsr":s.fpsr,"tpidr":format!("{:#x}",s.tpidr),"tpidrro":format!("{:#x}",s.tpidrro)})
    }
    for o in &run.observations {
        let memory=o.memory.iter().map(|m|json!({"kind":if m.write {"write"} else {"read"},"address":format!("{:#x}",m.address),"size":m.size,"bytes":m.bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"ok":m.ok,"error":m.error})).collect::<Vec<_>>();
        let row = json!({"type":"instruction","ordinal":o.ordinal,"pc":format!("{:#x}",o.pc),"raw":format!("{:#010x}",o.raw),"before":state(&o.before),"after":state(&o.after),"memory":memory,"read_pages":o.read_pages.iter().map(|(base,data)|json!({"base":format!("{base:#x}"),"bytes":data.iter().map(|b|format!("{b:02x}")).collect::<String>()})).collect::<Vec<_>>(),"status":o.status,"speculative":o.speculative});
        writeln!(out, "{row}").map_err(|e| e.to_string())?;
    }
    for c in &run.calls {
        let memory=c.memory.iter().map(|m|json!({"kind":if m.write {"write"} else {"read"},"address":format!("{:#x}",m.address),"size":m.size,"bytes":m.bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"ok":m.ok,"error":m.error})).collect::<Vec<_>>();
        let row = json!({"type":"model_call","ordinal":c.ordinal,"pc":format!("{:#x}",c.caller_pc),"name":c.name,"args":c.args.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>(),"returned":format!("{:#x}",c.returned),"modeled":c.modeled,"detail":c.detail,"before":c.before.as_ref().map(state),"after":c.after.as_ref().map(state),"memory":memory});
        writeln!(out, "{row}").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}

fn analyze(path: &str, args: &[String]) -> Result<(), String> {
    let mut start = None;
    let mut end = None;
    let mut input = 0u8;
    let mut result = 8u8;
    let mut solver = "z3".to_string();
    let mut binary = None;
    let mut output = None;
    let mut replays = Vec::new();
    let mut resolve = false;
    let mut i = 0;
    while i < args.len() {
        let option = &args[i];
        i += 1;
        if option == "--resolve-table" {
            resolve = true;
            continue;
        }
        let val = args
            .get(i)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--start" => start = Some(parse_u64(val)?),
            "--end" => end = Some(parse_u64(val)?),
            "--symbolic-reg" => {
                let n = parse_u64(val)?;
                if n > 30 {
                    return Err("register must be 0..30".into());
                }
                input = n as u8;
            }
            "--result-reg" => {
                let n = parse_u64(val)?;
                if n > 30 {
                    return Err("register must be 0..30".into());
                }
                result = n as u8;
            }
            "--solver" => solver = val.clone(),
            "--binary" => binary = Some(val.clone()),
            "--replay" => replays.push(val.clone()),
            "--out" => output = Some(val.clone()),
            _ => return Err(format!("unknown analyze option {option}")),
        };
        i += 1;
    }
    if !resolve && !replays.is_empty() {
        return Err("--replay requires --resolve-table".into());
    }
    let value = semantic::analyze(
        path,
        start.ok_or("missing --start")?,
        end.ok_or("missing --end")?,
        input,
        result,
        &solver,
        binary.as_deref(),
        &replays,
        resolve,
    )?;
    let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    if let Some(p) = output {
        std::fs::write(&p, format!("{text}\n")).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    } else {
        println!("{text}");
    }
    Ok(())
}

fn slice_command(path: &str, args: &[String]) -> Result<(), String> {
    let (mut at, mut occurrence, mut limit, mut binary, mut output) =
        (None, 0usize, 10000usize, None, None);
    let mut i = 0;
    while i < args.len() {
        let name = &args[i];
        i += 1;
        let val = args
            .get(i)
            .ok_or_else(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--at" => at = Some(parse_u64(val)?),
            "--occurrence" => {
                occurrence = usize::try_from(parse_u64(val)?).map_err(|e| e.to_string())?
            }
            "--limit" => {
                limit = usize::try_from(parse_u64(val)?)
                    .map_err(|e| e.to_string())?
                    .min(1_000_000)
            }
            "--binary" => binary = Some(val.clone()),
            "--out" => output = Some(val.clone()),
            _ => return Err(format!("unknown slice option {name}")),
        }
        i += 1;
    }
    let value = slice::analyze(
        path,
        at.ok_or("missing --at")?,
        occurrence,
        limit,
        binary.as_deref(),
    )?;
    let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    if let Some(p) = output {
        std::fs::write(&p, format!("{text}\n")).map_err(|e| format!("{p}: {e}"))?;
        eprintln!("wrote {p}");
    } else {
        println!("{text}");
    }
    Ok(())
}

fn file_sha256(path: impl AsRef<std::path::Path>) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let p = path.as_ref();
    let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(format!("{:x}", Sha256::digest(data)))
}

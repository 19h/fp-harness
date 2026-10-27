//! Dynamic control-flow reconstruction and evidence-based simplification.
//!
//! The graph is built from actually retired instruction sequences, never from
//! a static disassembly guess. Each edge records how many runs traversed it,
//! how many were forced during exploration, and the branch evidence observed
//! at the terminator. Simplification is deliberately conservative: only
//! edges never observed on an invariant branch are pruned, and pruning is
//! reported, not hidden.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::decode::{self, condition_name, Flow};
use crate::machine::{EventKind, RunResult, Stop};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    CondTaken,
    CondNotTaken,
    Uncond,
    Call,
    CallReturn,
    Indirect,
    Return,
    ImportCall,
    Exit,
    Fallthrough,
}

impl EdgeKind {
    pub fn name(self) -> &'static str {
        match self {
            EdgeKind::CondTaken => "cond-taken",
            EdgeKind::CondNotTaken => "cond-not-taken",
            EdgeKind::Uncond => "b",
            EdgeKind::Call => "call",
            EdgeKind::CallReturn => "call-return",
            EdgeKind::Indirect => "indirect",
            EdgeKind::Return => "ret",
            EdgeKind::ImportCall => "import-call",
            EdgeKind::Exit => "exit",
            EdgeKind::Fallthrough => "fallthrough",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub id: usize,
    pub start: u64,
    pub insns: Vec<(u64, u32)>,
    pub external: bool,
    pub term_pc: u64,
}

#[derive(Clone, Debug)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
    pub runs: usize,
    pub forced: usize,
    pub evidence: Option<String>,
    pub import: Option<String>,
    pub label: String,
}

#[derive(Clone, Debug, Default)]
pub struct BranchStat {
    pub pc: u64,
    pub runs: usize,
    pub taken: usize,
    pub not_taken: usize,
    pub forced_taken: usize,
    pub forced_not_taken: usize,
    pub evidence: BTreeSet<String>,
}

impl BranchStat {
    pub fn invariant(&self) -> bool {
        (self.taken + self.not_taken > 0)
            && (self.taken == 0 || self.not_taken == 0)
            && self.forced_taken + self.forced_not_taken == 0
    }
}

#[derive(Clone, Debug)]
pub struct CallStat {
    pub name: String,
    pub sites: BTreeSet<u64>,
    pub modeled: bool,
    pub returns: BTreeSet<u64>,
}

pub struct Graph {
    pub blocks: Vec<Block>,
    pub edges: Vec<Edge>,
    pub branches: BTreeMap<u64, BranchStat>,
    pub calls: BTreeMap<String, CallStat>,
    pub warnings: Vec<String>,
    pub stops: Vec<String>,
    pub runs: usize,
    pub entry: u64,
    pub image_path: String,
    pub restored_from: Option<String>,
    pub interventions: Vec<(u8, u64)>,
    pub heap_size: u64,
    pub writes: Vec<(u64, u64, u8)>,
    pub by_start: BTreeMap<u64, usize>,
    /// Unique linear block sequences observed across runs, as block starts.
    pub paths: Vec<Vec<u64>>,
    run_records: Vec<RunResult>,
    pending: Vec<RunResult>,
}

impl Graph {
    pub fn empty(entry: u64) -> Self {
        Self {
            blocks: Vec::new(),
            edges: Vec::new(),
            branches: BTreeMap::new(),
            calls: BTreeMap::new(),
            warnings: Vec::new(),
            stops: Vec::new(),
            runs: 0,
            entry,
            image_path: String::new(),
            restored_from: None,
            interventions: Vec::new(),
            heap_size: 0,
            writes: Vec::new(),
            by_start: BTreeMap::new(),
            paths: Vec::new(),
            run_records: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn intern(&mut self, addr: u64, external: bool) -> usize {
        if let Some(&id) = self.by_start.get(&addr) {
            return id;
        }
        let id = self.blocks.len();
        self.blocks.push(Block {
            id,
            start: addr,
            insns: Vec::new(),
            external,
            term_pc: 0,
        });
        self.by_start.insert(addr, id);
        id
    }

    pub fn add_run(&mut self, run: &RunResult) {
        let mut record = run.clone();
        record.observations.clear();
        record.checkpoint = None;
        self.pending.push(record);
    }

    /// Rebuild all blocks using leaders from every run, so a later path cannot
    /// introduce overlapping blocks in an earlier path.
    pub fn finalize(&mut self) {
        let runs = std::mem::take(&mut self.pending);
        let mut leaders = BTreeSet::new();
        for run in &runs {
            leaders.insert(run.entry);
            for ev in &run.events {
                leaders.insert(ev.target);
                leaders.insert(ev.pc.wrapping_add(4));
                if let Flow::Cond {
                    target, alternate, ..
                } = decode::classify(ev.insn, ev.pc)
                {
                    leaders.insert(target);
                    leaders.insert(alternate);
                }
            }
            for pair in run.steps.windows(2) {
                if pair[1].pc != pair[0].pc.wrapping_add(4) {
                    leaders.insert(pair[1].pc);
                }
            }
        }
        for run in &runs {
            self.ingest(run, &leaders);
        }
        self.run_records = runs;
    }

    fn ingest(&mut self, run: &RunResult, leaders: &BTreeSet<u64>) {
        self.runs += 1;
        self.stops.push(run.stop.name());
        for w in &run.warnings {
            if !self.warnings.contains(w) {
                self.warnings.push(w.clone());
            }
        }
        for c in &run.calls {
            let e = self
                .calls
                .entry(c.name.clone())
                .or_insert_with(|| CallStat {
                    name: c.name.clone(),
                    sites: BTreeSet::new(),
                    modeled: c.modeled,
                    returns: BTreeSet::new(),
                });
            e.sites.insert(c.caller_pc);
            e.returns.insert(c.returned);
            e.modeled &= c.modeled;
        }

        // Retired instructions, split at leaders and at any discontinuity.
        let mut pc_to_block: BTreeMap<u64, usize> = BTreeMap::new();
        let mut seq: Vec<usize> = Vec::new();
        let mut cur: Option<usize> = None;
        let mut prev: Option<u64> = None;
        let mut existing: BTreeSet<u64> = self
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter().map(|(pc, _)| *pc))
            .collect();
        for step in &run.steps {
            let discontinuity = prev.map(|p| p.wrapping_add(4) != step.pc).unwrap_or(true);
            if leaders.contains(&step.pc) || discontinuity || cur.is_none() {
                let id = self.intern(step.pc, false);
                // A block first interned as an unobserved branch target is
                // real code once an instruction retires in it.
                self.blocks[id].external = false;
                cur = Some(id);
                seq.push(id);
            }
            let id = cur.unwrap();
            pc_to_block.insert(step.pc, id);
            if existing.insert(step.pc) {
                self.blocks[id].insns.push((step.pc, step.insn));
            }
            prev = Some(step.pc);
        }

        // Retired path as a linear block sequence. This is the simplest
        // "deobfuscated" artefact: the order the CPU actually took, with the
        // wholesale dispatcher churn already folded into basic blocks.
        let path: Vec<u64> = seq.iter().map(|&b| self.blocks[b].start).collect();
        if !path.is_empty() && !self.paths.contains(&path) {
            self.paths.push(path);
        }

        // Terminators and their immediate edges.
        for ev in &run.events {
            let Some(&from) = pc_to_block.get(&ev.pc) else {
                continue;
            };
            self.blocks[from].term_pc = ev.pc;
            if matches!(ev.kind, EventKind::CondTaken | EventKind::CondNotTaken) {
                let st = self.branches.entry(ev.pc).or_insert_with(|| BranchStat {
                    pc: ev.pc,
                    ..Default::default()
                });
                st.runs += 1;
                if ev.kind == EventKind::CondTaken {
                    if ev.forced {
                        st.forced_taken += 1;
                    } else {
                        st.taken += 1;
                    }
                } else if ev.forced {
                    st.forced_not_taken += 1;
                } else {
                    st.not_taken += 1;
                }
                if let Some(e) = &ev.evidence {
                    st.evidence.insert(e.clone());
                }
            }

            match ev.kind {
                EventKind::CondTaken => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::CondTaken,
                        ev.forced,
                        ev.evidence.clone(),
                        format!("{} taken", cond_text(ev.insn)),
                        None,
                    );
                    if let Flow::Cond {
                        target, alternate, ..
                    } = decode::classify(ev.insn, ev.pc)
                    {
                        let other = if ev.target == target {
                            alternate
                        } else {
                            target
                        };
                        let oid = self.intern(other, !self.contains_addr(other));
                        self.ensure_edge(
                            from,
                            oid,
                            EdgeKind::CondNotTaken,
                            format!("{} not-taken (unobserved)", cond_text(ev.insn)),
                        );
                    }
                }
                EventKind::CondNotTaken => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::CondNotTaken,
                        ev.forced,
                        ev.evidence.clone(),
                        format!("{} not-taken", cond_text(ev.insn)),
                        None,
                    );
                    if let Flow::Cond {
                        target, alternate, ..
                    } = decode::classify(ev.insn, ev.pc)
                    {
                        let other = if ev.target == alternate {
                            target
                        } else {
                            alternate
                        };
                        let oid = self.intern(other, !self.contains_addr(other));
                        self.ensure_edge(
                            from,
                            oid,
                            EdgeKind::CondTaken,
                            format!("{} taken (unobserved)", cond_text(ev.insn)),
                        );
                    }
                }
                EventKind::Uncond => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Uncond,
                        ev.forced,
                        None,
                        "b".into(),
                        None,
                    );
                }
                EventKind::CallDirect | EventKind::CallIndirect => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Call,
                        ev.forced,
                        ev.evidence.clone(),
                        if ev.kind == EventKind::CallDirect {
                            "bl".into()
                        } else {
                            "blr".into()
                        },
                        None,
                    );
                }
                EventKind::Indirect => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Indirect,
                        ev.forced,
                        ev.evidence.clone(),
                        "br".into(),
                        None,
                    );
                }
                EventKind::Return => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Return,
                        ev.forced,
                        ev.evidence.clone(),
                        "ret".into(),
                        None,
                    );
                }
                EventKind::CallImport => {
                    let name = ev.evidence.clone().unwrap_or_else(|| "import".into());
                    let to = self.intern(ev.call_site, true);
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::ImportCall,
                        ev.forced,
                        ev.evidence.clone(),
                        name.clone(),
                        Some(name),
                    );
                }
                EventKind::Syscall => {
                    let to = self.intern(ev.target, !self.contains_addr(ev.target));
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Uncond,
                        false,
                        ev.evidence.clone(),
                        "svc".into(),
                        None,
                    );
                }
            }
        }

        // Record only transitions actually present in the retired sequence.
        // Calls into target code do not imply an immediate return edge.
        let events_by_pc: BTreeMap<u64, _> = run.events.iter().map(|ev| (ev.pc, ev)).collect();
        for pair in run.steps.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let Some(&from) = pc_to_block.get(&a.pc) else {
                continue;
            };
            let Some(&to) = pc_to_block.get(&b.pc) else {
                continue;
            };
            if from == to {
                continue;
            }
            let event = events_by_pc.get(&a.pc).copied();
            match event {
                Some(ev) if ev.kind == EventKind::CallImport && ev.target == b.pc => {
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::CallReturn,
                        ev.forced,
                        None,
                        "model return".into(),
                        ev.evidence.clone(),
                    );
                }
                None if a.next == b.pc && a.pc.wrapping_add(4) == b.pc => {
                    self.add_edge(
                        from,
                        to,
                        EdgeKind::Fallthrough,
                        b.speculative,
                        None,
                        "fallthrough".into(),
                        None,
                    );
                }
                _ => {}
            }
        }

        if let Some(step) = run.steps.last() {
            if let Some(&from) = pc_to_block.get(&step.pc) {
                let exit_id = self.intern(u64::MAX, true);
                let label = match &run.stop {
                    Stop::Returned { .. } => "return".to_string(),
                    other => other.name(),
                };
                self.add_edge(from, exit_id, EdgeKind::Exit, false, None, label, None);
            }
        }
    }

    fn contains_addr(&self, addr: u64) -> bool {
        self.by_start.contains_key(&addr)
    }

    /// Create an edge that is architecturally possible but was not observed,
    /// with zero traversals. These are the candidates the simplifier prunes.
    fn ensure_edge(&mut self, from: usize, to: usize, kind: EdgeKind, label: String) {
        if !self
            .edges
            .iter()
            .any(|e| e.from == from && e.to == to && e.kind == kind)
        {
            self.edges.push(Edge {
                from,
                to,
                kind,
                runs: 0,
                forced: 0,
                evidence: None,
                import: None,
                label,
            });
        }
    }

    fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        kind: EdgeKind,
        forced: bool,
        evidence: Option<String>,
        label: String,
        import: Option<String>,
    ) {
        if let Some(e) = self
            .edges
            .iter_mut()
            .find(|e| e.from == from && e.to == to && e.kind == kind)
        {
            e.runs += 1;
            if forced {
                e.forced += 1;
            }
            if e.evidence.is_none() {
                e.evidence = evidence;
            }
            // A previously synthetic "unobserved" successor is now observed.
            if !label.contains("unobserved") {
                e.label = label;
            }
            return;
        }
        self.edges.push(Edge {
            from,
            to,
            kind,
            runs: 1,
            forced: usize::from(forced),
            evidence,
            import,
            label,
        });
    }

    /// Edges that a simplified view may drop: the never-observed side of a
    /// conditional branch that was invariant across every run and was never
    /// forced during exploration.
    pub fn pruned_edges(&self) -> BTreeSet<(usize, usize, EdgeKind)> {
        let mut pruned = BTreeSet::new();
        for e in &self.edges {
            if !matches!(e.kind, EdgeKind::CondTaken | EdgeKind::CondNotTaken) {
                continue;
            }
            let Some(st) = self.branches.get(&self.blocks[e.from].term_pc) else {
                continue;
            };
            if st.forced_taken + st.forced_not_taken > 0 || st.taken + st.not_taken == 0 {
                continue;
            }
            if e.kind == EdgeKind::CondTaken && st.taken == 0 && st.forced_taken == 0 {
                pruned.insert((e.from, e.to, e.kind));
            }
            if e.kind == EdgeKind::CondNotTaken && st.not_taken == 0 && st.forced_not_taken == 0 {
                pruned.insert((e.from, e.to, e.kind));
            }
        }
        pruned
    }

    pub fn dispatchers(&self) -> Vec<(usize, Vec<u64>)> {
        let mut out = Vec::new();
        for b in &self.blocks {
            let targets: Vec<u64> = self
                .edges
                .iter()
                .filter(|e| e.from == b.id && e.kind == EdgeKind::Indirect)
                .map(|e| self.blocks[e.to].start)
                .collect();
            if targets.len() >= 3 {
                out.push((b.id, targets));
            }
        }
        out
    }

    pub fn to_dot(&self, simplified: bool) -> String {
        let pruned = if simplified {
            self.pruned_edges()
        } else {
            BTreeSet::new()
        };
        let mut s = String::new();
        let _ = writeln!(s, "digraph fairplayd {{");
        let _ = writeln!(
            s,
            "  rankdir=LR; node [shape=box, fontname=\"Menlo\", fontsize=9];"
        );
        for b in &self.blocks {
            let label = if b.external {
                if b.start == u64::MAX {
                    "exit".to_string()
                } else {
                    format!("ext\\n{:#x}", b.start)
                }
            } else {
                format!("B{}\\n{:#x}\\n{} insns", b.id, b.start, b.insns.len())
            };
            let shape = if b.external { "ellipse" } else { "box" };
            let _ = writeln!(s, "  n{} [label=\"{}\", shape={}];", b.id, label, shape);
        }
        for e in &self.edges {
            let dropped = pruned.contains(&(e.from, e.to, e.kind));
            if simplified && dropped {
                continue;
            }
            let mut attrs = format!("label=\"{}\"", e.label);
            match e.kind {
                EdgeKind::CondTaken => attrs.push_str(", color=\"#1a7f37\""),
                EdgeKind::CondNotTaken => attrs.push_str(", color=\"#9a6700\""),
                EdgeKind::ImportCall => attrs.push_str(", color=\"#8250df\""),
                EdgeKind::CallReturn => attrs.push_str(", style=dashed, color=\"#57606a\""),
                EdgeKind::Exit => attrs.push_str(", color=\"#cf222e\""),
                _ => {}
            }
            if e.forced > 0 {
                attrs.push_str(", penwidth=2");
            }
            let _ = writeln!(s, "  n{} -> n{} [{}];", e.from, e.to, attrs);
        }
        let _ = writeln!(s, "}}");
        s
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "entry {:#x}; {} runs; {} blocks; {} edges",
            self.entry,
            self.runs,
            self.blocks.len(),
            self.edges.len()
        );
        for (i, p) in self.paths.iter().take(8).enumerate() {
            let line: Vec<String> = p.iter().map(|a| format!("{a:#x}")).collect();
            let _ = writeln!(s, "path {i}: {}", line.join(" -> "));
        }
        for b in &self.blocks {
            if b.external {
                continue;
            }
            let _ = writeln!(s, "\nB{} {:#x} ({} insns)", b.id, b.start, b.insns.len());
            for (pc, raw) in b.insns.iter().take(20) {
                let _ = writeln!(s, "  {pc:#x}: {:<38} {raw:#010x}", decode::disasm(*raw));
            }
            if b.insns.len() > 20 {
                let _ = writeln!(s, "  ... {} more", b.insns.len() - 20);
            }
            for e in self.edges.iter().filter(|e| e.from == b.id) {
                let _ = writeln!(
                    s,
                    "  -> B{} {:#x} [{}] runs={} forced={}{}",
                    e.to,
                    self.blocks[e.to].start,
                    e.label,
                    e.runs,
                    e.forced,
                    e.import
                        .as_ref()
                        .map(|i| format!(" import={i}"))
                        .unwrap_or_default()
                );
            }
        }
        if !self.branches.is_empty() {
            let _ = writeln!(
                s,
                "\nbranches (invariant means one observed outcome only, not proof)"
            );
            for b in self.branches.values() {
                let ev = b.evidence.iter().next().cloned().unwrap_or_default();
                let _ = writeln!(
                    s,
                    "  {:#x}: taken={} not-taken={} forced={}+{} {} {}",
                    b.pc,
                    b.taken,
                    b.not_taken,
                    b.forced_taken,
                    b.forced_not_taken,
                    if b.invariant() {
                        "INVARIANT"
                    } else {
                        "variable"
                    },
                    ev
                );
            }
        }
        s
    }

    pub fn to_json(&self) -> String {
        fn esc(s: &str) -> String {
            let mut out = String::new();
            for ch in s.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out
        }
        let pruned = self.pruned_edges();
        let mut s = String::new();
        let _ = writeln!(s, "{{");
        let _ = writeln!(s, "  \"image_path\": \"{}\",", esc(&self.image_path));
        let restored = self
            .restored_from
            .as_ref()
            .map(|v| format!("\"{}\"", esc(v)))
            .unwrap_or_else(|| "null".into());
        let _ = writeln!(s, "  \"restored_from\": {restored},");
        let overrides = self
            .interventions
            .iter()
            .map(|(r, v)| format!("{{\"register\":{r},\"value\":\"{v:#x}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(s, "  \"interventions\": [{overrides}],");
        let _ = writeln!(s, "  \"heap_size_bytes\": {},", self.heap_size);
        let writes = self
            .writes
            .iter()
            .map(|(a, v, w)| {
                format!("{{\"address\":\"{a:#x}\",\"value\":\"{v:#x}\",\"width_bytes\":{w}}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(s, "  \"initial_writes\": [{}],", writes);
        let _ = writeln!(s, "  \"entry\": \"{:#x}\",", self.entry);
        let _ = writeln!(s, "  \"runs\": {},", self.runs);
        let _ = writeln!(s, "  \"run_records\": [");
        for (i, r) in self.run_records.iter().enumerate() {
            let args = r
                .args
                .iter()
                .map(|v| format!("\"{v:#x}\""))
                .collect::<Vec<_>>()
                .join(",");
            let prefix = r
                .requested_prefix
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let events = r.events.iter().map(|e| format!("{{\"pc\":\"{:#x}\",\"target\":\"{:#x}\",\"kind\":\"{:?}\",\"speculative\":{},\"evidence\":{}}}", e.pc, e.target, e.kind, e.forced, e.evidence.as_ref().map(|v| format!("\"{}\"", esc(v))).unwrap_or_else(|| "null".into()))).collect::<Vec<_>>().join(",");
            let calls = r.calls.iter().map(|c| format!("{{\"pc\":\"{:#x}\",\"name\":\"{}\",\"modeled\":{},\"result\":\"{:#x}\",\"detail\":\"{}\"}}", c.caller_pc, esc(&c.name), c.modeled, c.returned, esc(&c.detail))).collect::<Vec<_>>().join(",");
            let memory = r
                .memory
                .iter()
                .map(|(addr, bytes)| match bytes {
                    Ok(bytes) => format!(
                        "{{\"address\":\"{addr:#x}\",\"data_hex\":\"{}\",\"error\":null}}",
                        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ),
                    Err(e) => format!(
                        "{{\"address\":\"{addr:#x}\",\"data_hex\":null,\"error\":\"{}\"}}",
                        esc(e)
                    ),
                })
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(s, "    {{\"args\":[{}],\"requested_prefix\":[{}],\"conditional_occurrences\":{},\"redirects\":{},\"instructions\":{},\"result_x0\":\"{:#x}\",\"stop\":\"{}\",\"events\":[{}],\"calls\":[{}],\"memory\":[{}]}}{}", args, prefix, r.cond_branches, r.forced_branches, r.steps.len(), r.result_x0, esc(&r.stop.name()), events, calls, memory, if i + 1 < self.run_records.len() { "," } else { "" });
        }
        let _ = writeln!(s, "  ],");
        let _ = writeln!(s, "  \"paths\": [");
        let paths: Vec<String> = self
            .paths
            .iter()
            .map(|p| {
                format!(
                    "    [{}]",
                    p.iter()
                        .map(|a| format!("\"{a:#x}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        let _ = writeln!(s, "{}", paths.join(",\n"));
        let _ = writeln!(s, "  ],");
        let _ = writeln!(
            s,
            "  \"stops\": [{}],",
            self.stops
                .iter()
                .map(|x| format!("\"{}\"", esc(x)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(s, "  \"blocks\": [");
        for (i, b) in self.blocks.iter().enumerate() {
            let insns = b
                .insns
                .iter()
                .map(|(pc, raw)| {
                    format!(
                        "{{\"pc\":\"{pc:#x}\",\"raw\":\"{raw:#010x}\",\"disasm\":\"{}\"}}",
                        esc(&decode::disasm(*raw))
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                s,
                "    {{\"id\":{},\"start\":\"{:#x}\",\"external\":{},\"insns\":[{}]}}{}",
                b.id,
                b.start,
                b.external,
                insns,
                if i + 1 < self.blocks.len() {
                    ",\n"
                } else {
                    "\n"
                }
            );
        }
        let _ = writeln!(s, "  ],");
        let _ = writeln!(s, "  \"edges\": [");
        let edges: Vec<String> = self
            .edges
            .iter()
            .map(|e| {
                format!(
                    "    {{\"from\":{},\"to\":{},\"kind\":\"{}\",\"runs\":{},\"forced\":{},\"pruned\":{},\"import\":{}}}",
                    e.from,
                    e.to,
                    e.kind.name(),
                    e.runs,
                    e.forced,
                    pruned.contains(&(e.from, e.to, e.kind)),
                    e.import
                        .as_ref()
                        .map(|i| format!("\"{}\"", esc(i)))
                        .unwrap_or_else(|| "null".into())
                )
            })
            .collect();
        let _ = writeln!(s, "{}", edges.join(",\n"));
        let _ = writeln!(s, "  ],");
        let _ = writeln!(s, "  \"branches\": [");
        let branches: Vec<String> = self
            .branches
            .values()
            .map(|b| {
                format!(
                    "    {{\"pc\":\"{:#x}\",\"runs\":{},\"taken\":{},\"not_taken\":{},\"forced_taken\":{},\"forced_not_taken\":{},\"invariant\":{},\"evidence\":[{}]}}",
                    b.pc,
                    b.runs,
                    b.taken,
                    b.not_taken,
                    b.forced_taken,
                    b.forced_not_taken,
                    b.invariant(),
                    b.evidence
                        .iter()
                        .map(|e| format!("\"{}\"", esc(e)))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        let _ = writeln!(s, "{}", branches.join(",\n"));
        let _ = writeln!(s, "  ],");
        let _ = writeln!(s, "  \"calls\": [");
        let calls: Vec<String> = self
            .calls
            .values()
            .map(|c| {
                format!(
                    "    {{\"name\":\"{}\",\"modeled\":{},\"sites\":[{}]}}",
                    esc(&c.name),
                    c.modeled,
                    c.sites
                        .iter()
                        .map(|s| format!("\"{s:#x}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        let _ = writeln!(s, "{}", calls.join(",\n"));
        let _ = writeln!(s, "  ],");
        let _ = writeln!(
            s,
            "  \"warnings\": [{}]",
            self.warnings
                .iter()
                .map(|w| format!("\"{}\"", esc(w)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(s, "}}");
        s
    }
}

fn cond_text(raw: u32) -> String {
    if (raw & 0x7e00_0000) == 0x3400_0000 {
        return format!("cb{}", if raw & 0x0100_0000 != 0 { "nz" } else { "z" });
    }
    if (raw & 0x7e00_0000) == 0x3600_0000 {
        return format!("tb{}", if raw & 0x0100_0000 != 0 { "nz" } else { "z" });
    }
    match decode::classify(raw, 0) {
        Flow::Cond { cond, .. } => format!("b.{}", condition_name(cond)),
        _ => "cond".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{Event, Step};

    fn run(steps: Vec<Step>, events: Vec<Event>) -> RunResult {
        RunResult {
            entry: 0x1000,
            args: [0; 8],
            requested_prefix: vec![],
            observations: vec![],
            checkpoint: None,
            memory: vec![],
            steps,
            events,
            stop: Stop::Budget { pc: 0x2000 },
            result_x0: 0,
            calls: vec![],
            warnings: vec![],
            forced_branches: 0,
            cond_branches: 0,
            ret: 0,
            sp: 0,
            last_pc: 0x2000,
        }
    }

    #[test]
    fn later_leader_splits_existing_block_and_call_has_no_fake_return() {
        let mut graph = Graph::empty(0x1000);
        graph.add_run(&run(
            vec![
                Step {
                    pc: 0x1000,
                    insn: 0xd503201f,
                    next: 0x1004,
                    speculative: false,
                },
                Step {
                    pc: 0x1004,
                    insn: 0x940003ff,
                    next: 0x2000,
                    speculative: false,
                },
                Step {
                    pc: 0x2000,
                    insn: 0xd503201f,
                    next: 0x2004,
                    speculative: false,
                },
            ],
            vec![Event {
                pc: 0x1004,
                insn: 0x940003ff,
                target: 0x2000,
                kind: EventKind::CallDirect,
                forced: false,
                call_site: 0,
                evidence: None,
            }],
        ));
        graph.add_run(&run(
            vec![
                Step {
                    pc: 0x1000,
                    insn: 0xd503201f,
                    next: 0x1004,
                    speculative: false,
                },
                Step {
                    pc: 0x1004,
                    insn: 0x940003ff,
                    next: 0x2000,
                    speculative: false,
                },
                Step {
                    pc: 0x2000,
                    insn: 0x17fffc01,
                    next: 0x1004,
                    speculative: false,
                },
                Step {
                    pc: 0x1004,
                    insn: 0x940003ff,
                    next: 0x2000,
                    speculative: false,
                },
            ],
            vec![
                Event {
                    pc: 0x1004,
                    insn: 0x940003ff,
                    target: 0x2000,
                    kind: EventKind::CallDirect,
                    forced: false,
                    call_site: 0,
                    evidence: None,
                },
                Event {
                    pc: 0x2000,
                    insn: 0x17fffc01,
                    target: 0x1004,
                    kind: EventKind::Uncond,
                    forced: false,
                    call_site: 0,
                    evidence: None,
                },
            ],
        ));
        graph.finalize();
        let appearances = graph
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter())
            .filter(|(pc, _)| *pc == 0x1004)
            .count();
        assert_eq!(appearances, 1);
        assert!(graph.blocks.iter().any(|b| b.start == 0x1004));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::Fallthrough));
        assert!(!graph.edges.iter().any(|e| e.kind == EdgeKind::CallReturn));
    }
}

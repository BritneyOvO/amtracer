use super::plan::{Plan, Point};
use anyhow::{Context, Result, ensure};
use debugplz_abi::instruction::{self, Header, REGISTER_COUNT, RegisterHeader};
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::value::{RawValue, to_raw_value};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
};

pub struct Writer<'a> {
    plan: &'a Plan,
    json: Option<Vec<PointJsonCache>>,
}

struct PointJsonCache {
    primary: Option<(u64, JsonMetadata)>,
    aliases: BTreeMap<u64, JsonMetadata>,
}

struct JsonMetadata {
    pc: Box<RawValue>,
    module: Box<RawValue>,
    elf_address: Box<RawValue>,
    opcode: Box<RawValue>,
    instruction: Box<RawValue>,
}

impl PointJsonCache {
    fn get(&self, pc: u64) -> Option<&JsonMetadata> {
        if let Some((primary_pc, ref meta)) = self.primary
            && primary_pc == pc
        {
            return Some(meta);
        }
        self.aliases.get(&pc)
    }
}

impl<'a> Writer<'a> {
    pub fn new(plan: &'a Plan, json: bool) -> Result<Self> {
        // Metadata is immutable for the capture. Encode strings once, including
        // JSON escaping, rather than allocating and scanning them for every hit.
        let metadata = json
            .then(|| {
                plan.points
                    .iter()
                    .map(|point| {
                        let target = &plan.targets[point.target];
                        let mut entries = point
                            .instructions
                            .iter()
                            .map(|(pc, instruction)| {
                                Ok((
                                    *pc,
                                    JsonMetadata {
                                        pc: to_raw_value(&format!("{pc:#x}"))?,
                                        module: to_raw_value(&target.path.to_string_lossy())?,
                                        elf_address: to_raw_value(&format!(
                                            "{:#x}",
                                            point.elf_address
                                        ))?,
                                        opcode: to_raw_value(&format!("{:08x}", instruction.word))?,
                                        instruction: to_raw_value(&instruction.assembly)?,
                                    },
                                ))
                            })
                            .collect::<Result<BTreeMap<_, _>>>()?;
                        let primary = if entries.len() == 1 {
                            entries.pop_first()
                        } else {
                            None
                        };
                        Ok(PointJsonCache {
                            primary,
                            aliases: entries,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        Ok(Self {
            plan,
            json: metadata,
        })
    }
}

pub struct Event {
    pub header: Header,
    pub regs: Option<RegisterChanges>,
}

pub struct RegisterChanges {
    full: bool,
    header: RegisterHeader,
    values: [u64; REGISTER_COUNT],
}

impl RegisterChanges {
    fn kind(&self) -> &'static str {
        if self.full { "full" } else { "delta" }
    }

    fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        let mut mask = self.header.changed_mask;
        self.values[..mask.count_ones() as usize]
            .iter()
            .map(move |value| {
                // Decode validates the mask; each packed value has one set bit.
                let bit = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                (instruction::REGISTER_NAMES[bit], *value)
            })
    }
}

struct ChangedValues<'a>(&'a RegisterChanges);

impl Serialize for ChangedValues<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map =
            serializer.serialize_map(Some(self.0.header.changed_mask.count_ones() as usize))?;
        for (name, value) in self.0.iter() {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

impl Event {
    pub fn decode(bytes: &[u8], tgid: u32, regs: bool, plan: &Plan) -> Result<Self> {
        ensure!(
            bytes.len() >= size_of::<Header>(),
            "short instruction trace event"
        );
        // SAFETY: Header is repr(C) integers only, the complete prefix is
        // available, and unaligned loads accept ringbuf byte alignment.
        let header = unsafe { bytes.as_ptr().cast::<Header>().read_unaligned() };
        ensure!(
            header.magic == instruction::MAGIC && header.version == instruction::VERSION,
            "unsupported instruction trace ABI"
        );
        ensure!(
            if regs {
                header.flags == instruction::FLAG_REGS
                    || header.flags == instruction::FLAG_REGS | instruction::FLAG_REGS_FULL
            } else {
                header.flags == 0
            },
            "unexpected instruction trace flags"
        );
        ensure!(
            header.length as usize == bytes.len(),
            "invalid instruction trace length"
        );
        ensure!(
            header.tgid == tgid
                && header.tid != 0
                && header.sequence != 0
                && header.thread_epoch != 0,
            "invalid instruction trace identity/sequence"
        );
        let point = point(plan, header.cookie)?;
        let valid_pc = if point.instructions.len() == 1 {
            point
                .instructions
                .first_key_value()
                .is_some_and(|(&pc, _)| pc == header.pc)
        } else {
            point.instructions.contains_key(&header.pc)
        };
        ensure!(valid_pc, "instruction trace PC outside declared range");
        let payload = &bytes[size_of::<Header>()..];
        let registers = if regs {
            ensure!(
                payload.len() >= size_of::<RegisterHeader>(),
                "short register payload"
            );
            // SAFETY: the complete integer-only repr(C) prefix is available;
            // unaligned loads accept the ring buffer's byte alignment.
            let registers = unsafe { payload.as_ptr().cast::<RegisterHeader>().read_unaligned() };
            ensure!(
                registers.changed_mask & !instruction::REGISTER_MASK == 0,
                "unknown register mask bits"
            );
            let count = registers.changed_mask.count_ones() as usize;
            ensure!(
                payload.len() == size_of::<RegisterHeader>() + count * size_of::<u64>(),
                "invalid packed register length"
            );
            let full = header.flags & instruction::FLAG_REGS_FULL != 0;
            ensure!(
                if full {
                    registers.base_sequence == 0
                        && registers.changed_mask == instruction::REGISTER_MASK
                } else {
                    registers.base_sequence != 0 && registers.base_sequence < header.sequence
                },
                "invalid register snapshot/baseline"
            );
            let mut values = [0; REGISTER_COUNT];
            let (raw_values, _) = payload[size_of::<RegisterHeader>()..].as_chunks::<8>();
            for (value, raw) in values.iter_mut().zip(raw_values) {
                *value = u64::from_le_bytes(*raw);
            }
            Some(RegisterChanges {
                full,
                header: registers,
                values,
            })
        } else {
            ensure!(payload.is_empty(), "unexpected register payload");
            None
        };
        Ok(Self {
            header,
            regs: registers,
        })
    }
}

impl Writer<'_> {
    pub fn write(
        &self,
        event: &Event,
        missed: u64,
        incomplete: bool,
        output: &mut impl Write,
    ) -> Result<()> {
        let header = &event.header;
        if let Some(cache) = &self.json {
            let metadata = cache
                .get(point_index(header.cookie)?)
                .and_then(|point| point.get(header.pc))
                .context("instruction trace PC outside declared range")?;
            let record = Output {
                source: "instruction",
                timestamp_ns: header.timestamp_ns,
                tgid: header.tgid,
                tid: header.tid,
                cpu: header.cpu,
                sequence: header.sequence,
                thread_epoch: header.thread_epoch,
                probe: header.cookie,
                pc: &metadata.pc,
                module: &metadata.module,
                elf_address: &metadata.elf_address,
                opcode: &metadata.opcode,
                instruction: &metadata.instruction,
                missed_before: missed,
                incomplete,
                registers: event.regs.as_ref().map(|regs| RegisterOutput {
                    kind: regs.kind(),
                    base_sequence: regs.header.base_sequence,
                    values: ChangedValues(regs),
                }),
            };
            serde_json::to_writer(&mut *output, &record)?;
            writeln!(output)?;
        } else {
            let point = point(self.plan, header.cookie)?;
            let target = &self.plan.targets[point.target];
            let instruction = point
                .instructions
                .get(&header.pc)
                .context("instruction trace PC outside declared range")?;
            writeln!(
                output,
                "{}:{} #{} {:#x} {}+{:#x} {:08x} {} missed_before={} incomplete={}",
                header.tgid,
                header.tid,
                header.sequence,
                header.pc,
                target.path.display(),
                point.elf_address,
                instruction.word,
                instruction.assembly,
                missed,
                incomplete
            )?;
            if let Some(regs) = &event.regs {
                write!(
                    output,
                    " registers={} base_sequence={}",
                    regs.kind(),
                    regs.header.base_sequence
                )?;
                for (name, value) in regs.iter() {
                    write!(output, " {name}={value:#x}")?;
                }
                writeln!(output)?;
            }
        }
        Ok(())
    }
}

fn point_index(cookie: u64) -> Result<usize> {
    cookie
        .checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .context("invalid instruction trace cookie")
}

fn point(plan: &Plan, cookie: u64) -> Result<&Point> {
    plan.points
        .get(point_index(cookie)?)
        .context("unknown instruction trace cookie")
}

#[derive(Serialize)]
struct Output<'a> {
    source: &'static str,
    timestamp_ns: u64,
    tgid: u32,
    tid: u32,
    cpu: u32,
    sequence: u64,
    thread_epoch: u64,
    probe: u64,
    pc: &'a RawValue,
    module: &'a RawValue,
    elf_address: &'a RawValue,
    opcode: &'a RawValue,
    instruction: &'a RawValue,
    missed_before: u64,
    incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    registers: Option<RegisterOutput<'a>>,
}

#[derive(Serialize)]
struct RegisterOutput<'a> {
    kind: &'static str,
    base_sequence: u64,
    values: ChangedValues<'a>,
}

#[derive(Default)]
pub struct Sequences {
    hot_tid: u32,
    hot_epoch: u64,
    hot_sequence: u64,
    threads: HashMap<u32, (u64, u64)>,
    pub missed: u64,
    pub incomplete: bool,
}

impl Sequences {
    pub fn observe(&mut self, event: &Event) -> Result<u64> {
        let header = &event.header;
        let previous = if self.hot_tid == header.tid && self.hot_tid != 0 {
            if self.hot_epoch == header.thread_epoch {
                self.hot_sequence
            } else {
                ensure!(
                    header.thread_epoch > self.hot_epoch,
                    "instruction trace thread epoch moved backwards"
                );
                0
            }
        } else {
            match self.threads.get(&header.tid) {
                Some(&(epoch, sequence)) if epoch == header.thread_epoch => sequence,
                Some(&(epoch, _)) => {
                    ensure!(
                        header.thread_epoch > epoch,
                        "instruction trace thread epoch moved backwards"
                    );
                    0
                }
                None => {
                    let existing = usize::from(self.hot_tid != 0) + self.threads.len();
                    ensure!(
                        existing < instruction::MAX_THREADS as usize,
                        "instruction trace exceeded userspace thread identity budget"
                    );
                    0
                }
            }
        };
        ensure!(
            header.sequence > previous,
            "instruction trace sequence repeated or moved backwards"
        );
        if let Some(regs) = &event.regs {
            ensure!(
                regs.full
                    || (previous != 0
                        && regs.header.base_sequence == previous
                        && header.sequence - previous == 1),
                "instruction trace register delta has no matching baseline"
            );
        }
        let missed = header.sequence - previous - 1;
        self.missed += missed;
        self.incomplete |= missed != 0;
        if self.hot_tid != header.tid && self.hot_tid != 0 {
            self.threads
                .insert(self.hot_tid, (self.hot_epoch, self.hot_sequence));
        }
        self.hot_tid = header.tid;
        self.hot_epoch = header.thread_epoch;
        self.hot_sequence = header.sequence;
        Ok(missed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::ResolvedProbe;
    use debugplz_abi::instruction::Record;
    use std::fs::File;

    fn plan() -> Plan {
        Plan {
            targets: vec![ResolvedProbe {
                file: File::open("/dev/null").unwrap(),
                path: "/test.so".into(),
                file_offset: 4096,
                elf_address: 0x1000,
                mappings: vec![],
            }],
            points: vec![Point {
                target: 0,
                file_offset: 4096,
                elf_address: 0x1000,
                instructions: [(
                    0x7000,
                    super::super::plan::Instruction {
                        word: 0xd503201f,
                        assembly: "nop".into(),
                    },
                )]
                .into(),
            }],
            pid: 10,
            pages: Default::default(),
        }
    }

    fn header() -> Header {
        Header {
            magic: instruction::MAGIC,
            version: instruction::VERSION,
            length: 64,
            tgid: 10,
            tid: 11,
            sequence: 1,
            thread_epoch: 55,
            cookie: 1,
            pc: 0x7000,
            ..Header::default()
        }
    }

    fn pc_event(header: Header) -> Event {
        Event { header, regs: None }
    }

    fn record(sequence: u64, base: u64, mask: u64, values: &[u64]) -> Record {
        let mut record = Record {
            header: Header {
                flags: instruction::FLAG_REGS
                    | if base == 0 {
                        instruction::FLAG_REGS_FULL
                    } else {
                        0
                    },
                length: u32::try_from(80 + 8 * values.len()).unwrap(),
                sequence,
                ..header()
            },
            registers: RegisterHeader {
                base_sequence: base,
                changed_mask: mask,
            },
            ..Record::default()
        };
        record.values[..values.len()].copy_from_slice(values);
        record
    }

    fn bytes<T>(value: &T) -> &[u8] {
        // SAFETY: test values are initialized integer-only headers/records with no padding.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        }
    }

    fn decode(record: &Record) -> Result<Event> {
        Event::decode(
            &bytes(record)[..record.header.length as usize],
            10,
            true,
            &plan(),
        )
    }

    #[test]
    fn rejects_forged_pc_events_and_old_abi() {
        let plan = plan();
        let h = header();
        assert!(Event::decode(bytes(&h), 10, false, &plan).is_ok());
        assert!(Event::decode(&bytes(&h)[..63], 10, false, &plan).is_err());
        assert!(Event::decode(bytes(&h), 10, true, &plan).is_err());
        for h in [
            Header { length: 336, ..h },
            Header { flags: 2, ..h },
            Header { cookie: 0, ..h },
            Header { pc: 0x7004, ..h },
            Header { tgid: 12, ..h },
            Header { version: 1, ..h },
            Header { sequence: 0, ..h },
        ] {
            assert!(Event::decode(bytes(&h), 10, false, &plan).is_err());
        }
    }

    #[test]
    fn outputs_instruction_for_the_actual_runtime_alias() {
        let mut plan = plan();
        plan.points[0].instructions.insert(
            0x9000,
            super::super::plan::Instruction {
                word: 0xd10243ff,
                assembly: "sub sp, sp, #0x90".into(),
            },
        );
        let writer = Writer::new(&plan, true).unwrap();
        for (pc, opcode) in [(0x7000, "d503201f"), (0x9000, "d10243ff")] {
            let h = Header { pc, ..header() };
            let event = Event::decode(bytes(&h), 10, false, &plan).unwrap();
            let mut output = Vec::new();
            writer.write(&event, 0, false, &mut output).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(json["opcode"], opcode);
            assert_eq!(json["pc"], format!("{pc:#x}"));
        }
    }

    #[test]
    fn cached_json_preserves_escaping_and_changing_event_fields() {
        let mut plan = plan();
        let module = "/test\"\\\n雪.so";
        let assembly = "text \"quoted\"\\\n雪";
        plan.targets[0].path = module.into();
        plan.points[0]
            .instructions
            .get_mut(&0x7000)
            .unwrap()
            .assembly = assembly.into();
        let writer = Writer::new(&plan, true).unwrap();
        for sequence in [1, 9] {
            let event = pc_event(Header {
                sequence,
                timestamp_ns: sequence * 100,
                ..header()
            });
            let mut output = Vec::new();
            writer
                .write(&event, sequence - 1, sequence != 1, &mut output)
                .unwrap();
            let actual: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(
                actual,
                serde_json::json!({
                    "source": "instruction", "timestamp_ns": sequence * 100,
                    "tgid": 10, "tid": 11, "cpu": 0, "sequence": sequence,
                    "thread_epoch": 55, "probe": 1, "pc": "0x7000",
                    "module": module, "elf_address": "0x1000", "opcode": "d503201f",
                    "instruction": assembly, "missed_before": sequence - 1,
                    "incomplete": sequence != 1,
                })
            );
            assert!(output.ends_with(b"\n"));
        }
    }

    #[test]
    fn full_snapshot_decodes_unaligned_and_writes_named_registers() {
        let record = record(1, 0, instruction::REGISTER_MASK, &[123; REGISTER_COUNT]);
        let mut unaligned = vec![0];
        unaligned.extend_from_slice(bytes(&record));
        let event = Event::decode(&unaligned[1..], 10, true, &plan()).unwrap();
        assert_eq!(event.regs.as_ref().unwrap().iter().count(), REGISTER_COUNT);
        let mut output = Vec::new();
        Writer::new(&plan(), true)
            .unwrap()
            .write(&event, 2, true, &mut output)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["missed_before"], 2);
        assert_eq!(json["registers"]["kind"], "full");
        assert_eq!(json["registers"]["base_sequence"], 0);
        assert_eq!(json["registers"]["values"]["x30"], 123);
        assert_eq!(json["registers"]["values"]["sp"], 123);
        assert_eq!(
            json["registers"]["values"].as_object().unwrap().len(),
            REGISTER_COUNT
        );
        assert!(json["registers"]["values"].get("pc").is_none());
    }

    #[test]
    fn deltas_pack_zero_sp_pstate_and_allow_no_changes() {
        let changed = record(
            2,
            1,
            (1 << 13) | (1 << 31) | (1 << 32),
            &[0, 0x8000, 0x60000000],
        );
        assert_eq!(changed.header.length, 104);
        let event = decode(&changed).unwrap();
        let mut output = Vec::new();
        Writer::new(&plan(), true)
            .unwrap()
            .write(&event, 0, false, &mut output)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            json["registers"],
            serde_json::json!({
                "kind": "delta", "base_sequence": 1,
                "values": {"x13": 0, "sp": 0x8000, "pstate": 0x60000000}
            })
        );
        let unchanged = record(3, 2, 0, &[]);
        assert_eq!(unchanged.header.length, 80);
        assert_eq!(decode(&unchanged).unwrap().regs.unwrap().iter().count(), 0);
        let all = record(4, 3, instruction::REGISTER_MASK, &[456; REGISTER_COUNT]);
        assert_eq!(
            decode(&all).unwrap().regs.unwrap().iter().count(),
            REGISTER_COUNT
        );
    }

    #[test]
    fn rejects_invalid_masks_lengths_flags_and_bases() {
        for record in [
            record(2, 1, 1 << 33, &[1]),
            record(2, 1, 3, &[1]),
            record(2, 1, 0, &[1]),
            record(1, 0, 1, &[1]),
            record(1, 1, 0, &[]),
            record(2, 3, 0, &[]),
        ] {
            assert!(decode(&record).is_err());
        }
        let mut r = record(1, 0, instruction::REGISTER_MASK, &[0; REGISTER_COUNT]);
        r.header.flags = instruction::FLAG_REGS;
        assert!(decode(&r).is_err());
        r.header.flags = 7;
        assert!(decode(&r).is_err());
        r.header.flags = instruction::FLAG_REGS | instruction::FLAG_REGS_FULL;
        r.registers.base_sequence = 1;
        assert!(decode(&r).is_err());
        let r = record(2, 1, 1, &[1]);
        assert!(Event::decode(&bytes(&r)[..87], 10, true, &plan()).is_err());
        assert!(Event::decode(bytes(&r), 10, true, &plan()).is_err());
    }

    #[test]
    fn gaps_migration_and_tid_reuse_keep_separate_sequences() {
        let mut sequences = Sequences::default();
        let h = header();
        assert_eq!(sequences.observe(&pc_event(h)).unwrap(), 0);
        assert_eq!(
            sequences
                .observe(&pc_event(Header {
                    sequence: 4,
                    cpu: 7,
                    ..h
                }))
                .unwrap(),
            2
        );
        assert!(
            sequences
                .observe(&pc_event(Header { sequence: 4, ..h }))
                .is_err()
        );
        assert_eq!(
            sequences
                .observe(&pc_event(Header {
                    thread_epoch: 56,
                    ..h
                }))
                .unwrap(),
            0
        );
        assert!(
            sequences
                .observe(&pc_event(Header {
                    thread_epoch: 55,
                    sequence: 10,
                    ..h
                }))
                .is_err()
        );
        assert_eq!(sequences.missed, 2);
        assert!(sequences.incomplete);
    }

    #[test]
    fn register_chain_requires_initial_and_recovery_snapshots() {
        let mut sequences = Sequences::default();
        let full = |seq| {
            decode(&record(
                seq,
                0,
                instruction::REGISTER_MASK,
                &[123; REGISTER_COUNT],
            ))
            .unwrap()
        };
        let delta = |seq, base| decode(&record(seq, base, 1, &[456])).unwrap();
        assert!(sequences.observe(&delta(2, 1)).is_err());
        assert_eq!(sequences.observe(&full(1)).unwrap(), 0);
        assert_eq!(sequences.observe(&delta(2, 1)).unwrap(), 0);
        assert!(sequences.observe(&delta(5, 4)).is_err());
        assert!(sequences.observe(&delta(5, 2)).is_err());
        assert_eq!(sequences.observe(&full(5)).unwrap(), 2);
        assert_eq!(sequences.observe(&delta(6, 5)).unwrap(), 0);
        assert!(sequences.observe(&delta(7, 2)).is_err());
        let mut migrated = delta(7, 6);
        migrated.header.cpu = 7;
        assert_eq!(sequences.observe(&migrated).unwrap(), 0);
        let mut independent = full(1);
        independent.header.tid = 12;
        assert_eq!(sequences.observe(&independent).unwrap(), 0);
        let mut reused = delta(8, 7);
        reused.header.thread_epoch = 56;
        assert!(sequences.observe(&reused).is_err());
        reused = full(1);
        reused.header.thread_epoch = 56;
        assert_eq!(sequences.observe(&reused).unwrap(), 0);
        assert_eq!(sequences.missed, 2);
        assert!(sequences.incomplete);
    }
}

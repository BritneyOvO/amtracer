use super::plan::{Plan, Point};
use amtracer_abi::{
    Registers,
    instruction::{self, Header, Record},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::HashMap, io::Write};

pub struct Event {
    pub header: Header,
    pub regs: Option<Registers>,
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
            header.flags == if regs { instruction::FLAG_REGS } else { 0 },
            "unexpected instruction trace flags"
        );
        let length = if regs {
            size_of::<Record>()
        } else {
            size_of::<Header>()
        };
        ensure!(
            bytes.len() == length && header.length as usize == length,
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
        ensure!(
            point.addresses.contains(&header.pc),
            "instruction trace PC outside declared range"
        );
        let registers = if regs {
            // SAFETY: Record is repr(C) integers only and its exact length was checked.
            let record = unsafe { bytes.as_ptr().cast::<Record>().read_unaligned() };
            ensure!(record.regs.pc == header.pc, "inconsistent register PC");
            Some(record.regs)
        } else {
            None
        };
        Ok(Self {
            header,
            regs: registers,
        })
    }

    pub fn write(
        &self,
        plan: &Plan,
        missed: u64,
        incomplete: bool,
        json: bool,
        output: &mut impl Write,
    ) -> Result<()> {
        let point = point(plan, self.header.cookie)?;
        let target = &plan.targets[point.target];
        if json {
            let event = Output {
                source: "instruction",
                timestamp_ns: self.header.timestamp_ns,
                tgid: self.header.tgid,
                tid: self.header.tid,
                cpu: self.header.cpu,
                sequence: self.header.sequence,
                thread_epoch: self.header.thread_epoch,
                probe: self.header.cookie,
                pc: format!("{:#x}", self.header.pc),
                module: target.path.to_string_lossy(),
                elf_address: format!("{:#x}", point.elf_address),
                opcode: format!("{:08x}", point.word),
                instruction: &point.assembly,
                missed_before: missed,
                incomplete,
                registers: self.regs.as_ref().map(|regs| RegisterOutput {
                    x: &regs.x,
                    sp: regs.sp,
                    pc: regs.pc,
                    pstate: regs.pstate,
                }),
            };
            serde_json::to_writer(&mut *output, &event)?;
            writeln!(output)?;
        } else {
            writeln!(
                output,
                "{}:{} #{} {:#x} {}+{:#x} {:08x} {} missed_before={} incomplete={}",
                self.header.tgid,
                self.header.tid,
                self.header.sequence,
                self.header.pc,
                target.path.display(),
                point.elf_address,
                point.word,
                point.assembly,
                missed,
                incomplete
            )?;
            if let Some(regs) = self.regs {
                for (index, value) in regs.x.iter().enumerate() {
                    write!(output, " x{index}={value:#x}")?;
                }
                writeln!(
                    output,
                    " sp={:#x} pc={:#x} pstate={:#x}",
                    regs.sp, regs.pc, regs.pstate
                )?;
            }
        }
        Ok(())
    }
}

fn point(plan: &Plan, cookie: u64) -> Result<&Point> {
    let index = cookie
        .checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .context("invalid instruction trace cookie")?;
    plan.points
        .get(index)
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
    pc: String,
    module: std::borrow::Cow<'a, str>,
    elf_address: String,
    opcode: String,
    instruction: &'a str,
    missed_before: u64,
    incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    registers: Option<RegisterOutput<'a>>,
}

#[derive(Serialize)]
struct RegisterOutput<'a> {
    x: &'a [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[derive(Default)]
pub struct Sequences {
    threads: HashMap<u32, (u64, u64)>,
    pub missed: u64,
    pub incomplete: bool,
}

impl Sequences {
    pub fn observe(&mut self, header: &Header) -> Result<u64> {
        let previous = match self.threads.get(&header.tid) {
            Some((epoch, sequence)) if *epoch == header.thread_epoch => *sequence,
            Some((epoch, _)) => {
                ensure!(
                    header.thread_epoch > *epoch,
                    "instruction trace thread epoch moved backwards"
                );
                0
            }
            None => {
                ensure!(
                    self.threads.len() < instruction::MAX_THREADS as usize,
                    "instruction trace exceeded userspace thread identity budget"
                );
                0
            }
        };
        ensure!(
            header.sequence > previous,
            "instruction trace sequence repeated or moved backwards"
        );
        let missed = header.sequence - previous - 1;
        self.missed += missed;
        self.incomplete |= missed != 0;
        self.threads
            .insert(header.tid, (header.thread_epoch, header.sequence));
        Ok(missed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::ResolvedProbe;
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
                word: 0xd503201f,
                assembly: "nop".into(),
                addresses: vec![0x7000],
            }],
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

    fn bytes<T>(value: &T) -> &[u8] {
        // SAFETY: test values are initialized integer-only headers/records with no padding.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        }
    }

    #[test]
    fn rejects_forged_events_and_unaligned_registers_decode() {
        let plan = plan();
        let h = header();
        assert!(Event::decode(bytes(&h), 10, false, &plan).is_ok());
        assert!(Event::decode(&bytes(&h)[..63], 10, false, &plan).is_err());
        for h in [
            Header { length: 336, ..h },
            Header { flags: 2, ..h },
            Header { cookie: 0, ..h },
            Header { pc: 0x7004, ..h },
            Header { tgid: 12, ..h },
            Header { version: 99, ..h },
            Header { sequence: 0, ..h },
        ] {
            assert!(Event::decode(bytes(&h), 10, false, &plan).is_err());
        }
        let record = Record {
            header: Header {
                flags: 1,
                length: 336,
                ..h
            },
            regs: Registers {
                pc: h.pc,
                x: [123; 31],
                ..Registers::default()
            },
        };
        let mut unaligned = vec![0];
        unaligned.extend_from_slice(bytes(&record));
        assert_eq!(
            Event::decode(&unaligned[1..], 10, true, &plan)
                .unwrap()
                .regs
                .unwrap()
                .x[30],
            123
        );
        let mut output = Vec::new();
        Event::decode(bytes(&record), 10, true, &plan)
            .unwrap()
            .write(&plan, 2, true, true, &mut output)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["missed_before"], 2);
        assert_eq!(json["registers"]["x"][30], 123);
    }

    #[test]
    fn gaps_migration_and_tid_reuse_keep_separate_sequences() {
        let mut sequences = Sequences::default();
        let h = header();
        assert_eq!(sequences.observe(&h).unwrap(), 0);
        assert_eq!(
            sequences
                .observe(&Header {
                    sequence: 4,
                    cpu: 7,
                    ..h
                })
                .unwrap(),
            2
        );
        assert!(sequences.observe(&Header { sequence: 4, ..h }).is_err());
        assert_eq!(
            sequences
                .observe(&Header {
                    thread_epoch: 56,
                    ..h
                })
                .unwrap(),
            0
        );
        assert!(
            sequences
                .observe(&Header {
                    thread_epoch: 55,
                    sequence: 10,
                    ..h
                })
                .is_err()
        );
        assert_eq!(sequences.missed, 2);
        assert!(sequences.incomplete);
    }
}

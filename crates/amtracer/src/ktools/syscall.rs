use super::{bindings::*, prefix};
use crate::unwind::{NativeUnwinder, Snapshot};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;

pub struct Blob<'a> {
    header: sct_blob,
    bytes: &'a [u8],
}
pub struct Record<'a> {
    pub header: sct_event_header,
    blobs: Vec<Blob<'a>>,
}
impl<'a> TryFrom<&'a [u8]> for Record<'a> {
    type Error = anyhow::Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let header: sct_event_header = prefix(bytes)?;
        ensure!(
            header.magic == SCT_EVENT_MAGIC
                && u32::from(header.version) == SCT_EVENT_VERSION
                && header.size as usize == bytes.len(),
            "invalid syscall event ABI/length"
        );
        ensure!(
            [
                sct_event_type_SCT_EV_ENTER,
                sct_event_type_SCT_EV_EXIT,
                sct_event_type_SCT_EV_LOST
            ]
            .contains(&u32::from(header.type_)),
            "unknown syscall event type"
        );
        let count = header.blob_count as usize;
        let start = header.blob_off as usize;
        let end = start
            .checked_add(
                count
                    .checked_mul(size_of::<sct_blob>())
                    .context("blob count overflow")?,
            )
            .context("blob table overflow")?;
        ensure!(
            start >= size_of::<sct_event_header>() && end <= bytes.len(),
            "blob table outside record"
        );
        let mut blobs = Vec::with_capacity(count);
        let mut previous_end = end;
        let mut seen_stack = false;
        for index in 0..count {
            let blob: sct_blob = prefix(&bytes[start + index * size_of::<sct_blob>()..])?;
            let offset = blob.data_off as usize;
            let data_end = offset
                .checked_add(blob.data_len as usize)
                .context("blob length overflow")?;
            ensure!(
                offset >= previous_end && data_end <= bytes.len(),
                "overlapping or out-of-bounds blob"
            );
            ensure!(
                u32::from(blob.flags) & !SCT_BLOB_F_FAULT == 0,
                "unknown blob flags"
            );
            if u32::from(blob.kind) == sct_blob_kind_SCT_BLOB_USER_STACK {
                ensure!(
                    !seen_stack && blob.user_addr == header.user_sp && blob.data_len <= 16384,
                    "invalid stack blob"
                );
                seen_stack = true;
            } else {
                ensure!(blob.arg_index < 6, "invalid argument index");
            }
            blobs.push(Blob {
                header: blob,
                bytes: &bytes[offset..data_end],
            });
            previous_end = data_end;
        }
        Ok(Self { header, blobs })
    }
}

#[derive(Default)]
pub struct Decoder {
    pending: HashMap<u32, (i32, u64)>,
    lost: u32,
    next_expiry: u64,
    pub invalidated: u64,
}
impl Decoder {
    pub fn event(&mut self, record: Record<'_>, unwinder: Option<&mut NativeUnwinder>) -> Value {
        let h = record.header;
        let lost = u32::from(h.type_) == sct_event_type_SCT_EV_LOST;
        if h.lost_before != self.lost || lost {
            self.invalidated += self.pending.len() as u64;
            self.pending.clear();
            self.lost = h.lost_before;
        }
        // A bounded map handles threads which never produce an EXIT. Expiry is
        // amortized once per event-time second; capacity eviction is explicit.
        const EXPIRY_NS: u64 = 300_000_000_000;
        if h.ts_ns >= self.next_expiry {
            let before = self.pending.len();
            self.pending
                .retain(|_, (_, time)| h.ts_ns.saturating_sub(*time) <= EXPIRY_NS);
            self.invalidated += (before - self.pending.len()) as u64;
            self.next_expiry = h.ts_ns.saturating_add(1_000_000_000);
        }
        let enter = u32::from(h.type_) == sct_event_type_SCT_EV_ENTER;
        let duration = if lost {
            None
        } else if enter {
            if self.pending.len() >= 4096
                && !self.pending.contains_key(&h.tid)
                && let Some(tid) = self
                    .pending
                    .iter()
                    .min_by_key(|(_, (_, time))| *time)
                    .map(|(tid, _)| *tid)
            {
                self.pending.remove(&tid);
                self.invalidated += 1;
            }
            if self.pending.insert(h.tid, (h.nr, h.ts_ns)).is_some() {
                self.invalidated += 1;
            }
            None
        } else {
            self.pending.remove(&h.tid).and_then(|(nr, time)| {
                if nr == h.nr {
                    h.ts_ns.checked_sub(time)
                } else {
                    None
                }
            })
        };
        let restart = !enter && matches!(h.ret, -512 | -513 | -514 | -516);
        let errno = if !enter && !restart && (-4095..=-1).contains(&h.ret) {
            Some(-h.ret)
        } else {
            None
        };
        let mut event = json!({"source":"syscall","timestamp_ns":h.ts_ns,"sequence":h.seq,"tgid":h.pid,"tid":h.tid,"cpu":h.cpu,"nr":h.nr,
            "phase":if lost {"lost"}else if enter {"enter"}else{"exit"},"args":h.args,"return":if enter||lost {None}else{Some(h.ret)},
            "errno":errno,"restart":restart,"duration_ns":duration,"flags":h.flags,"lost_before":h.lost_before,"pc":h.user_pc,"sp":h.user_sp});
        let mut args = Vec::new();
        let mut stack = None;
        for blob in record.blobs {
            if u32::from(blob.header.kind) == sct_blob_kind_SCT_BLOB_USER_STACK {
                stack = Some(blob);
            } else {
                let mut arg = json!({"index":blob.header.arg_index,"kind":blob.header.kind,"address":format!("{:#x}",blob.header.user_addr),"flags":blob.header.flags,"data":blob.bytes});
                if u32::from(blob.header.kind) == sct_blob_kind_SCT_BLOB_USER_STRING {
                    let end = blob
                        .bytes
                        .iter()
                        .position(|b| *b == 0)
                        .unwrap_or(blob.bytes.len());
                    arg["text"] = json!(String::from_utf8_lossy(&blob.bytes[..end]));
                }
                args.push(arg);
            }
        }
        event["blobs"] = json!(args);
        if let Some(unwinder) = unwinder {
            event["stack"] = if let Some(blob) = stack {
                if u32::from(blob.header.flags) & SCT_BLOB_F_FAULT != 0 {
                    json!({"frames":[],"end":"capture_fault","snapshot_bytes":0})
                } else {
                    unwinder.unwind(Snapshot {
                        pc: h.user_pc,
                        sp: h.user_sp,
                        fp: h.user_fp,
                        lr: h.user_lr,
                        bytes: blob.bytes,
                    })
                }
            } else {
                json!({"frames":[],"end":"not_captured","snapshot_bytes":0})
            };
        }
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn empty(phase: u32, tid: u32, ts: u64) -> Record<'static> {
        Record {
            header: sct_event_header {
                type_: u16::try_from(phase).unwrap(),
                tid,
                ts_ns: ts,
                nr: 172,
                ..Default::default()
            },
            blobs: Vec::new(),
        }
    }
    #[test]
    fn loss_and_wrong_number_invalidate_pairing() {
        let mut decoder = Decoder::default();
        decoder.event(empty(sct_event_type_SCT_EV_ENTER, 1, 10), None);
        let mut exit = empty(sct_event_type_SCT_EV_EXIT, 1, 20);
        exit.header.lost_before = 1;
        assert_eq!(decoder.event(exit, None)["duration_ns"], Value::Null);
        decoder.event(empty(sct_event_type_SCT_EV_ENTER, 1, 30), None);
        let mut exit = empty(sct_event_type_SCT_EV_EXIT, 1, 40);
        exit.header.nr = 63;
        assert_eq!(decoder.event(exit, None)["duration_ns"], Value::Null);
        decoder.event(empty(sct_event_type_SCT_EV_ENTER, 1, 50), None);
        assert_eq!(
            decoder.event(empty(sct_event_type_SCT_EV_EXIT, 1, 70), None)["duration_ns"],
            20
        );
    }
    #[test]
    fn pairing_is_bounded_and_restarts_are_not_errno() {
        let mut decoder = Decoder::default();
        for tid in 0..4100 {
            decoder.event(empty(sct_event_type_SCT_EV_ENTER, tid, 10), None);
        }
        assert_eq!(decoder.pending.len(), 4096);
        assert_eq!(decoder.invalidated, 4);
        let mut exit = empty(sct_event_type_SCT_EV_EXIT, 4099, 20);
        exit.header.ret = -512;
        let event = decoder.event(exit, None);
        assert_eq!(event["errno"], Value::Null);
        assert_eq!(event["restart"], true);
    }
    #[test]
    fn rejects_short_and_forged_tables() {
        assert!(Record::try_from(&[0; 16][..]).is_err());
        let mut bytes = vec![0; size_of::<sct_event_header>()];
        bytes[0..4].copy_from_slice(&SCT_EVENT_MAGIC.to_ne_bytes());
        bytes[4..6].copy_from_slice(&u16::try_from(SCT_EVENT_VERSION).unwrap().to_ne_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_ne_bytes());
        let len = u32::try_from(bytes.len()).unwrap();
        bytes[8..12].copy_from_slice(&len.to_ne_bytes());
        let table = std::mem::offset_of!(sct_event_header, blob_off);
        bytes[table..table + 4].copy_from_slice(&len.to_ne_bytes());
        assert!(Record::try_from(bytes.as_slice()).is_ok());
        let count = std::mem::offset_of!(sct_event_header, blob_count);
        bytes[count..count + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(Record::try_from(bytes.as_slice()).is_err());
    }
}

use super::bindings::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;

pub fn event(header: bt_binder_event, features: u32) -> Result<Value> {
    ensure!(
        header.kind == BT_EVENT_KIND_BINDER_TRANSACTION
            && header.data_len <= BT_MAX_INLINE_DATA
            && u64::from(header.data_len) <= header.data_size,
        "invalid Binder record"
    );
    let outcome = if features & BT_FEATURE_TRANSACTION_RESULT == 0 {
        "unknown"
    } else {
        match u32::from(header.outcome) {
            BT_OUTCOME_SUBMITTED => "submitted",
            BT_OUTCOME_FAILED => "failed",
            _ => "unknown",
        }
    };
    let data = &header.data[..header.data_len as usize];
    let interface = if header.reply == 0 {
        interface_token(data)
    } else {
        None
    };
    Ok(
        json!({"source":"binder","timestamp_ns":header.timestamp_ns,"sequence":header.sequence,"tgid":header.tgid,"tid":header.pid,
        "transaction_id":header.transaction_debug_id,"reply_to_id":header.reply_to_debug_id,"reply":header.reply!=0,"oneway":header.flags&1!=0,
        "code":header.code,"flags":header.flags,"sender_pid":header.sender_pid,"sender_euid":header.sender_euid,"target_handle":header.target_handle,
        "outcome":outcome,"error":header.error,"data_size":header.data_size,"data":data,"truncated":header.data_truncated!=0,"lost_before":header.lost_before,
        "interface_token":interface}),
    )
}

#[derive(Clone, Copy)]
struct Pending {
    timestamp_ns: u64,
    sequence: u64,
    tgid: u32,
    tid: u32,
    code: u32,
    owner: bool,
}

pub struct Decoder {
    owner_tgid: u32,
    with_replies: bool,
    pending: HashMap<u32, Pending>,
    last_sequence: Option<u64>,
    lost_before: u32,
    next_expiry_ns: u64,
    pub invalidated: u64,
}

impl Decoder {
    pub fn new(owner_tgid: u32, with_replies: bool) -> Self {
        Self {
            owner_tgid,
            with_replies,
            pending: HashMap::new(),
            last_sequence: None,
            lost_before: 0,
            next_expiry_ns: 0,
            invalidated: 0,
        }
    }

    pub fn event(&mut self, header: bt_binder_event, features: u32) -> Result<Option<Value>> {
        if !self.with_replies {
            return event(header, features).map(Some);
        }

        let sequence = header.sequence;
        let lost_before = header.lost_before;
        let lost_delta = lost_before.saturating_sub(self.lost_before);
        let sequence_discontinuity = self
            .last_sequence
            .is_some_and(|previous| sequence != previous.saturating_add(1));
        if sequence_discontinuity || lost_delta > 0 || lost_before < self.lost_before {
            self.invalidated += self.pending.len() as u64;
            self.pending.clear();
        }
        self.last_sequence = Some(sequence);
        self.lost_before = lost_before;

        const EXPIRY_NS: u64 = 300_000_000_000;
        if header.timestamp_ns >= self.next_expiry_ns {
            let before = self.pending.len();
            self.pending.retain(|_, request| {
                header.timestamp_ns.saturating_sub(request.timestamp_ns) <= EXPIRY_NS
            });
            self.invalidated += (before - self.pending.len()) as u64;
            self.next_expiry_ns = header.timestamp_ns.saturating_add(1_000_000_000);
        }

        let owner_event = header.tgid == self.owner_tgid;
        let mut decoded = event(header, features)?;
        if header.reply != 0 {
            let request = self.pending.remove(&header.reply_to_debug_id);
            if let Some(request) = request {
                if !request.owner {
                    return Ok(None);
                }
                decoded["correlation"] = json!({
                    "status": if u32::from(header.outcome) == BT_OUTCOME_FAILED
                        && features & BT_FEATURE_TRANSACTION_RESULT != 0
                    {
                        "reply_failed"
                    } else {
                        "matched"
                    },
                    "request_sequence": request.sequence,
                    "request_tgid": request.tgid,
                    "request_tid": request.tid,
                    "request_code": request.code,
                    "elapsed_ns": header.timestamp_ns.checked_sub(request.timestamp_ns),
                });
                return Ok(Some(decoded));
            }
            return Ok(None);
        }

        let oneway = header.flags & 1 != 0;
        let outcome = u32::from(header.outcome);
        if oneway {
            if !owner_event {
                return Ok(None);
            }
            decoded["correlation"] = json!({"status":"not_expected","reason":"oneway"});
        } else if features & BT_FEATURE_TRANSACTION_RESULT != 0 && outcome == BT_OUTCOME_FAILED {
            if !owner_event {
                return Ok(None);
            }
            decoded["correlation"] = json!({"status":"failed_request"});
        } else if features & BT_FEATURE_TRANSACTION_RESULT != 0
            && outcome == BT_OUTCOME_SUBMITTED
            && header.transaction_debug_id != 0
        {
            if self.pending.len() >= 4096
                && !self.pending.contains_key(&header.transaction_debug_id)
                && let Some(id) = self
                    .pending
                    .iter()
                    .min_by_key(|(_, request)| request.timestamp_ns)
                    .map(|(id, _)| *id)
            {
                self.pending.remove(&id);
                self.invalidated += 1;
            }
            let request = Pending {
                timestamp_ns: header.timestamp_ns,
                sequence: header.sequence,
                tgid: header.tgid,
                tid: header.pid,
                code: header.code,
                owner: owner_event,
            };
            if self
                .pending
                .insert(header.transaction_debug_id, request)
                .is_some()
            {
                self.invalidated += 1;
            }
            if !owner_event {
                return Ok(None);
            }
            decoded["correlation"] =
                json!({"status":"pending","request_id":header.transaction_debug_id});
        } else {
            if !owner_event {
                return Ok(None);
            }
            decoded["correlation"] = json!({"status":"unknown_outcome"});
        }
        Ok(owner_event.then_some(decoded))
    }
}

fn interface_token(bytes: &[u8]) -> Option<String> {
    // Android 13 native Parcel header. Other layouts stay raw instead of
    // guessing a UTF-16 string in arbitrary transaction payloads.
    let marker = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    if marker != 0x53595354 {
        return None;
    }
    let length = i32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?);
    let length = usize::try_from(length).ok()?;
    let end = 16_usize.checked_add(length.checked_mul(2)?)?;
    if bytes.get(end..end.checked_add(2)?)? != [0, 0] {
        return None;
    }
    let words = bytes
        .get(16..end)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
        .collect::<Vec<_>>();
    let token = String::from_utf16(&words).ok()?;
    (!token.is_empty() && !token.chars().any(char::is_control)).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(
        sequence: u64,
        timestamp_ns: u64,
        tgid: u32,
        reply: bool,
        id: u32,
        reply_to: u32,
    ) -> bt_binder_event {
        bt_binder_event {
            sequence,
            timestamp_ns,
            kind: BT_EVENT_KIND_BINDER_TRANSACTION,
            pid: tgid + 1,
            tgid,
            reply: u32::from(reply),
            transaction_debug_id: id,
            reply_to_debug_id: reply_to,
            flags: 0,
            outcome: u8::try_from(BT_OUTCOME_SUBMITTED).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn token_requires_complete_utf16_and_terminator() {
        let mut bytes = vec![0; 16];
        bytes[8..12].copy_from_slice(&0x53595354_u32.to_le_bytes());
        let words = "amtracer.ITest".encode_utf16().collect::<Vec<_>>();
        bytes[12..16].copy_from_slice(&i32::try_from(words.len()).unwrap().to_le_bytes());
        for word in words {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend([0, 0]);
        assert_eq!(interface_token(&bytes).as_deref(), Some("amtracer.ITest"));
        for end in 0..bytes.len() {
            assert!(interface_token(&bytes[..end]).is_none());
        }
        bytes[12..16].copy_from_slice(&i32::MAX.to_le_bytes());
        assert!(interface_token(&bytes).is_none());
    }
    #[test]
    fn outcome_is_not_inferred_from_errno() {
        let header = bt_binder_event {
            kind: BT_EVENT_KIND_BINDER_TRANSACTION,
            outcome: u8::try_from(BT_OUTCOME_FAILED).unwrap(),
            error: 0,
            ..Default::default()
        };
        assert_eq!(
            event(header, BT_FEATURE_TRANSACTION_RESULT).unwrap()["outcome"],
            "failed"
        );
        assert_eq!(event(header, 0).unwrap()["outcome"], "unknown");
    }

    #[test]
    fn correlates_target_request_with_peer_reply() {
        let mut decoder = Decoder::new(100, true);
        let request = transaction(1, 100, 100, false, 77, 0);
        assert_eq!(
            decoder
                .event(request, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .unwrap()["correlation"]["status"],
            "pending"
        );
        let reply = transaction(2, 180, 200, true, 78, 77);
        let event = decoder
            .event(reply, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap()
            .unwrap();
        assert_eq!(event["correlation"]["status"], "matched");
        assert_eq!(event["correlation"]["request_tgid"], 100);
        assert_eq!(event["correlation"]["elapsed_ns"], 80);
        assert_eq!(decoder.pending.len(), 0);
    }

    #[test]
    fn suppresses_peer_requests_and_unmatched_replies() {
        let mut decoder = Decoder::new(100, true);
        let unrelated = transaction(1, 100, 200, false, 10, 0);
        assert!(
            decoder
                .event(unrelated, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .is_none()
        );
        let reply = transaction(2, 120, 100, true, 11, 10);
        assert!(
            decoder
                .event(reply, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oneway_failure_and_loss_do_not_create_false_pairs() {
        let mut decoder = Decoder::new(100, true);
        let mut oneway = transaction(1, 10, 100, false, 4, 0);
        oneway.flags = 1;
        let event = decoder
            .event(oneway, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap()
            .unwrap();
        assert_eq!(event["correlation"]["status"], "not_expected");
        let mut failed = transaction(2, 20, 100, false, 5, 0);
        failed.outcome = u8::try_from(BT_OUTCOME_FAILED).unwrap();
        let event = decoder
            .event(failed, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap()
            .unwrap();
        assert_eq!(event["correlation"]["status"], "failed_request");

        let request = transaction(3, 30, 100, false, 6, 0);
        decoder
            .event(request, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap();
        let mut lost = transaction(5, 50, 200, false, 7, 0);
        lost.flags = 1;
        assert!(
            decoder
                .event(lost, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .is_none()
        );
        assert_eq!(decoder.pending.len(), 0);
        assert_eq!(decoder.invalidated, 1);
        let late_reply = transaction(6, 60, 100, true, 8, 6);
        assert!(
            decoder
                .event(late_reply, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn default_mode_keeps_single_pid_events_unchanged() {
        let mut decoder = Decoder::new(100, false);
        let request = transaction(1, 10, 100, false, 4, 0);
        let decoded = decoder
            .event(request, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap()
            .unwrap();
        assert!(decoded.get("correlation").is_none());
        let peer = transaction(2, 20, 200, false, 5, 0);
        assert!(
            decoder
                .event(peer, BT_FEATURE_TRANSACTION_RESULT)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn unknown_outcome_does_not_create_a_pair() {
        let mut decoder = Decoder::new(100, true);
        let request = transaction(1, 10, 100, false, 4, 0);
        let decoded = decoder.event(request, 0).unwrap().unwrap();
        assert_eq!(decoded["outcome"], "unknown");
        assert_eq!(decoded["correlation"]["status"], "unknown_outcome");
        let reply = transaction(2, 20, 200, true, 5, 4);
        assert!(decoder.event(reply, 0).unwrap().is_none());
    }

    #[test]
    fn sequence_repetition_invalidates_pending_pairs() {
        let mut decoder = Decoder::new(100, true);
        let request = transaction(4, 10, 100, false, 4, 0);
        decoder
            .event(request, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap();
        let duplicate = transaction(4, 20, 200, false, 5, 0);
        decoder
            .event(duplicate, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap();
        assert_eq!(decoder.pending.len(), 1);
        assert!(!decoder.pending.get(&5).unwrap().owner);
        assert_eq!(decoder.invalidated, 1);
    }

    #[test]
    fn failed_reply_is_not_reported_as_a_successful_match() {
        let mut decoder = Decoder::new(100, true);
        let request = transaction(1, 10, 100, false, 4, 0);
        decoder
            .event(request, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap();
        let mut reply = transaction(2, 20, 200, true, 5, 4);
        reply.outcome = u8::try_from(BT_OUTCOME_FAILED).unwrap();
        let decoded = decoder
            .event(reply, BT_FEATURE_TRANSACTION_RESULT)
            .unwrap()
            .unwrap();
        assert_eq!(decoded["correlation"]["status"], "reply_failed");
        assert_eq!(decoded["outcome"], "failed");
    }
}

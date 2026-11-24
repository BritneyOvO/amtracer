use super::bindings::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};

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
}

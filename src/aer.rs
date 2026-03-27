//! Compact Address-Event Representation (AER) codec used by stimuli bridge.
//!
//! Encoding uses timestamp deltas + varints for transport efficiency.

use thiserror::Error;

const MAGIC: &[u8; 4] = b"AER1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AerEvent {
    pub ts_us: u64,
    pub addr: u32,
    pub value: u8,
}

#[derive(Debug, Error)]
pub enum AerError {
    #[error("invalid AER header")]
    InvalidMagic,
    #[error("truncated AER payload")]
    Truncated,
    #[error("varint overflow")]
    VarintOverflow,
}

/// Encodes AER events sorted by timestamp into a compact binary payload.
pub fn encode_events(events: &[AerEvent]) -> Vec<u8> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|ev| ev.ts_us);

    let base_ts = sorted[0].ts_us;
    let mut out = Vec::with_capacity(12 + sorted.len() * 6);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&base_ts.to_le_bytes());

    let mut prev_ts = base_ts;
    for ev in sorted {
        let delta = ev.ts_us.saturating_sub(prev_ts);
        prev_ts = ev.ts_us;
        write_varint(delta, &mut out);
        write_varint(ev.addr as u64, &mut out);
        write_varint(ev.value as u64, &mut out);
    }

    out
}

/// Decodes AER payload bytes into ordered events.
pub fn decode_events(bytes: &[u8]) -> Result<Vec<AerEvent>, AerError> {
    if bytes.len() < 12 {
        return Err(AerError::Truncated);
    }
    if &bytes[..4] != MAGIC {
        return Err(AerError::InvalidMagic);
    }

    let mut idx = 4;
    let mut base = [0u8; 8];
    base.copy_from_slice(&bytes[idx..idx + 8]);
    idx += 8;
    let base_ts = u64::from_le_bytes(base);
    let mut prev_ts = base_ts;
    let mut events = Vec::new();

    while idx < bytes.len() {
        let (delta, used) = read_varint(&bytes[idx..])?;
        idx += used;
        let (addr, used) = read_varint(&bytes[idx..])?;
        idx += used;
        let (value, used) = read_varint(&bytes[idx..])?;
        idx += used;

        prev_ts = prev_ts.saturating_add(delta);
        events.push(AerEvent {
            ts_us: prev_ts,
            addr: addr as u32,
            value: (value & 0xff) as u8,
        });
    }

    Ok(events)
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize), AerError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        let val = (b & 0x7f) as u64;
        result |= val << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(AerError::VarintOverflow);
        }
    }
    Err(AerError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip_preserves_events() {
        let events = vec![
            AerEvent {
                ts_us: 1002,
                addr: 0x10,
                value: 7,
            },
            AerEvent {
                ts_us: 1000,
                addr: 0x20,
                value: 9,
            },
            AerEvent {
                ts_us: 1010,
                addr: 0x30,
                value: 255,
            },
        ];
        let encoded = encode_events(&events);
        let decoded = decode_events(&encoded).expect("payload should decode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].ts_us, 1000);
        assert_eq!(decoded[1].ts_us, 1002);
        assert_eq!(decoded[2].ts_us, 1010);
        assert_eq!(decoded[2].value, 255);
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut payload = b"BAD!".to_vec();
        payload.extend_from_slice(&123u64.to_le_bytes());
        assert!(matches!(
            decode_events(&payload),
            Err(AerError::InvalidMagic)
        ));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        assert!(matches!(decode_events(&[]), Err(AerError::Truncated)));
        assert!(matches!(
            decode_events(b"AER1\x00\x00\x00\x00"),
            Err(AerError::Truncated)
        ));
    }

    #[test]
    fn decode_rejects_varint_overflow() {
        let mut payload = b"AER1".to_vec();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&[0x80; 10]);
        assert!(matches!(
            decode_events(&payload),
            Err(AerError::VarintOverflow)
        ));
    }
}

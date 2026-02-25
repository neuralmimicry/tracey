use thiserror::Error;

const MAGIC: &[u8; 4] = b"AER1";

#[derive(Clone, Debug)]
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

//! CF_INBOX_INDEX key encoding and decoding helpers.
//!
//! Key schema:
//!   `identity_id (16 bytes) || machine_id (16 bytes) || inverted_ts (8 bytes BE) || conversation_id (32 bytes)`
//!
//! Inverted timestamp = `u64::MAX - last_message_at_ms`. A forward RocksDB
//! prefix scan therefore yields entries newest-first without any in-memory sort.

use zero_crypto::aad::{IdentityId, MachineId};

use crate::dm::types::ConversationId;

const IDENTITY_LEN: usize = 16;
const MACHINE_LEN: usize = 16;
const TS_LEN: usize = 8;
const CONVERSATION_LEN: usize = 32;

/// Total key length: 16 + 16 + 8 + 32 = 72 bytes.
pub const KEY_LEN: usize = IDENTITY_LEN + MACHINE_LEN + TS_LEN + CONVERSATION_LEN;

/// Prefix length for owner scans: 16 + 16 = 32 bytes.
pub const PREFIX_LEN: usize = IDENTITY_LEN + MACHINE_LEN;

/// Encode the composite key for a single inbox entry.
///
/// The inverted timestamp (`u64::MAX - last_ts`) ensures a forward scan
/// returns newest entries first.
#[must_use]
pub fn encode_key(
    identity_id: &IdentityId,
    machine_id: &MachineId,
    last_ts: u64,
    conversation_id: &ConversationId,
) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let mut offset = 0;

    key[offset..offset + IDENTITY_LEN].copy_from_slice(&identity_id.0);
    offset += IDENTITY_LEN;

    key[offset..offset + MACHINE_LEN].copy_from_slice(&machine_id.0);
    offset += MACHINE_LEN;

    let inverted_ts = u64::MAX - last_ts;
    key[offset..offset + TS_LEN].copy_from_slice(&inverted_ts.to_be_bytes());
    offset += TS_LEN;

    key[offset..offset + CONVERSATION_LEN].copy_from_slice(&conversation_id.0);

    key
}

/// Build a prefix for scanning all conversations belonging to a given
/// (identity, machine) pair.
#[must_use]
pub fn owner_prefix(identity_id: &IdentityId, machine_id: &MachineId) -> [u8; PREFIX_LEN] {
    let mut prefix = [0u8; PREFIX_LEN];
    prefix[..IDENTITY_LEN].copy_from_slice(&identity_id.0);
    prefix[IDENTITY_LEN..].copy_from_slice(&machine_id.0);
    prefix
}

/// Decode a key back into its component parts.
///
/// Returns `None` if the slice length does not match [`KEY_LEN`].
pub fn decode_key(key: &[u8]) -> Option<(IdentityId, MachineId, u64, ConversationId)> {
    if key.len() != KEY_LEN {
        return None;
    }

    let mut id = [0u8; 16];
    id.copy_from_slice(&key[..IDENTITY_LEN]);

    let mut mid = [0u8; 16];
    mid.copy_from_slice(&key[IDENTITY_LEN..IDENTITY_LEN + MACHINE_LEN]);

    let ts_start = IDENTITY_LEN + MACHINE_LEN;
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&key[ts_start..ts_start + TS_LEN]);
    let inverted_ts = u64::from_be_bytes(ts_bytes);
    let last_ts = u64::MAX - inverted_ts;

    let cid_start = ts_start + TS_LEN;
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&key[cid_start..]);

    Some((IdentityId(id), MachineId(mid), last_ts, ConversationId(cid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity() -> IdentityId {
        IdentityId([1u8; 16])
    }
    fn make_machine() -> MachineId {
        MachineId([2u8; 16])
    }
    fn make_conv(seed: u8) -> ConversationId {
        let mut b = [0u8; 32];
        b[0] = seed;
        ConversationId(b)
    }

    #[test]
    fn round_trip_key_encoding() {
        let identity = make_identity();
        let machine = make_machine();
        let conv = make_conv(3);
        let ts: u64 = 1_700_000_000_000;

        let key = encode_key(&identity, &machine, ts, &conv);
        assert_eq!(key.len(), KEY_LEN);

        let (id2, mid2, ts2, cid2) = decode_key(&key).unwrap();
        assert_eq!(id2, identity);
        assert_eq!(mid2, machine);
        assert_eq!(ts2, ts);
        assert_eq!(cid2, conv);
    }

    #[test]
    fn decode_wrong_length_returns_none() {
        assert!(decode_key(&[0u8; 10]).is_none());
        assert!(decode_key(&[]).is_none());
    }

    #[test]
    fn owner_prefix_matches_key_start() {
        let identity = make_identity();
        let machine = make_machine();
        let conv = make_conv(9);

        let key = encode_key(&identity, &machine, 42_000, &conv);
        let prefix = owner_prefix(&identity, &machine);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn forward_scan_order_is_desc_by_timestamp() {
        // Keys with higher timestamps must sort BEFORE lower ones
        // because we store inverted_ts in big-endian.
        let identity = make_identity();
        let machine = make_machine();

        let newer = encode_key(&identity, &machine, 2_000, &make_conv(1));
        let older = encode_key(&identity, &machine, 1_000, &make_conv(2));

        // newer entry has smaller inverted_ts, so its key is lexicographically smaller
        assert!(
            newer < older,
            "newer key must sort before older key in a forward scan"
        );
    }

    #[test]
    fn inverted_ts_roundtrip_max_min() {
        let identity = make_identity();
        let machine = make_machine();
        let conv = make_conv(5);

        for &ts in &[0u64, 1, u64::MAX / 2, u64::MAX - 1] {
            let key = encode_key(&identity, &machine, ts, &conv);
            let (_, _, recovered, _) = decode_key(&key).unwrap();
            assert_eq!(recovered, ts);
        }
    }
}

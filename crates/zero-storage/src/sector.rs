//! Sector wire-format codec.
//!
//! Defines the canonical `Sector` struct and `SectorId` (UUIDv7 newtype),
//! plus postcard-based `encode_sector` / `decode_sector`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::StorageError;

/// Time-ordered sector identifier wrapping a UUIDv7.
///
/// Byte-level comparison preserves chronological ordering because UUIDv7
/// encodes the Unix-ms timestamp in the most-significant 48 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SectorId(pub [u8; 16]);

impl SectorId {
    pub fn new() -> Self {
        SectorId(Uuid::now_v7().into_bytes())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        SectorId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn as_uuid(&self) -> Uuid {
        Uuid::from_bytes(self.0)
    }
}

impl Default for SectorId {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialOrd for SectorId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SectorId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::fmt::Display for SectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_uuid())
    }
}

/// Canonical sector as stored on disk and transmitted on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sector {
    pub id: SectorId,
    pub kind: String,
    pub identity_id: String,
    pub machine_id: String,
    pub created_at: u64,
    pub payload: Vec<u8>,
    pub prev: Option<SectorId>,
}

/// Encode a `Sector` to its postcard wire format.
pub fn encode_sector(sector: &Sector) -> Result<Vec<u8>, StorageError> {
    postcard::to_stdvec(sector).map_err(StorageError::from)
}

/// Decode a `Sector` from its postcard wire format.
pub fn decode_sector(bytes: &[u8]) -> Result<Sector, StorageError> {
    postcard::from_bytes(bytes).map_err(StorageError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn make_sector() -> Sector {
        Sector {
            id: SectorId::new(),
            kind: "zero.chat.v1".to_string(),
            identity_id: "id-alice".to_string(),
            machine_id: "machine-01".to_string(),
            created_at: 1_700_000_000_000,
            payload: vec![1, 2, 3, 4],
            prev: None,
        }
    }

    #[test]
    fn round_trip_encode_decode() {
        let sector = make_sector();
        let bytes = encode_sector(&sector).expect("encode");
        let decoded = decode_sector(&bytes).expect("decode");
        assert_eq!(sector, decoded);
    }

    #[test]
    fn round_trip_with_prev() {
        let prev_id = SectorId::new();
        let sector = Sector {
            id: SectorId::new(),
            kind: "zero.chat.v1".to_string(),
            identity_id: "id-bob".to_string(),
            machine_id: "machine-02".to_string(),
            created_at: 1_700_000_001_000,
            payload: vec![10, 20],
            prev: Some(prev_id),
        };
        let bytes = encode_sector(&sector).expect("encode");
        let decoded = decode_sector(&bytes).expect("decode");
        assert_eq!(sector, decoded);
    }

    #[test]
    fn round_trip_empty_payload() {
        let sector = Sector {
            id: SectorId::new(),
            kind: String::new(),
            identity_id: String::new(),
            machine_id: String::new(),
            created_at: 0,
            payload: vec![],
            prev: None,
        };
        let bytes = encode_sector(&sector).expect("encode");
        let decoded = decode_sector(&bytes).expect("decode");
        assert_eq!(sector, decoded);
    }

    #[test]
    fn decode_garbage_returns_codec_error() {
        let result = decode_sector(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::Codec(_) => {}
            other => panic!("expected Codec error, got: {other}"),
        }
    }

    #[test]
    fn sector_id_ordering_newer_sorts_after_older() {
        let first = SectorId::new();
        thread::sleep(Duration::from_millis(2));
        let second = SectorId::new();
        assert!(
            second > first,
            "newer SectorId should sort after older: first={first}, second={second}"
        );
    }

    #[test]
    fn sector_id_ordering_across_many() {
        let mut ids: Vec<SectorId> = Vec::with_capacity(100);
        for _ in 0..100 {
            ids.push(SectorId::new());
        }
        for window in ids.windows(2) {
            assert!(
                window[1] >= window[0],
                "IDs must be monotonically non-decreasing"
            );
        }
    }

    #[test]
    fn sector_id_display() {
        let id = SectorId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36, "UUID display should be 36 chars with hyphens");
    }
}

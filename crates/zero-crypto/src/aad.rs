//! Canonical CBOR-encoded AAD (Additional Authenticated Data) construction.
//!
//! Fields are serialized as a CBOR map with keys in lexicographic order per
//! RFC 8949 section 4.2.1 (deterministic encoding). The fixed key order is:
//!
//! 1. `"epoch"`
//! 2. `"prev_sector_id"`
//! 3. `"schema_tag"`
//! 4. `"sector_id"`
//! 5. `"sender_identity"`
//! 6. `"sender_machine"`
//!
//! Reordering or omitting fields produces different bytes, which is validated
//! by the KAT vectors in `tests/vectors/aad_kat.json`.

use ciborium::Value;

use crate::error::CryptoError;

// ── Newtypes ──────────────────────────────────────────────────────────────────

/// Discriminates the sector schema version / type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchemaTag(pub u32);

/// 16-byte opaque sector identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SectorId(pub [u8; 16]);

/// 16-byte opaque identity identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityId(pub [u8; 16]);

/// 16-byte opaque machine identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MachineId(pub [u8; 16]);

/// Logical clock / sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Epoch(pub u64);

// ── MessageAad ────────────────────────────────────────────────────────────────

/// Canonical CBOR-encoded AAD bound into every AEAD ciphertext.
///
/// All fields are included; `prev_sector_id` serialises as CBOR `null` when
/// absent, preserving a fixed 6-entry map structure for deterministic encoding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MessageAad {
    pub schema_tag: SchemaTag,
    pub sector_id: SectorId,
    pub sender_identity: IdentityId,
    pub sender_machine: MachineId,
    pub epoch: Epoch,
    pub prev_sector_id: Option<SectorId>,
}

impl MessageAad {
    /// CBOR-encode deterministically (canonical map key ordering).
    ///
    /// Keys are emitted in the fixed lexicographic order listed in the module
    /// doc. The resulting bytes are byte-identical across runs and platforms.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let prev = match &self.prev_sector_id {
            Some(sid) => Value::Bytes(sid.0.to_vec()),
            None => Value::Null,
        };

        // Fixed lexicographic key order: epoch, prev_sector_id, schema_tag,
        // sector_id, sender_identity, sender_machine.
        let map = Value::Map(vec![
            (
                Value::Text("epoch".to_string()),
                Value::Integer(ciborium::value::Integer::from(self.epoch.0)),
            ),
            (Value::Text("prev_sector_id".to_string()), prev),
            (
                Value::Text("schema_tag".to_string()),
                Value::Integer(ciborium::value::Integer::from(self.schema_tag.0)),
            ),
            (
                Value::Text("sector_id".to_string()),
                Value::Bytes(self.sector_id.0.to_vec()),
            ),
            (
                Value::Text("sender_identity".to_string()),
                Value::Bytes(self.sender_identity.0.to_vec()),
            ),
            (
                Value::Text("sender_machine".to_string()),
                Value::Bytes(self.sender_machine.0.to_vec()),
            ),
        ]);

        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out)
            .map_err(|e| CryptoError::AadEncoding(e.to_string()))?;
        Ok(out)
    }

    /// Decode CBOR bytes produced by [`MessageAad::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::AadEncoding(e.to_string()))?;

        let entries = match value {
            Value::Map(m) => m,
            other => {
                return Err(CryptoError::AadEncoding(format!(
                    "expected CBOR map, got {:?}",
                    other
                )))
            }
        };

        let mut epoch: Option<u64> = None;
        let mut prev_sector_id: Option<Option<SectorId>> = None;
        let mut schema_tag: Option<u32> = None;
        let mut sector_id: Option<SectorId> = None;
        let mut sender_identity: Option<IdentityId> = None;
        let mut sender_machine: Option<MachineId> = None;

        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "epoch" => {
                    epoch = Some(extract_u64(&v, "epoch")?);
                }
                "prev_sector_id" => {
                    prev_sector_id = Some(match v {
                        Value::Null => None,
                        Value::Bytes(b) => Some(SectorId(bytes_to_16(&b, "prev_sector_id")?)),
                        other => {
                            return Err(CryptoError::AadEncoding(format!(
                                "prev_sector_id: expected bytes or null, got {:?}",
                                other
                            )))
                        }
                    });
                }
                "schema_tag" => {
                    schema_tag = Some(extract_u64(&v, "schema_tag")? as u32);
                }
                "sector_id" => {
                    sector_id = Some(SectorId(extract_bytes16(&v, "sector_id")?));
                }
                "sender_identity" => {
                    sender_identity = Some(IdentityId(extract_bytes16(&v, "sender_identity")?));
                }
                "sender_machine" => {
                    sender_machine = Some(MachineId(extract_bytes16(&v, "sender_machine")?));
                }
                _ => {}
            }
        }

        Ok(MessageAad {
            schema_tag: SchemaTag(
                schema_tag.ok_or_else(|| CryptoError::AadEncoding("missing schema_tag".into()))?,
            ),
            sector_id: sector_id
                .ok_or_else(|| CryptoError::AadEncoding("missing sector_id".into()))?,
            sender_identity: sender_identity
                .ok_or_else(|| CryptoError::AadEncoding("missing sender_identity".into()))?,
            sender_machine: sender_machine
                .ok_or_else(|| CryptoError::AadEncoding("missing sender_machine".into()))?,
            epoch: Epoch(epoch.ok_or_else(|| CryptoError::AadEncoding("missing epoch".into()))?),
            prev_sector_id: prev_sector_id
                .ok_or_else(|| CryptoError::AadEncoding("missing prev_sector_id".into()))?,
        })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn extract_u64(v: &Value, field: &str) -> Result<u64, CryptoError> {
    match v {
        Value::Integer(i) => u64::try_from(*i)
            .map_err(|_| CryptoError::AadEncoding(format!("{field}: integer out of u64 range"))),
        other => Err(CryptoError::AadEncoding(format!(
            "{field}: expected integer, got {:?}",
            other
        ))),
    }
}

fn extract_bytes16(v: &Value, field: &str) -> Result<[u8; 16], CryptoError> {
    match v {
        Value::Bytes(b) => bytes_to_16(b, field),
        other => Err(CryptoError::AadEncoding(format!(
            "{field}: expected bytes, got {:?}",
            other
        ))),
    }
}

fn bytes_to_16(b: &[u8], field: &str) -> Result<[u8; 16], CryptoError> {
    b.try_into().map_err(|_| {
        CryptoError::AadEncoding(format!(
            "{field}: expected exactly 16 bytes, got {}",
            b.len()
        ))
    })
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_aad() -> MessageAad {
        MessageAad {
            schema_tag: SchemaTag(1),
            sector_id: SectorId([0x01; 16]),
            sender_identity: IdentityId([0x02; 16]),
            sender_machine: MachineId([0x03; 16]),
            epoch: Epoch(42),
            prev_sector_id: None,
        }
    }

    #[test]
    fn round_trip_encode_decode() {
        let aad = sample_aad();
        let encoded = aad.encode().unwrap();
        let decoded = MessageAad::decode(&encoded).unwrap();
        assert_eq!(aad, decoded);
    }

    #[test]
    fn encode_is_deterministic() {
        let aad = sample_aad();
        let a = aad.encode().unwrap();
        let b = aad.encode().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn round_trip_byte_identical() {
        let aad = sample_aad();
        let encoded1 = aad.encode().unwrap();
        let decoded = MessageAad::decode(&encoded1).unwrap();
        let encoded2 = decoded.encode().unwrap();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn with_prev_sector_id() {
        let mut aad = sample_aad();
        aad.prev_sector_id = Some(SectorId([0xdd; 16]));
        let encoded = aad.encode().unwrap();
        let decoded = MessageAad::decode(&encoded).unwrap();
        assert_eq!(aad, decoded);
        assert_eq!(decoded.prev_sector_id, Some(SectorId([0xdd; 16])));
    }

    #[test]
    fn different_field_values_change_bytes() {
        let aad1 = sample_aad();
        let mut aad2 = sample_aad();
        aad2.epoch = Epoch(99);
        assert_ne!(aad1.encode().unwrap(), aad2.encode().unwrap());
    }

    #[test]
    fn adding_prev_sector_id_changes_bytes() {
        let aad1 = sample_aad();
        let mut aad2 = sample_aad();
        aad2.prev_sector_id = Some(SectorId([0xab; 16]));
        assert_ne!(aad1.encode().unwrap(), aad2.encode().unwrap());
    }
}

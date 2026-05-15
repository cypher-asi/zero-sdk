use std::path::Path;

use proptest::prelude::*;
use serde_json::Value;
use zero_crypto::aad::{Epoch, IdentityId, MachineId, MessageAad, SchemaTag, SectorId};

fn load_kat() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("aad_kat.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {}", path.display(), e));
    serde_json::from_str(&data).expect("invalid KAT JSON")
}

fn build_aad_from_kat(v: &Value) -> MessageAad {
    let schema_tag = v["schema_tag"].as_u64().unwrap();
    let epoch = v["epoch"].as_u64().unwrap();

    let sector_id_hex = v["sector_id_hex"].as_str().unwrap();
    let sender_identity_hex = v["sender_identity_hex"].as_str().unwrap();
    let sender_machine_hex = v["sender_machine_hex"].as_str().unwrap();

    let mut sector_id = [0u8; 16];
    hex::decode_to_slice(sector_id_hex, &mut sector_id).unwrap();
    let mut sender_identity = [0u8; 16];
    hex::decode_to_slice(sender_identity_hex, &mut sender_identity).unwrap();
    let mut sender_machine = [0u8; 16];
    hex::decode_to_slice(sender_machine_hex, &mut sender_machine).unwrap();

    let prev_sector_id = if v["prev_sector_id_hex"].is_null() {
        None
    } else {
        let h = v["prev_sector_id_hex"].as_str().unwrap();
        let bytes = hex::decode(h).unwrap();
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes);
        Some(SectorId(buf))
    };

    MessageAad {
        schema_tag: SchemaTag(schema_tag as u32),
        sector_id: SectorId(sector_id),
        sender_identity: IdentityId(sender_identity),
        sender_machine: MachineId(sender_machine),
        epoch: Epoch(epoch),
        prev_sector_id,
    }
}

#[test]
fn kat_no_prev_sector_id() {
    let kat = load_kat();
    let vector = &kat["vectors"][0];
    let aad = build_aad_from_kat(&vector["input"]);
    let expected_hex = vector["expected_cbor_hex"].as_str().unwrap();

    let encoded = aad.encode().unwrap();
    assert_eq!(
        hex::encode(&encoded),
        expected_hex,
        "KAT mismatch for vector without prev_sector_id"
    );
}

#[test]
fn kat_with_prev_sector_id() {
    let kat = load_kat();
    let vector = &kat["vectors"][1];
    let aad = build_aad_from_kat(&vector["input"]);
    let expected_hex = vector["expected_cbor_hex"].as_str().unwrap();

    let encoded = aad.encode().unwrap();
    assert_eq!(
        hex::encode(&encoded),
        expected_hex,
        "KAT mismatch for vector with prev_sector_id"
    );
}

#[test]
fn round_trip_byte_identical() {
    let kat = load_kat();
    for vector in kat["vectors"].as_array().unwrap() {
        let aad = build_aad_from_kat(&vector["input"]);
        let encoded1 = aad.encode().unwrap();
        let decoded = MessageAad::decode(&encoded1).unwrap();
        let encoded2 = decoded.encode().unwrap();
        assert_eq!(encoded1, encoded2, "round-trip produced different bytes");
    }
}

#[test]
fn reordering_fields_changes_bytes() {
    let aad = MessageAad {
        schema_tag: SchemaTag(1),
        sector_id: SectorId([0x01; 16]),
        sender_identity: IdentityId([0x02; 16]),
        sender_machine: MachineId([0x03; 16]),
        epoch: Epoch(42),
        prev_sector_id: None,
    };
    let canonical = aad.encode().unwrap();

    // Manually build CBOR with keys in reverse-alphabetical order.
    // Canonical order: epoch, prev_sector_id, schema_tag, sector_id,
    //                  sender_identity, sender_machine
    // Reversed order:  sender_machine, sender_identity, sector_id,
    //                  schema_tag, prev_sector_id, epoch
    let mut reversed_buf = Vec::new();
    let reversed_map: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            ciborium::Value::Text("sender_machine".into()),
            ciborium::Value::Bytes(vec![0x03; 16]),
        ),
        (
            ciborium::Value::Text("sender_identity".into()),
            ciborium::Value::Bytes(vec![0x02; 16]),
        ),
        (
            ciborium::Value::Text("sector_id".into()),
            ciborium::Value::Bytes(vec![0x01; 16]),
        ),
        (
            ciborium::Value::Text("schema_tag".into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Text("prev_sector_id".into()),
            ciborium::Value::Null,
        ),
        (
            ciborium::Value::Text("epoch".into()),
            ciborium::Value::Integer(42.into()),
        ),
    ];
    ciborium::into_writer(&ciborium::Value::Map(reversed_map), &mut reversed_buf).unwrap();

    assert_ne!(
        canonical, reversed_buf,
        "reordering fields must produce different CBOR bytes"
    );

    // Both should decode to equivalent AAD values
    let decoded_canonical = MessageAad::decode(&canonical).unwrap();
    let decoded_reversed = MessageAad::decode(&reversed_buf).unwrap();
    assert_eq!(decoded_canonical.schema_tag, decoded_reversed.schema_tag);
    assert_eq!(decoded_canonical.sector_id, decoded_reversed.sector_id);
    assert_eq!(
        decoded_canonical.sender_identity,
        decoded_reversed.sender_identity
    );
    assert_eq!(
        decoded_canonical.sender_machine,
        decoded_reversed.sender_machine
    );
    assert_eq!(decoded_canonical.epoch, decoded_reversed.epoch);
}

#[test]
fn different_values_change_bytes() {
    let aad1 = MessageAad {
        schema_tag: SchemaTag(1),
        sector_id: SectorId([0x01; 16]),
        sender_identity: IdentityId([0x02; 16]),
        sender_machine: MachineId([0x03; 16]),
        epoch: Epoch(42),
        prev_sector_id: None,
    };
    let aad2 = MessageAad {
        schema_tag: SchemaTag(99),
        sector_id: SectorId([0x01; 16]),
        sender_identity: IdentityId([0x02; 16]),
        sender_machine: MachineId([0x03; 16]),
        epoch: Epoch(42),
        prev_sector_id: None,
    };
    assert_ne!(
        aad1.encode().unwrap(),
        aad2.encode().unwrap(),
        "different schema_tag must produce different bytes"
    );
}

#[test]
fn adding_prev_sector_id_changes_bytes() {
    let aad_none = MessageAad {
        schema_tag: SchemaTag(1),
        sector_id: SectorId([0x01; 16]),
        sender_identity: IdentityId([0x02; 16]),
        sender_machine: MachineId([0x03; 16]),
        epoch: Epoch(42),
        prev_sector_id: None,
    };
    let aad_some = MessageAad {
        schema_tag: SchemaTag(1),
        sector_id: SectorId([0x01; 16]),
        sender_identity: IdentityId([0x02; 16]),
        sender_machine: MachineId([0x03; 16]),
        epoch: Epoch(42),
        prev_sector_id: Some(SectorId([0xFF; 16])),
    };
    assert_ne!(
        aad_none.encode().unwrap(),
        aad_some.encode().unwrap(),
        "adding prev_sector_id must change output bytes"
    );
}

proptest! {
    #[test]
    fn proptest_aad_round_trip(
        schema_tag in 0u32..=u32::MAX,
        sector_id in proptest::collection::vec(any::<u8>(), 16..=16),
        sender_identity in proptest::collection::vec(any::<u8>(), 16..=16),
        sender_machine in proptest::collection::vec(any::<u8>(), 16..=16),
        epoch in 0u64..=u64::MAX,
        use_prev in any::<bool>(),
        prev_bytes in proptest::collection::vec(any::<u8>(), 16..=16),
    ) {
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&sector_id);
        let mut iid = [0u8; 16];
        iid.copy_from_slice(&sender_identity);
        let mut mid = [0u8; 16];
        mid.copy_from_slice(&sender_machine);

        let prev = if use_prev {
            let mut p = [0u8; 16];
            p.copy_from_slice(&prev_bytes);
            Some(SectorId(p))
        } else {
            None
        };

        let aad = MessageAad {
            schema_tag: SchemaTag(schema_tag),
            sector_id: SectorId(sid),
            sender_identity: IdentityId(iid),
            sender_machine: MachineId(mid),
            epoch: Epoch(epoch),
            prev_sector_id: prev,
        };

        let encoded1 = aad.encode().unwrap();
        let decoded = MessageAad::decode(&encoded1).unwrap();
        let encoded2 = decoded.encode().unwrap();
        prop_assert_eq!(&encoded1, &encoded2, "encode-decode-encode must be byte-identical");
    }
}

//! KAT (Known Answer Test) vectors for the sector postcard wire format.
//!
//! These tests lock the postcard encoding so that any change to `Sector`
//! field order, naming, or types is detected immediately.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zero_storage::{decode_sector, encode_sector, Sector, SectorId};

#[derive(Debug, Serialize, Deserialize)]
struct KatVector {
    name: String,
    sector_id_hex: String,
    kind: String,
    identity_id: String,
    machine_id: String,
    created_at: u64,
    payload_hex: String,
    prev_hex: Option<String>,
    encoded_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KatFile {
    vectors: Vec<KatVector>,
}

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kat")
}

fn build_sector(v: &KatVector) -> Sector {
    let id_bytes: [u8; 16] = hex::decode(&v.sector_id_hex)
        .expect("bad sector_id hex")
        .try_into()
        .expect("sector_id must be 16 bytes");
    let prev = v.prev_hex.as_ref().map(|h| {
        let bytes: [u8; 16] = hex::decode(h)
            .expect("bad prev hex")
            .try_into()
            .expect("prev must be 16 bytes");
        SectorId::from_bytes(bytes)
    });
    Sector {
        id: SectorId::from_bytes(id_bytes),
        kind: v.kind.clone(),
        identity_id: v.identity_id.clone(),
        machine_id: v.machine_id.clone(),
        created_at: v.created_at,
        payload: hex::decode(&v.payload_hex).expect("bad payload hex"),
        prev,
    }
}

fn make_test_vectors() -> Vec<KatVector> {
    #[allow(clippy::type_complexity)]
    let vectors_input: Vec<(
        &str,
        [u8; 16],
        &str,
        &str,
        &str,
        u64,
        Vec<u8>,
        Option<[u8; 16]>,
    )> = vec![
        (
            "minimal - empty payload, no prev",
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "zero.chat.v1",
            "alice",
            "m1",
            1000,
            vec![],
            None,
        ),
        (
            "with payload and prev",
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            "zero.file.v1",
            "bob",
            "desktop",
            999_999,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ),
        (
            "large created_at value",
            [
                0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x03,
            ],
            "zero.contact.v1",
            "carol",
            "phone",
            1_700_000_000_000,
            vec![0x01, 0x02, 0x03],
            None,
        ),
    ];

    vectors_input
        .into_iter()
        .map(|(name, id, kind, identity, machine, ts, payload, prev)| {
            let sector = Sector {
                id: SectorId::from_bytes(id),
                kind: kind.to_string(),
                identity_id: identity.to_string(),
                machine_id: machine.to_string(),
                created_at: ts,
                payload: payload.clone(),
                prev: prev.map(SectorId::from_bytes),
            };
            let encoded = encode_sector(&sector).expect("encoding must succeed");
            KatVector {
                name: name.to_string(),
                sector_id_hex: hex::encode(id),
                kind: kind.to_string(),
                identity_id: identity.to_string(),
                machine_id: machine.to_string(),
                created_at: ts,
                payload_hex: hex::encode(&payload),
                prev_hex: prev.map(hex::encode),
                encoded_hex: hex::encode(&encoded),
            }
        })
        .collect()
}

/// Generates the KAT vector file if it does not exist.
/// This is called once to bootstrap; afterwards the file is committed.
fn ensure_kat_file() -> KatFile {
    let path = kat_dir().join("sector_kat.json");
    if path.exists() {
        let contents = std::fs::read_to_string(&path).expect("failed to read sector_kat.json");
        let loaded: KatFile =
            serde_json::from_str(&contents).expect("failed to parse sector_kat.json");
        if !loaded.vectors.is_empty() {
            return loaded;
        }
    }
    let kat = KatFile {
        vectors: make_test_vectors(),
    };
    std::fs::create_dir_all(kat_dir()).expect("failed to create kat dir");
    let json = serde_json::to_string_pretty(&kat).expect("failed to serialize");
    std::fs::write(&path, &json).expect("failed to write sector_kat.json");
    kat
}

#[test]
fn kat_encode_matches_stored_vectors() {
    let kat = ensure_kat_file();
    for v in &kat.vectors {
        let sector = build_sector(v);
        let encoded = encode_sector(&sector).expect("encoding must succeed");
        let actual_hex = hex::encode(&encoded);
        assert_eq!(
            actual_hex, v.encoded_hex,
            "KAT encode mismatch for vector {:?}: got {}, expected {}",
            v.name, actual_hex, v.encoded_hex
        );
    }
}

#[test]
fn kat_decode_matches_stored_vectors() {
    let kat = ensure_kat_file();
    for v in &kat.vectors {
        let expected = build_sector(v);
        let raw = hex::decode(&v.encoded_hex).expect("bad encoded_hex");
        let decoded = decode_sector(&raw).expect("decoding must succeed");
        assert_eq!(decoded.id, expected.id, "id mismatch for {:?}", v.name);
        assert_eq!(
            decoded.kind, expected.kind,
            "kind mismatch for {:?}",
            v.name
        );
        assert_eq!(
            decoded.identity_id, expected.identity_id,
            "identity_id mismatch for {:?}",
            v.name
        );
        assert_eq!(
            decoded.machine_id, expected.machine_id,
            "machine_id mismatch for {:?}",
            v.name
        );
        assert_eq!(
            decoded.created_at, expected.created_at,
            "created_at mismatch for {:?}",
            v.name
        );
        assert_eq!(
            decoded.payload, expected.payload,
            "payload mismatch for {:?}",
            v.name
        );
        assert_eq!(
            decoded.prev, expected.prev,
            "prev mismatch for {:?}",
            v.name
        );
    }
}

#[test]
fn kat_round_trip_all_vectors() {
    let kat = ensure_kat_file();
    for v in &kat.vectors {
        let sector = build_sector(v);
        let encoded = encode_sector(&sector).expect("encode");
        let decoded = decode_sector(&encoded).expect("decode");
        assert_eq!(decoded.id, sector.id, "round-trip id for {:?}", v.name);
        assert_eq!(
            decoded.kind, sector.kind,
            "round-trip kind for {:?}",
            v.name
        );
        assert_eq!(
            decoded.payload, sector.payload,
            "round-trip payload for {:?}",
            v.name
        );
        assert_eq!(
            decoded.prev, sector.prev,
            "round-trip prev for {:?}",
            v.name
        );
    }
}

#[test]
fn kat_lock_toml_is_valid() {
    let path = kat_dir().join("kat_lock.toml");
    let contents = std::fs::read_to_string(&path).expect("kat_lock.toml must exist");
    let table: toml::Table = contents.parse().expect("kat_lock.toml must be valid TOML");
    assert!(
        table.contains_key("codec"),
        "kat_lock.toml must have a [codec] section"
    );
    let codec = table["codec"].as_table().expect("[codec] must be a table");
    assert_eq!(
        codec.get("format").and_then(|v| v.as_str()),
        Some("postcard"),
        "codec.format must be 'postcard'"
    );
}

//! RocksDB handle and column-family management.

use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, Options, DB};

use crate::error::StorageError;
use crate::sector::{decode_sector, encode_sector, Sector, SectorId};

/// Key-value pair list returned by prefix scans.
pub type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Build a composite key: `[identity_id_len_u16_be][identity_id][machine_id_len_u16_be][machine_id][sector_id_16_bytes]`.
fn make_sector_key(identity_id: &str, machine_id: &str, sector_id: &SectorId) -> Vec<u8> {
    let ilen = identity_id.len() as u16;
    let mlen = machine_id.len() as u16;
    let mut key = Vec::with_capacity(2 + identity_id.len() + 2 + machine_id.len() + 16);
    key.extend_from_slice(&ilen.to_be_bytes());
    key.extend_from_slice(identity_id.as_bytes());
    key.extend_from_slice(&mlen.to_be_bytes());
    key.extend_from_slice(machine_id.as_bytes());
    key.extend_from_slice(sector_id.as_bytes());
    key
}

/// Build the prefix for all sectors belonging to `(identity_id, machine_id)`.
fn make_scope_prefix(identity_id: &str, machine_id: &str) -> Vec<u8> {
    let ilen = identity_id.len() as u16;
    let mlen = machine_id.len() as u16;
    let mut prefix = Vec::with_capacity(2 + identity_id.len() + 2 + machine_id.len());
    prefix.extend_from_slice(&ilen.to_be_bytes());
    prefix.extend_from_slice(identity_id.as_bytes());
    prefix.extend_from_slice(&mlen.to_be_bytes());
    prefix.extend_from_slice(machine_id.as_bytes());
    prefix
}

pub const CF_SECTORS: &str = "cf_sectors";
pub const CF_CHAINS: &str = "cf_chains";
pub const CF_INBOX_INDEX: &str = "cf_inbox_index";
pub const CF_CONTACTS: &str = "cf_contacts";
pub const CF_GROUPS: &str = "cf_groups";
pub const CF_OUTBOX: &str = "cf_outbox";
pub const CF_META: &str = "cf_meta";

const ALL_CFS: [&str; 7] = [
    CF_SECTORS,
    CF_CHAINS,
    CF_INBOX_INDEX,
    CF_CONTACTS,
    CF_GROUPS,
    CF_OUTBOX,
    CF_META,
];

/// RocksDB-backed storage with pre-defined column families.
pub struct ZeroDb {
    db: DB,
}

impl ZeroDb {
    /// Open (or create) a RocksDB database at `path` with all column families.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;

        Ok(Self { db })
    }

    /// Return a reference to the underlying RocksDB instance.
    pub fn inner(&self) -> &DB {
        &self.db
    }

    /// Look up a column family handle, returning `StorageError::MissingColumnFamily`
    /// if the name is not known.
    pub fn cf_handle(&self, name: &'static str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or(StorageError::MissingColumnFamily(name))
    }

    /// Write a key-value pair into the named column family.
    pub fn put_raw(&self, cf: &'static str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let handle = self.cf_handle(cf)?;
        self.db.put_cf(handle, key, value)?;
        Ok(())
    }

    /// Read a value from the named column family.
    pub fn get_raw(&self, cf: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let handle = self.cf_handle(cf)?;
        let val = self.db.get_cf(handle, key)?;
        Ok(val)
    }

    /// Delete a key from the named column family.
    pub fn delete_raw(&self, cf: &'static str, key: &[u8]) -> Result<(), StorageError> {
        let handle = self.cf_handle(cf)?;
        self.db.delete_cf(handle, key)?;
        Ok(())
    }

    /// Prefix scan: return all `(key, value)` pairs whose key starts with
    /// `prefix` in the given column family.
    pub fn prefix_scan_raw(
        &self,
        cf: &'static str,
        prefix: &[u8],
    ) -> Result<KvPairs, StorageError> {
        let handle = self.cf_handle(cf)?;
        let iter = self.db.prefix_iterator_cf(handle, prefix);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item?;
            if !k.starts_with(prefix) {
                break;
            }
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    /// Store a sector, keyed by `(identity_id, machine_id, sector_id)`.
    pub fn put_sector(&self, sector: &Sector) -> Result<(), StorageError> {
        let key = make_sector_key(&sector.identity_id, &sector.machine_id, &sector.id);
        let value = encode_sector(sector)?;
        let handle = self.cf_handle(CF_SECTORS)?;
        self.db.put_cf(handle, &key, &value)?;
        Ok(())
    }

    /// Retrieve a sector by its scoped key.
    /// Returns `None` if the key does not exist (including wrong scope).
    pub fn get_sector(
        &self,
        identity_id: &str,
        machine_id: &str,
        sector_id: &SectorId,
    ) -> Result<Option<Sector>, StorageError> {
        let key = make_sector_key(identity_id, machine_id, sector_id);
        let handle = self.cf_handle(CF_SECTORS)?;
        match self.db.get_cf(handle, &key)? {
            Some(bytes) => Ok(Some(decode_sector(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Delete a sector by its scoped key.
    pub fn delete_sector(
        &self,
        identity_id: &str,
        machine_id: &str,
        sector_id: &SectorId,
    ) -> Result<(), StorageError> {
        let key = make_sector_key(identity_id, machine_id, sector_id);
        let handle = self.cf_handle(CF_SECTORS)?;
        self.db.delete_cf(handle, &key)?;
        Ok(())
    }

    /// Return all sectors under `(identity_id, machine_id)`, ordered by
    /// `SectorId` ascending (chronological, since UUIDv7 sorts by time).
    pub fn iter_chain(
        &self,
        identity_id: &str,
        machine_id: &str,
    ) -> Result<Vec<Sector>, StorageError> {
        let prefix = make_scope_prefix(identity_id, machine_id);
        let handle = self.cf_handle(CF_SECTORS)?;
        let iter = self.db.prefix_iterator_cf(handle, &prefix);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item?;
            if !k.starts_with(&prefix) {
                break;
            }
            results.push(decode_sector(&v)?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_creates_all_seven_cfs() {
        let tmp = TempDir::new().unwrap();
        let db = ZeroDb::open(tmp.path()).unwrap();

        for cf_name in &ALL_CFS {
            assert!(
                db.db.cf_handle(cf_name).is_some(),
                "column family {cf_name} should exist"
            );
        }
    }

    #[test]
    fn open_lists_exactly_seven_custom_cfs() {
        let tmp = TempDir::new().unwrap();
        let _db = ZeroDb::open(tmp.path()).unwrap();
        drop(_db);

        let listed = DB::list_cf(&Options::default(), tmp.path()).unwrap();
        // RocksDB always includes the "default" CF, so we expect 7 + 1 = 8.
        assert_eq!(
            listed.len(),
            8,
            "expected 7 custom CFs + default, got: {listed:?}"
        );

        for cf_name in &ALL_CFS {
            assert!(
                listed.contains(&cf_name.to_string()),
                "listed CFs should contain {cf_name}"
            );
        }
    }

    #[test]
    fn reopen_existing_db_loads_all_cfs() {
        let tmp = TempDir::new().unwrap();

        {
            let db = ZeroDb::open(tmp.path()).unwrap();
            db.put_raw(CF_SECTORS, b"test_key", b"test_val").unwrap();
        }

        let db2 = ZeroDb::open(tmp.path()).unwrap();
        let val = db2.get_raw(CF_SECTORS, b"test_key").unwrap();
        assert_eq!(val.as_deref(), Some(b"test_val".as_slice()));
    }

    #[test]
    fn put_raw_unknown_cf_returns_error() {
        let tmp = TempDir::new().unwrap();
        let db = ZeroDb::open(tmp.path()).unwrap();

        let result = db.put_raw("nonexistent_cf", b"k", b"v");
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::MissingColumnFamily(name) => {
                assert_eq!(name, "nonexistent_cf");
            }
            other => panic!("expected MissingColumnFamily, got: {other}"),
        }
    }

    #[test]
    fn get_raw_missing_key_returns_none() {
        let tmp = TempDir::new().unwrap();
        let db = ZeroDb::open(tmp.path()).unwrap();

        let val = db.get_raw(CF_META, b"no_such_key").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn delete_raw_nonexistent_key_succeeds() {
        let tmp = TempDir::new().unwrap();
        let db = ZeroDb::open(tmp.path()).unwrap();

        db.delete_raw(CF_OUTBOX, b"nothing").unwrap();
    }
}

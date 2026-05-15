use std::sync::Arc;

use zero_crypto::aad::IdentityId;
use zero_storage::db::ZeroDb;

use super::types::{Contact, ContactError};

const CF_CONTACTS: &str = "cf_contacts";

fn make_key(owner: &IdentityId, contact: &IdentityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&owner.0);
    key.extend_from_slice(&contact.0);
    key
}

fn owner_prefix(owner: &IdentityId) -> Vec<u8> {
    owner.0.to_vec()
}

pub struct ContactStore {
    db: Arc<ZeroDb>,
    owner: IdentityId,
}

impl ContactStore {
    pub fn new(db: Arc<ZeroDb>, owner: IdentityId) -> Self {
        Self { db, owner }
    }

    pub fn add_contact(&self, contact: Contact) -> Result<(), ContactError> {
        if contact.label.len() > 64 {
            return Err(ContactError::LabelTooLong {
                len: contact.label.len(),
            });
        }
        let key = make_key(&self.owner, &contact.identity_id);
        let value =
            postcard::to_stdvec(&contact).map_err(|e| ContactError::Codec(e.to_string()))?;
        self.db
            .put_raw(CF_CONTACTS, &key, &value)
            .map_err(ContactError::Storage)
    }

    pub fn get_contact(&self, id: &IdentityId) -> Result<Option<Contact>, ContactError> {
        let key = make_key(&self.owner, id);
        match self.db.get_raw(CF_CONTACTS, &key) {
            Ok(Some(bytes)) => {
                let contact: Contact =
                    postcard::from_bytes(&bytes).map_err(|e| ContactError::Codec(e.to_string()))?;
                Ok(Some(contact))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ContactError::Storage(e)),
        }
    }

    pub fn remove_contact(&self, id: &IdentityId) -> Result<(), ContactError> {
        let key = make_key(&self.owner, id);
        self.db
            .delete_raw(CF_CONTACTS, &key)
            .map_err(ContactError::Storage)
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>, ContactError> {
        let prefix = owner_prefix(&self.owner);
        let cf = self
            .db
            .cf_handle(CF_CONTACTS)
            .map_err(ContactError::Storage)?;
        let iter = self.db.inner().prefix_iterator_cf(cf, &prefix);
        let mut contacts = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ContactError::Codec(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            let contact: Contact =
                postcard::from_bytes(&value).map_err(|e| ContactError::Codec(e.to_string()))?;
            contacts.push(contact);
        }
        Ok(contacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (Arc<ZeroDb>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = ZeroDb::open(dir.path()).unwrap();
        (Arc::new(db), dir)
    }

    fn make_contact(id_byte: u8, label: &str) -> Contact {
        Contact {
            identity_id: IdentityId([id_byte; 16]),
            machine_keys: Vec::new(),
            last_seen_epoch: None,
            added_at_ms: 1_000_000,
            label: label.to_string(),
        }
    }

    #[test]
    fn add_and_get_round_trip() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xAA; 16]);
        let store = ContactStore::new(db, owner);
        let contact = make_contact(1, "Alice");
        store.add_contact(contact.clone()).unwrap();
        let retrieved = store.get_contact(&IdentityId([1; 16])).unwrap();
        assert_eq!(retrieved, Some(contact));
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xAA; 16]);
        let store = ContactStore::new(db, owner);
        let result = store.get_contact(&IdentityId([99; 16])).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn remove_then_get_returns_none() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xAA; 16]);
        let store = ContactStore::new(db, owner);
        let contact = make_contact(2, "Bob");
        store.add_contact(contact).unwrap();
        store.remove_contact(&IdentityId([2; 16])).unwrap();
        let result = store.get_contact(&IdentityId([2; 16])).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn list_contacts_empty() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xBB; 16]);
        let store = ContactStore::new(db, owner);
        let list = store.list_contacts().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_contacts_multiple() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xCC; 16]);
        let store = ContactStore::new(db, owner);
        for i in 0..5u8 {
            let c = make_contact(i, &format!("Contact-{i}"));
            store.add_contact(c).unwrap();
        }
        let list = store.list_contacts().unwrap();
        assert_eq!(list.len(), 5);
    }

    #[test]
    fn uniqueness_on_identity_id() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xDD; 16]);
        let store = ContactStore::new(db, owner);
        let c1 = make_contact(1, "First");
        let c2 = make_contact(1, "Second");
        store.add_contact(c1).unwrap();
        store.add_contact(c2).unwrap();
        let retrieved = store.get_contact(&IdentityId([1; 16])).unwrap().unwrap();
        assert_eq!(retrieved.label, "Second");
        let list = store.list_contacts().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn scoping_respected() {
        let (db, _dir) = setup();
        let owner_a = IdentityId([0x01; 16]);
        let owner_b = IdentityId([0x02; 16]);
        let store_a = ContactStore::new(Arc::clone(&db), owner_a);
        let store_b = ContactStore::new(Arc::clone(&db), owner_b);

        store_a.add_contact(make_contact(10, "A-contact")).unwrap();
        store_b.add_contact(make_contact(20, "B-contact")).unwrap();

        let list_a = store_a.list_contacts().unwrap();
        let list_b = store_b.list_contacts().unwrap();
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_a[0].label, "A-contact");
        assert_eq!(list_b[0].label, "B-contact");

        assert!(store_a
            .get_contact(&IdentityId([20; 16]))
            .unwrap()
            .is_none());
        assert!(store_b
            .get_contact(&IdentityId([10; 16]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn label_too_long_rejected() {
        let (db, _dir) = setup();
        let owner = IdentityId([0xEE; 16]);
        let store = ContactStore::new(db, owner);
        let long_label = "x".repeat(65);
        let contact = make_contact(1, &long_label);
        let err = store.add_contact(contact).unwrap_err();
        assert!(matches!(err, ContactError::LabelTooLong { len: 65 }));
    }

    #[test]
    fn add_machine_key_appends_to_contact() {
        use super::super::types::ContactMachineKey;
        use zero_crypto::aad::MachineId;

        let (db, _dir) = setup();
        let owner = IdentityId([0xFF; 16]);
        let store = ContactStore::new(db, owner);
        let contact = make_contact(5, "Dave");
        store.add_contact(contact).unwrap();

        let mk = ContactMachineKey {
            machine_id: MachineId([0x10; 16]),
            x25519_public: [0u8; 32],
            mlkem_encap_key: vec![0u8; 1184],
            ed25519_verifying: [0u8; 32],
            mldsa_verifying: vec![0u8; 32],
            epoch: zero_crypto::aad::Epoch(1),
        };

        let mut c = store.get_contact(&IdentityId([5; 16])).unwrap().unwrap();
        c.machine_keys.push(mk.clone());
        store.add_contact(c).unwrap();

        let updated = store.get_contact(&IdentityId([5; 16])).unwrap().unwrap();
        assert_eq!(updated.machine_keys.len(), 1);
        assert_eq!(updated.machine_keys[0].machine_id, mk.machine_id);
    }
}

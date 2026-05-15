//! Group messaging module: types, permissions, manifest, and group lifecycle (task 6.1).

pub mod manifest;
pub mod permissions;
pub mod types;

pub use manifest::merge_manifest;
pub use permissions::{check_permission, PERMISSION_TABLE};
pub use types::{
    GroupAction, GroupError, GroupId, GroupManifest, GroupMember, GroupMessage, GroupMessageId,
    GroupMessageStatus, GroupReceiptPayload, Role, GROUP_MSG_TAG, GROUP_RECEIPT_TAG,
};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zero_crypto::aad::{IdentityId, MachineId};
use zero_storage::{ZeroDb, CF_GROUPS};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}

/// Create a new group. All founders are assigned the `Owner` role.
/// Returns the new `GroupId`. The manifest is persisted with epoch=0.
///
/// # Errors
/// - `GroupError::NameTooLong` if `label` exceeds 64 characters.
/// - `GroupError::Storage` on persistence failure.
pub fn create_group(
    db: &Arc<ZeroDb>,
    label: String,
    founders: &[IdentityId],
) -> Result<GroupId, GroupError> {
    if label.len() > 64 {
        return Err(GroupError::NameTooLong { len: label.len() });
    }

    let group_id = GroupId(uuid::Uuid::now_v7().into_bytes());
    let ts = now_ms();

    let members: Vec<GroupMember> = founders
        .iter()
        .map(|id| GroupMember {
            identity_id: *id,
            machine_id: MachineId([0; 16]),
            role: Role::Owner,
            added_at_ms: ts,
        })
        .collect();

    let mut man = GroupManifest {
        group_id,
        name: label,
        creator: founders.first().copied().unwrap_or(IdentityId([0; 16])),
        members,
        mls_epoch: 0,
        mls_state_blob: Vec::new(),
        created_at_ms: ts,
        updated_at_ms: ts,
    };

    manifest::normalize_members(&mut man);

    let encoded = manifest::encode_manifest(&man)?;
    db.put_raw(CF_GROUPS, &group_id.0, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(group_id)
}

/// Determine which `GroupAction` is needed to move a member to `new_role`.
const fn action_for_role_change(new_role: Role) -> GroupAction {
    match new_role {
        Role::Admin | Role::Owner => GroupAction::PromoteDemoteAdmin,
        Role::Moderator | Role::Member => GroupAction::PromoteDemoteMod,
    }
}

/// Promote a member to a higher-privilege role.
///
/// The caller must have permission for the relevant promote/demote action
/// (looked up via the const permission table). On success the manifest epoch
/// is incremented and the updated manifest is persisted.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::NotAMember` if caller or target is not in the group.
/// - `GroupError::PermissionDenied` if the caller lacks permission.
/// - `GroupError::InvalidManifestUpdate` if `new_role` is not actually a promotion.
pub fn promote(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    caller: IdentityId,
    target: IdentityId,
    new_role: Role,
) -> Result<(), GroupError> {
    let mut man = get_manifest(db, group_id)?;

    let caller_member = man
        .members
        .iter()
        .find(|m| m.identity_id == caller)
        .ok_or(GroupError::NotAMember(caller))?;
    let caller_role = caller_member.role;

    let target_member = man
        .members
        .iter()
        .find(|m| m.identity_id == target)
        .ok_or(GroupError::NotAMember(target))?;
    let target_role = target_member.role;

    if role_privilege(new_role) >= role_privilege(target_role) {
        return Err(GroupError::InvalidManifestUpdate);
    }

    let action = action_for_role_change(new_role);
    if !check_permission(caller_role, action, Some(target_role)) {
        return Err(GroupError::PermissionDenied {
            actor: caller_role,
            action,
        });
    }

    let target_entry = man
        .members
        .iter_mut()
        .find(|m| m.identity_id == target)
        .expect("target verified above");
    target_entry.role = new_role;

    man.mls_epoch += 1;
    man.updated_at_ms = now_ms();

    manifest::normalize_members(&mut man);
    let encoded = manifest::encode_manifest(&man)?;
    db.put_raw(CF_GROUPS, &group_id.0, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(())
}

/// Demote a member to a lower-privilege role.
///
/// The caller must have permission for the relevant promote/demote action.
/// On success the manifest epoch is incremented and the updated manifest is
/// persisted.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::NotAMember` if caller or target is not in the group.
/// - `GroupError::PermissionDenied` if the caller lacks permission.
/// - `GroupError::InvalidManifestUpdate` if `new_role` is not actually a demotion.
pub fn demote(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    caller: IdentityId,
    target: IdentityId,
    new_role: Role,
) -> Result<(), GroupError> {
    let mut man = get_manifest(db, group_id)?;

    let caller_member = man
        .members
        .iter()
        .find(|m| m.identity_id == caller)
        .ok_or(GroupError::NotAMember(caller))?;
    let caller_role = caller_member.role;

    let target_member = man
        .members
        .iter()
        .find(|m| m.identity_id == target)
        .ok_or(GroupError::NotAMember(target))?;
    let target_role = target_member.role;

    if role_privilege(new_role) <= role_privilege(target_role) {
        return Err(GroupError::InvalidManifestUpdate);
    }

    let action = action_for_role_change(target_role);
    if !check_permission(caller_role, action, Some(target_role)) {
        return Err(GroupError::PermissionDenied {
            actor: caller_role,
            action,
        });
    }

    let target_entry = man
        .members
        .iter_mut()
        .find(|m| m.identity_id == target)
        .expect("target verified above");
    target_entry.role = new_role;

    man.mls_epoch += 1;
    man.updated_at_ms = now_ms();

    manifest::normalize_members(&mut man);
    let encoded = manifest::encode_manifest(&man)?;
    db.put_raw(CF_GROUPS, &group_id.0, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(())
}

/// Maximum number of members in a group (V1 documented constraint).
/// `add_member` returns `GroupFull` when current membership reaches this cap.
pub const MAX_GROUP_SIZE: usize = 256;

/// Add a new member to the group with the `Member` role.
///
/// The caller must have the `AddMember` permission (Owner or Admin).
/// Fails with `GroupFull` if the group already has 256 members.
///
/// On success the manifest epoch is incremented and persisted.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::NotAMember` if the caller is not in the group.
/// - `GroupError::PermissionDenied` if the caller lacks `AddMember` permission.
/// - `GroupError::GroupFull` if the group already has 256 members.
///
/// If `new_member` is already in the group, returns `Ok(())` without changes.
pub fn add_member(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    caller: IdentityId,
    new_member: IdentityId,
) -> Result<(), GroupError> {
    let mut man = get_manifest(db, group_id)?;

    let caller_member = man
        .members
        .iter()
        .find(|m| m.identity_id == caller)
        .ok_or(GroupError::NotAMember(caller))?;
    let caller_role = caller_member.role;

    if !check_permission(caller_role, GroupAction::AddMember, None) {
        return Err(GroupError::PermissionDenied {
            actor: caller_role,
            action: GroupAction::AddMember,
        });
    }

    if man.members.iter().any(|m| m.identity_id == new_member) {
        return Ok(());
    }

    if man.members.len() >= MAX_GROUP_SIZE {
        return Err(GroupError::GroupFull {
            size: man.members.len(),
        });
    }

    man.members.push(GroupMember {
        identity_id: new_member,
        machine_id: MachineId([0; 16]),
        role: Role::Member,
        added_at_ms: now_ms(),
    });

    man.mls_epoch += 1;
    man.updated_at_ms = now_ms();

    manifest::normalize_members(&mut man);
    let encoded = manifest::encode_manifest(&man)?;
    db.put_raw(CF_GROUPS, &group_id.0, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(())
}

/// Remove a member from the group.
///
/// The caller must satisfy `PERMISSION_TABLE` for `RemoveMember`.
/// The Moderator special case is enforced: a Moderator may only remove a
/// Member, not an Admin or Owner.
///
/// On success the manifest epoch is incremented and persisted.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::NotAMember` if the caller or target is not in the group.
/// - `GroupError::PermissionDenied` if the caller lacks `RemoveMember` permission.
pub fn remove_member(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    caller: IdentityId,
    target: IdentityId,
) -> Result<(), GroupError> {
    let mut man = get_manifest(db, group_id)?;

    let caller_member = man
        .members
        .iter()
        .find(|m| m.identity_id == caller)
        .ok_or(GroupError::NotAMember(caller))?;
    let caller_role = caller_member.role;

    let target_member = man
        .members
        .iter()
        .find(|m| m.identity_id == target)
        .ok_or(GroupError::NotAMember(target))?;
    let target_role = target_member.role;

    if !check_permission(caller_role, GroupAction::RemoveMember, Some(target_role)) {
        return Err(GroupError::PermissionDenied {
            actor: caller_role,
            action: GroupAction::RemoveMember,
        });
    }

    // Additional privilege check: cannot remove someone of equal or higher rank
    // (Owner is exempt since they have the highest rank).
    if caller_role != Role::Owner && role_privilege(caller_role) >= role_privilege(target_role) {
        return Err(GroupError::PermissionDenied {
            actor: caller_role,
            action: GroupAction::RemoveMember,
        });
    }

    man.members.retain(|m| m.identity_id != target);

    man.mls_epoch += 1;
    man.updated_at_ms = now_ms();

    manifest::normalize_members(&mut man);
    let encoded = manifest::encode_manifest(&man)?;
    db.put_raw(CF_GROUPS, &group_id.0, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(())
}

/// Lower numeric value = higher privilege. Used to validate promote vs demote direction.
fn role_privilege(role: Role) -> u8 {
    match role {
        Role::Owner => 0,
        Role::Admin => 1,
        Role::Moderator => 2,
        Role::Member => 3,
    }
}

/// Load a persisted `GroupManifest` by its `GroupId`.
///
/// # Errors
/// - `GroupError::GroupNotFound` if no manifest exists for the given id.
/// - `GroupError::Storage` on read failure.
pub fn get_manifest(db: &Arc<ZeroDb>, group_id: GroupId) -> Result<GroupManifest, GroupError> {
    let bytes = db
        .get_raw(CF_GROUPS, &group_id.0)
        .map_err(GroupError::Storage)?
        .ok_or(GroupError::GroupNotFound(group_id))?;
    manifest::decode_manifest(&bytes)
}

const GROUP_MSG_PREFIX: &[u8] = b"group_msg:";

fn make_msg_key(group_id: &GroupId, message_id: &GroupMessageId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GROUP_MSG_PREFIX.len() + 16 + 16);
    key.extend_from_slice(GROUP_MSG_PREFIX);
    key.extend_from_slice(&group_id.0);
    key.extend_from_slice(&message_id.0);
    key
}

fn make_msg_prefix(group_id: &GroupId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GROUP_MSG_PREFIX.len() + 16);
    key.extend_from_slice(GROUP_MSG_PREFIX);
    key.extend_from_slice(&group_id.0);
    key
}

/// Send a text message in a group. The sender must be a current member.
///
/// Returns the new `GroupMessageId` on success.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::NotAMember` if the sender is not in the manifest.
/// - `GroupError::Storage` on persistence failure.
pub fn send_message(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    sender_identity: IdentityId,
    sender_machine: MachineId,
    text: String,
) -> Result<GroupMessageId, GroupError> {
    let man = get_manifest(db, group_id)?;

    if !man.members.iter().any(|m| m.identity_id == sender_identity) {
        return Err(GroupError::NotAMember(sender_identity));
    }

    let msg_id = GroupMessageId(uuid::Uuid::now_v7().into_bytes());
    let ts = now_ms();

    let msg = GroupMessage {
        id: msg_id,
        group_id,
        sender_identity,
        sender_machine,
        text,
        mls_epoch: man.mls_epoch,
        created_at_ms: ts,
        status: GroupMessageStatus::Sent,
    };

    let encoded = postcard::to_stdvec(&msg).map_err(|e| GroupError::Mls(e.to_string()))?;
    let key = make_msg_key(&group_id, &msg_id);
    db.put_raw(CF_GROUPS, &key, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(msg_id)
}

/// Receive (store) an inbound group message. Deduplication: if a message with
/// the same id already exists, the call is a no-op and returns `Ok(false)`.
///
/// Returns `Ok(true)` when the message was newly persisted.
///
/// # Errors
/// - `GroupError::GroupNotFound` if the group does not exist.
/// - `GroupError::Storage` on persistence failure.
pub fn receive_message(db: &Arc<ZeroDb>, msg: GroupMessage) -> Result<bool, GroupError> {
    let _man = get_manifest(db, msg.group_id)?;

    let key = make_msg_key(&msg.group_id, &msg.id);

    if db
        .get_raw(CF_GROUPS, &key)
        .map_err(GroupError::Storage)?
        .is_some()
    {
        return Ok(false);
    }

    let encoded = postcard::to_stdvec(&msg).map_err(|e| GroupError::Mls(e.to_string()))?;
    db.put_raw(CF_GROUPS, &key, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(true)
}

/// Retrieve a single group message by its id.
///
/// # Errors
/// - `GroupError::Mls` if the stored bytes cannot be decoded.
/// - `GroupError::Storage` on read failure.
pub fn get_message(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    message_id: GroupMessageId,
) -> Result<Option<GroupMessage>, GroupError> {
    let key = make_msg_key(&group_id, &message_id);
    match db.get_raw(CF_GROUPS, &key).map_err(GroupError::Storage)? {
        Some(bytes) => {
            let msg: GroupMessage =
                postcard::from_bytes(&bytes).map_err(|e| GroupError::Mls(e.to_string()))?;
            Ok(Some(msg))
        }
        None => Ok(None),
    }
}

/// List group messages in descending `created_at_ms` order.
///
/// If `before` is `Some`, only messages whose id is lexicographically less
/// than that cursor are returned (UUIDv7 ids are time-ordered, so this
/// provides natural pagination).
///
/// # Errors
/// - `GroupError::Storage` on iteration failure.
pub fn list_messages(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    before: Option<GroupMessageId>,
    limit: usize,
) -> Result<Vec<GroupMessage>, GroupError> {
    let prefix = make_msg_prefix(&group_id);
    let cf = db.cf_handle(CF_GROUPS).map_err(GroupError::Storage)?;
    let iter = db.inner().prefix_iterator_cf(cf, &prefix);

    let mut messages: Vec<GroupMessage> = Vec::new();
    for item in iter {
        let (key, value) =
            item.map_err(|e| GroupError::Storage(zero_storage::StorageError::Rocks(e)))?;
        if !key.starts_with(&prefix) {
            break;
        }
        let msg: GroupMessage =
            postcard::from_bytes(&value).map_err(|e| GroupError::Mls(e.to_string()))?;
        if let Some(ref cursor) = before {
            if msg.id.0 >= cursor.0 {
                continue;
            }
        }
        messages.push(msg);
    }

    messages.sort_by(|a, b| {
        b.created_at_ms
            .cmp(&a.created_at_ms)
            .then_with(|| b.id.0.cmp(&a.id.0))
    });
    messages.truncate(limit);
    Ok(messages)
}

/// Process a group receipt, updating the message status if the transition is
/// forward-only (Sent -> Delivered -> Read).
///
/// Returns `Ok(true)` if the status was updated, `Ok(false)` if the receipt
/// was a no-op (duplicate or backward transition).
///
/// # Errors
/// - `GroupError::Storage` on read/write failure.
/// - `GroupError::Mls` on decode failure.
pub fn process_receipt(
    db: &Arc<ZeroDb>,
    receipt: &GroupReceiptPayload,
) -> Result<bool, GroupError> {
    let key = make_msg_key(&receipt.group_id, &receipt.message_id);
    let bytes = match db.get_raw(CF_GROUPS, &key).map_err(GroupError::Storage)? {
        Some(b) => b,
        None => return Ok(false),
    };
    let mut msg: GroupMessage =
        postcard::from_bytes(&bytes).map_err(|e| GroupError::Mls(e.to_string()))?;

    if !is_forward_transition(msg.status, receipt.status) {
        return Ok(false);
    }

    msg.status = receipt.status;
    let encoded = postcard::to_stdvec(&msg).map_err(|e| GroupError::Mls(e.to_string()))?;
    db.put_raw(CF_GROUPS, &key, &encoded)
        .map_err(GroupError::Storage)?;

    Ok(true)
}

fn is_forward_transition(current: GroupMessageStatus, new: GroupMessageStatus) -> bool {
    let rank = |s: GroupMessageStatus| -> u8 {
        match s {
            GroupMessageStatus::Sent => 0,
            GroupMessageStatus::Delivered => 1,
            GroupMessageStatus::Read => 2,
        }
    };
    rank(new) > rank(current)
}

/// Build a `GroupReceiptPayload` that marks a message as delivered.
pub fn mark_delivered(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    message_id: GroupMessageId,
    recipient_identity: IdentityId,
    recipient_machine: MachineId,
) -> Result<Option<GroupReceiptPayload>, GroupError> {
    mark_status(
        db,
        group_id,
        message_id,
        recipient_identity,
        recipient_machine,
        GroupMessageStatus::Delivered,
    )
}

/// Build a `GroupReceiptPayload` that marks a message as read.
pub fn mark_read(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    message_id: GroupMessageId,
    recipient_identity: IdentityId,
    recipient_machine: MachineId,
) -> Result<Option<GroupReceiptPayload>, GroupError> {
    mark_status(
        db,
        group_id,
        message_id,
        recipient_identity,
        recipient_machine,
        GroupMessageStatus::Read,
    )
}

fn mark_status(
    db: &Arc<ZeroDb>,
    group_id: GroupId,
    message_id: GroupMessageId,
    recipient_identity: IdentityId,
    recipient_machine: MachineId,
    status: GroupMessageStatus,
) -> Result<Option<GroupReceiptPayload>, GroupError> {
    let receipt = GroupReceiptPayload {
        message_id,
        group_id,
        recipient_identity,
        recipient_machine,
        status,
        timestamp_ms: now_ms(),
    };

    let updated = process_receipt(db, &receipt)?;
    if updated {
        Ok(Some(receipt))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_storage::ZeroDb;

    fn temp_db() -> Arc<ZeroDb> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(ZeroDb::open(dir.path()).unwrap())
    }

    fn id(b: u8) -> IdentityId {
        IdentityId([b; 16])
    }

    #[test]
    fn create_single_founder() {
        let db = temp_db();
        let gid = create_group(&db, "test-group".into(), &[id(1)]).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.mls_epoch, 0);
        assert_eq!(man.members.len(), 1);
        assert_eq!(man.members[0].identity_id, id(1));
        assert_eq!(man.members[0].role, Role::Owner);
        assert_eq!(man.name, "test-group");
        assert_eq!(man.creator, id(1));
    }

    #[test]
    fn create_multiple_founders_all_owners() {
        let db = temp_db();
        let founders = vec![id(3), id(1), id(2)];
        let gid = create_group(&db, "multi".into(), &founders).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.mls_epoch, 0);
        assert_eq!(man.members.len(), 3);
        for m in &man.members {
            assert_eq!(m.role, Role::Owner);
        }
        // Members are sorted by identity_id bytes
        assert!(man.members[0].identity_id.0 <= man.members[1].identity_id.0);
        assert!(man.members[1].identity_id.0 <= man.members[2].identity_id.0);
    }

    #[test]
    fn create_name_too_long() {
        let db = temp_db();
        let long_name = "x".repeat(65);
        let err = create_group(&db, long_name, &[id(1)]).unwrap_err();
        assert!(matches!(err, GroupError::NameTooLong { len: 65 }));
    }

    #[test]
    fn get_manifest_not_found() {
        let db = temp_db();
        let missing = GroupId([0xFF; 16]);
        let err = get_manifest(&db, missing).unwrap_err();
        assert!(matches!(err, GroupError::GroupNotFound(_)));
    }

    #[test]
    fn manifest_persisted_and_readable() {
        let db = temp_db();
        let founders: Vec<IdentityId> = (1..=5).map(id).collect();
        let gid = create_group(&db, "persist-test".into(), &founders).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.group_id, gid);
        assert_eq!(man.members.len(), 5);
        assert_eq!(man.mls_epoch, 0);
    }

    #[test]
    fn epoch_zero_at_creation() {
        let db = temp_db();
        let gid = create_group(&db, "epoch".into(), &[id(9)]).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.mls_epoch, 0);
    }

    fn setup_group_with_roles(db: &Arc<ZeroDb>) -> GroupId {
        let gid = create_group(db, "roles".into(), &[id(1)]).unwrap();
        let mut man = get_manifest(db, gid).unwrap();
        man.members.push(GroupMember {
            identity_id: id(2),
            machine_id: MachineId([0; 16]),
            role: Role::Admin,
            added_at_ms: now_ms(),
        });
        man.members.push(GroupMember {
            identity_id: id(3),
            machine_id: MachineId([0; 16]),
            role: Role::Moderator,
            added_at_ms: now_ms(),
        });
        man.members.push(GroupMember {
            identity_id: id(4),
            machine_id: MachineId([0; 16]),
            role: Role::Member,
            added_at_ms: now_ms(),
        });
        manifest::normalize_members(&mut man);
        let encoded = manifest::encode_manifest(&man).unwrap();
        db.put_raw(CF_GROUPS, &gid.0, &encoded).unwrap();
        gid
    }

    #[test]
    fn promote_member_to_moderator_by_owner() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        promote(&db, gid, id(1), id(4), Role::Moderator).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        let target = man.members.iter().find(|m| m.identity_id == id(4)).unwrap();
        assert_eq!(target.role, Role::Moderator);
        assert_eq!(man.mls_epoch, 1);
    }

    #[test]
    fn promote_advances_epoch_and_persists() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let before = get_manifest(&db, gid).unwrap();
        assert_eq!(before.mls_epoch, 0);

        promote(&db, gid, id(1), id(4), Role::Moderator).unwrap();
        let after = get_manifest(&db, gid).unwrap();
        assert_eq!(after.mls_epoch, 1);
        assert!(after.updated_at_ms >= before.updated_at_ms);

        promote(&db, gid, id(1), id(4), Role::Admin).unwrap();
        let after2 = get_manifest(&db, gid).unwrap();
        assert_eq!(after2.mls_epoch, 2);
    }

    #[test]
    fn demote_admin_to_member_by_owner() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        demote(&db, gid, id(1), id(2), Role::Member).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        let target = man.members.iter().find(|m| m.identity_id == id(2)).unwrap();
        assert_eq!(target.role, Role::Member);
        assert_eq!(man.mls_epoch, 1);
    }

    #[test]
    fn demote_advances_epoch_and_persists() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        demote(&db, gid, id(1), id(2), Role::Moderator).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.mls_epoch, 1);
        let target = man.members.iter().find(|m| m.identity_id == id(2)).unwrap();
        assert_eq!(target.role, Role::Moderator);
    }

    #[test]
    fn promote_by_admin_to_moderator() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        promote(&db, gid, id(2), id(4), Role::Moderator).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        let target = man.members.iter().find(|m| m.identity_id == id(4)).unwrap();
        assert_eq!(target.role, Role::Moderator);
    }

    #[test]
    fn promote_by_admin_to_admin_denied() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(2), id(4), Role::Admin).unwrap_err();
        assert!(matches!(
            err,
            GroupError::PermissionDenied {
                action: GroupAction::PromoteDemoteAdmin,
                ..
            }
        ));
    }

    #[test]
    fn promote_by_member_denied() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(4), id(3), Role::Admin).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn promote_by_moderator_denied() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(3), id(4), Role::Moderator).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn demote_by_member_denied() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = demote(&db, gid, id(4), id(3), Role::Member).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn promote_wrong_direction_is_invalid() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(1), id(2), Role::Member).unwrap_err();
        assert!(matches!(err, GroupError::InvalidManifestUpdate));
    }

    #[test]
    fn demote_wrong_direction_is_invalid() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = demote(&db, gid, id(1), id(4), Role::Admin).unwrap_err();
        assert!(matches!(err, GroupError::InvalidManifestUpdate));
    }

    #[test]
    fn promote_same_role_is_invalid() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(1), id(4), Role::Member).unwrap_err();
        assert!(matches!(err, GroupError::InvalidManifestUpdate));
    }

    #[test]
    fn promote_nonmember_target_fails() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(1), id(99), Role::Admin).unwrap_err();
        assert!(matches!(err, GroupError::NotAMember(_)));
    }

    #[test]
    fn promote_nonmember_caller_fails() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        let err = promote(&db, gid, id(99), id(4), Role::Admin).unwrap_err();
        assert!(matches!(err, GroupError::NotAMember(_)));
    }

    #[test]
    fn promote_group_not_found() {
        let db = temp_db();
        let missing = GroupId([0xAA; 16]);
        let err = promote(&db, missing, id(1), id(2), Role::Admin).unwrap_err();
        assert!(matches!(err, GroupError::GroupNotFound(_)));
    }

    #[test]
    fn demote_group_not_found() {
        let db = temp_db();
        let missing = GroupId([0xAA; 16]);
        let err = demote(&db, missing, id(1), id(2), Role::Member).unwrap_err();
        assert!(matches!(err, GroupError::GroupNotFound(_)));
    }

    #[test]
    fn owner_promote_member_to_admin() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        promote(&db, gid, id(1), id(4), Role::Admin).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        let target = man.members.iter().find(|m| m.identity_id == id(4)).unwrap();
        assert_eq!(target.role, Role::Admin);
    }

    #[test]
    fn owner_demote_admin_to_moderator() {
        let db = temp_db();
        let gid = setup_group_with_roles(&db);
        demote(&db, gid, id(1), id(2), Role::Moderator).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        let target = man.members.iter().find(|m| m.identity_id == id(2)).unwrap();
        assert_eq!(target.role, Role::Moderator);
    }

    #[test]
    fn exhaustive_permission_matrix() {
        use super::permissions::PERMISSION_TABLE;
        let roles = [Role::Owner, Role::Admin, Role::Moderator, Role::Member];
        let actions = [
            GroupAction::SendMessage,
            GroupAction::AddMember,
            GroupAction::RemoveMember,
            GroupAction::PromoteDemoteMod,
            GroupAction::PromoteDemoteAdmin,
            GroupAction::DeleteGroup,
        ];
        for (ri, role) in roles.iter().enumerate() {
            for (ai, action) in actions.iter().enumerate() {
                let expected = PERMISSION_TABLE[ri][ai];
                // Moderator+RemoveMember requires a target_role; without one
                // check_permission conservatively returns false. For the
                // exhaustive sweep we pass Some(Role::Member) so it matches
                // the table's "true" for that cell.
                let target = if *role == Role::Moderator && *action == GroupAction::RemoveMember {
                    Some(Role::Member)
                } else {
                    None
                };
                let result = check_permission(*role, *action, target);
                assert_eq!(
                    result, expected,
                    "mismatch for {role:?} / {action:?}: table={expected}, check={result}"
                );
            }
        }
    }

    #[test]
    fn moderator_remove_member_special_case() {
        assert!(check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Member)
        ));
        assert!(!check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Admin)
        ));
        assert!(!check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Owner)
        ));
        assert!(!check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Moderator)
        ));
    }

    #[test]
    fn add_member_basic() {
        let db = temp_db();
        let owner = id(1);
        let new_member = id(5);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, new_member).unwrap();

        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 2);
        assert!(man.members.iter().any(|m| m.identity_id == new_member));
        let added = man
            .members
            .iter()
            .find(|m| m.identity_id == new_member)
            .unwrap();
        assert_eq!(added.role, Role::Member);
    }

    #[test]
    fn add_member_epoch_advances() {
        let db = temp_db();
        let owner = id(1);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        let epoch_before = get_manifest(&db, gid).unwrap().mls_epoch;

        add_member(&db, gid, owner, id(5)).unwrap();

        let man_after = get_manifest(&db, gid).unwrap();
        assert_eq!(man_after.mls_epoch, epoch_before + 1);
    }

    #[test]
    fn add_member_permission_denied_for_member_role() {
        let db = temp_db();
        let owner = id(1);
        let member = id(2);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, member).unwrap();

        let err = add_member(&db, gid, member, id(6)).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn add_member_group_full_at_257() {
        let db = temp_db();
        let owner = id(1);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        for i in 1u16..256 {
            let mut bytes = [0u8; 16];
            bytes[0] = (i >> 8) as u8;
            bytes[1] = (i & 0xff) as u8;
            bytes[2] = 0xAA;
            add_member(&db, gid, owner, IdentityId(bytes)).unwrap();
        }

        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 256);

        let mut overflow = [0u8; 16];
        overflow[0] = 0xFF;
        overflow[1] = 0xFF;
        overflow[2] = 0xBB;
        let err = add_member(&db, gid, owner, IdentityId(overflow)).unwrap_err();
        assert!(matches!(err, GroupError::GroupFull { size: 256 }));
    }

    #[test]
    fn add_member_already_exists_is_noop_like() {
        let db = temp_db();
        let owner = id(1);
        let member = id(5);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, member).unwrap();
        let man1 = get_manifest(&db, gid).unwrap();

        add_member(&db, gid, owner, member).unwrap();
        let man2 = get_manifest(&db, gid).unwrap();

        assert_eq!(man2.members.len(), 2);
        assert_eq!(man2.mls_epoch, man1.mls_epoch);
    }

    #[test]
    fn add_member_group_not_found() {
        let db = temp_db();
        let gid = GroupId([99u8; 16]);
        let err = add_member(&db, gid, id(1), id(5)).unwrap_err();
        assert!(matches!(err, GroupError::GroupNotFound(_)));
    }

    #[test]
    fn remove_member_basic() {
        let db = temp_db();
        let owner = id(1);
        let member = id(5);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, member).unwrap();
        assert_eq!(get_manifest(&db, gid).unwrap().members.len(), 2);

        remove_member(&db, gid, owner, member).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 1);
        assert!(!man.members.iter().any(|m| m.identity_id == member));
    }

    #[test]
    fn remove_member_epoch_advances() {
        let db = temp_db();
        let owner = id(1);
        let member = id(5);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, member).unwrap();
        let epoch_before = get_manifest(&db, gid).unwrap().mls_epoch;

        remove_member(&db, gid, owner, member).unwrap();
        let epoch_after = get_manifest(&db, gid).unwrap().mls_epoch;
        assert_eq!(epoch_after, epoch_before + 1);
    }

    #[test]
    fn remove_member_permission_denied_member_removes() {
        let db = temp_db();
        let owner = id(1);
        let m1 = id(5);
        let m2 = id(6);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, m1).unwrap();
        add_member(&db, gid, owner, m2).unwrap();

        let err = remove_member(&db, gid, m1, m2).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn remove_member_admin_cannot_remove_owner() {
        let db = temp_db();
        let owner = id(1);
        let admin_id = id(5);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, admin_id).unwrap();
        promote(&db, gid, owner, admin_id, Role::Admin).unwrap();

        let err = remove_member(&db, gid, admin_id, owner).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    #[test]
    fn remove_member_not_a_member() {
        let db = temp_db();
        let owner = id(1);
        let stranger = id(99);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        let err = remove_member(&db, gid, owner, stranger).unwrap_err();
        assert!(matches!(err, GroupError::NotAMember(_)));
    }

    #[test]
    fn remove_member_group_not_found() {
        let db = temp_db();
        let gid = GroupId([99u8; 16]);
        let err = remove_member(&db, gid, id(1), id(5)).unwrap_err();
        assert!(matches!(err, GroupError::GroupNotFound(_)));
    }

    #[test]
    fn add_remove_round_trip() {
        let db = temp_db();
        let owner = id(1);
        let m1 = id(5);
        let m2 = id(6);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, m1).unwrap();
        add_member(&db, gid, owner, m2).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 3);
        assert_eq!(man.mls_epoch, 2);

        remove_member(&db, gid, owner, m1).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 2);
        assert_eq!(man.mls_epoch, 3);
        assert!(!man.members.iter().any(|m| m.identity_id == m1));
        assert!(man.members.iter().any(|m| m.identity_id == m2));
    }

    #[test]
    fn moderator_can_remove_member_but_not_admin() {
        let db = temp_db();
        let owner = id(1);
        let mod_id = id(5);
        let member_id = id(6);
        let admin_id = id(7);
        let gid = create_group(&db, "test".into(), &[owner]).unwrap();

        add_member(&db, gid, owner, mod_id).unwrap();
        add_member(&db, gid, owner, member_id).unwrap();
        add_member(&db, gid, owner, admin_id).unwrap();

        promote(&db, gid, owner, mod_id, Role::Moderator).unwrap();
        promote(&db, gid, owner, admin_id, Role::Admin).unwrap();

        remove_member(&db, gid, mod_id, member_id).unwrap();
        let man = get_manifest(&db, gid).unwrap();
        assert!(!man.members.iter().any(|m| m.identity_id == member_id));

        add_member(&db, gid, owner, member_id).unwrap();

        let err = remove_member(&db, gid, mod_id, admin_id).unwrap_err();
        assert!(matches!(err, GroupError::PermissionDenied { .. }));
    }

    // ----------------------------------------------------------------
    // Multi-party convergence test (3 machines sharing one DB)
    // ----------------------------------------------------------------

    #[test]
    fn three_machine_convergence() {
        let db = temp_db();
        let owner = id(1);
        let alice = id(2);
        let bob = id(3);

        // Owner creates the group
        let gid = create_group(&db, "convergence".into(), &[owner]).unwrap();

        // Owner adds Alice and Bob
        add_member(&db, gid, owner, alice).unwrap();
        add_member(&db, gid, owner, bob).unwrap();

        // Promote Alice to Admin
        promote(&db, gid, owner, alice, Role::Admin).unwrap();

        // Alice (Admin) adds a 4th member
        let charlie = id(4);
        add_member(&db, gid, alice, charlie).unwrap();

        // Promote Bob to Moderator
        promote(&db, gid, owner, bob, Role::Moderator).unwrap();

        // Bob (Moderator) removes Charlie (Member)
        remove_member(&db, gid, bob, charlie).unwrap();

        // Send messages from each participant
        let m1 = send_message(
            &db,
            gid,
            owner,
            MachineId([1; 16]),
            "hello from owner".into(),
        )
        .unwrap();
        let m2 = send_message(
            &db,
            gid,
            alice,
            MachineId([2; 16]),
            "hello from alice".into(),
        )
        .unwrap();
        let m3 = send_message(&db, gid, bob, MachineId([3; 16]), "hello from bob".into()).unwrap();

        // Verify messages exist
        assert!(get_message(&db, gid, m1).unwrap().is_some());
        assert!(get_message(&db, gid, m2).unwrap().is_some());
        assert!(get_message(&db, gid, m3).unwrap().is_some());

        // Snapshot manifest from each "machine's" perspective (same DB = converged)
        let man_owner = get_manifest(&db, gid).unwrap();
        let man_alice = get_manifest(&db, gid).unwrap();
        let man_bob = get_manifest(&db, gid).unwrap();

        // All three see the same manifest
        assert_eq!(man_owner, man_alice);
        assert_eq!(man_alice, man_bob);

        // Verify final membership: owner(Owner), alice(Admin), bob(Moderator)
        assert_eq!(man_owner.members.len(), 3);
        let find = |iid: IdentityId| {
            man_owner
                .members
                .iter()
                .find(|m| m.identity_id == iid)
                .unwrap()
        };
        assert_eq!(find(owner).role, Role::Owner);
        assert_eq!(find(alice).role, Role::Admin);
        assert_eq!(find(bob).role, Role::Moderator);

        // Charlie was removed
        assert!(!man_owner.members.iter().any(|m| m.identity_id == charlie));

        // Epoch reflects all commits: 2 adds + promote(alice) + add(charlie)
        // + promote(bob) + remove(charlie) = 6
        assert_eq!(man_owner.mls_epoch, 6);
    }

    // ----------------------------------------------------------------
    // Multi-party: independent DB convergence via manifest merge
    // ----------------------------------------------------------------

    #[test]
    fn manifest_merge_convergence_across_dbs() {
        use crate::group::manifest::merge_manifests;

        let db = temp_db();
        let owner = id(1);
        let alice = id(2);

        // Create group and snapshot at epoch 0
        let gid = create_group(&db, "merge-test".into(), &[owner]).unwrap();
        let man_epoch0 = get_manifest(&db, gid).unwrap();

        // Advance: add alice => epoch 1
        add_member(&db, gid, owner, alice).unwrap();
        let man_epoch1 = get_manifest(&db, gid).unwrap();

        // Merge: man_epoch1 has epoch=1, man_epoch0 has epoch=0 => epoch1 wins
        let merged = merge_manifests(&man_epoch1, &man_epoch0);
        assert_eq!(merged.mls_epoch, man_epoch1.mls_epoch);
        assert_eq!(merged.members.len(), man_epoch1.members.len());

        // Commutativity
        let merged_rev = merge_manifests(&man_epoch0, &man_epoch1);
        assert_eq!(merged, merged_rev);

        // Idempotent
        let merged_again = merge_manifests(&merged, &man_epoch1);
        assert_eq!(merged, merged_again);
    }

    // ----------------------------------------------------------------
    // GroupFull at exactly 257 members
    // ----------------------------------------------------------------

    #[test]
    fn group_full_at_exactly_257() {
        let db = temp_db();
        let owner = id(1);
        let gid = create_group(&db, "big".into(), &[owner]).unwrap();

        // Add members 2..=255 (254 adds, total 255 members)
        for i in 2u16..=255 {
            let mid = IdentityId([
                (i >> 8) as u8,
                (i & 0xff) as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            add_member(&db, gid, owner, mid).unwrap();
        }

        // Member 256 should succeed (total = 256)
        let m256 = IdentityId([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        add_member(&db, gid, owner, m256).unwrap();

        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 256);

        // Member 257 must fail with GroupFull
        let m257 = IdentityId([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let err = add_member(&db, gid, owner, m257).unwrap_err();
        match err {
            GroupError::GroupFull { size } => assert_eq!(size, 256),
            other => panic!("expected GroupFull, got: {other:?}"),
        }
    }

    // ----------------------------------------------------------------
    // 3-member send/receive round-trip with receipts (task 6.4)
    // ----------------------------------------------------------------

    #[test]
    fn three_member_send_receive_round_trip() {
        let db = temp_db();
        let owner = id(1);
        let m2 = id(2);
        let m3 = id(3);

        let gid = create_group(&db, "trio".into(), &[owner]).unwrap();
        add_member(&db, gid, owner, m2).unwrap();
        add_member(&db, gid, owner, m3).unwrap();

        let man = get_manifest(&db, gid).unwrap();
        assert_eq!(man.members.len(), 3);

        let msg_id =
            send_message(&db, gid, owner, MachineId([0; 16]), "hello group".into()).unwrap();

        let sent_msg = get_message(&db, gid, msg_id).unwrap().unwrap();
        assert_eq!(sent_msg.text, "hello group");
        assert_eq!(sent_msg.sender_identity, owner);
        assert_eq!(sent_msg.status, GroupMessageStatus::Sent);

        let db2 = temp_db();
        manifest::persist_manifest(&db2, &man).unwrap();
        let received = receive_message(
            &db2,
            GroupMessage {
                id: msg_id,
                group_id: gid,
                sender_identity: owner,
                sender_machine: MachineId([0; 16]),
                text: "hello group".into(),
                mls_epoch: 0,
                created_at_ms: sent_msg.created_at_ms,
                status: GroupMessageStatus::Sent,
            },
        )
        .unwrap();
        assert!(received, "first receive should insert");

        let db3 = temp_db();
        manifest::persist_manifest(&db3, &man).unwrap();
        let received3 = receive_message(
            &db3,
            GroupMessage {
                id: msg_id,
                group_id: gid,
                sender_identity: owner,
                sender_machine: MachineId([0; 16]),
                text: "hello group".into(),
                mls_epoch: 0,
                created_at_ms: sent_msg.created_at_ms,
                status: GroupMessageStatus::Sent,
            },
        )
        .unwrap();
        assert!(received3, "third member receive should insert");

        let dup = receive_message(
            &db3,
            GroupMessage {
                id: msg_id,
                group_id: gid,
                sender_identity: owner,
                sender_machine: MachineId([0; 16]),
                text: "hello group".into(),
                mls_epoch: 0,
                created_at_ms: sent_msg.created_at_ms,
                status: GroupMessageStatus::Sent,
            },
        )
        .unwrap();
        assert!(!dup, "duplicate receive should be idempotent");

        let stored = get_message(&db2, gid, msg_id).unwrap().unwrap();
        assert_eq!(stored.text, "hello group");
    }

    #[test]
    fn receipt_transitions_sent_delivered_read() {
        let db = temp_db();
        let owner = id(1);
        let m2 = id(2);
        let gid = create_group(&db, "receipt-test".into(), &[owner]).unwrap();
        add_member(&db, gid, owner, m2).unwrap();

        let msg_id = send_message(&db, gid, owner, MachineId([0; 16]), "track me".into()).unwrap();

        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Sent,
        );

        let receipt_delivered = GroupReceiptPayload {
            group_id: gid,
            message_id: msg_id,
            recipient_identity: m2,
            recipient_machine: MachineId([0; 16]),
            status: GroupMessageStatus::Delivered,
            timestamp_ms: now_ms(),
        };
        let updated = process_receipt(&db, &receipt_delivered).unwrap();
        assert!(updated);
        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Delivered,
        );

        let receipt_read = GroupReceiptPayload {
            group_id: gid,
            message_id: msg_id,
            recipient_identity: m2,
            recipient_machine: MachineId([0; 16]),
            status: GroupMessageStatus::Read,
            timestamp_ms: now_ms(),
        };
        let updated = process_receipt(&db, &receipt_read).unwrap();
        assert!(updated);
        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Read,
        );

        let backward = GroupReceiptPayload {
            group_id: gid,
            message_id: msg_id,
            recipient_identity: m2,
            recipient_machine: MachineId([0; 16]),
            status: GroupMessageStatus::Delivered,
            timestamp_ms: now_ms(),
        };
        let updated = process_receipt(&db, &backward).unwrap();
        assert!(!updated, "backward transition should be rejected");
        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Read,
        );
    }

    #[test]
    fn three_member_receipts_update_statuses() {
        let db = temp_db();
        let owner = id(1);
        let m2 = id(2);
        let m3 = id(3);

        let gid = create_group(&db, "receipt-trio".into(), &[owner]).unwrap();
        add_member(&db, gid, owner, m2).unwrap();
        add_member(&db, gid, owner, m3).unwrap();

        let msg_id =
            send_message(&db, gid, m2, MachineId([0; 16]), "from member 2".into()).unwrap();

        let r1 = GroupReceiptPayload {
            group_id: gid,
            message_id: msg_id,
            recipient_identity: owner,
            recipient_machine: MachineId([0; 16]),
            status: GroupMessageStatus::Delivered,
            timestamp_ms: now_ms(),
        };
        assert!(process_receipt(&db, &r1).unwrap());
        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Delivered,
        );

        let r2 = GroupReceiptPayload {
            group_id: gid,
            message_id: msg_id,
            recipient_identity: m3,
            recipient_machine: MachineId([0; 16]),
            status: GroupMessageStatus::Read,
            timestamp_ms: now_ms(),
        };
        assert!(process_receipt(&db, &r2).unwrap());
        assert_eq!(
            get_message(&db, gid, msg_id).unwrap().unwrap().status,
            GroupMessageStatus::Read,
        );
    }

    #[test]
    fn schema_tags_match_spec() {
        assert_eq!(GROUP_MSG_TAG, "zero.group.v1");
        assert_eq!(GROUP_RECEIPT_TAG, "zero.receipt.v1");
    }

    #[test]
    fn list_messages_after_multi_member_send() {
        let db = temp_db();
        let owner = id(1);
        let m2 = id(2);
        let m3 = id(3);

        let gid = create_group(&db, "list-test".into(), &[owner]).unwrap();
        add_member(&db, gid, owner, m2).unwrap();
        add_member(&db, gid, owner, m3).unwrap();

        let id1 = send_message(&db, gid, owner, MachineId([0; 16]), "msg1".into()).unwrap();
        let id2 = send_message(&db, gid, m2, MachineId([0; 16]), "msg2".into()).unwrap();
        let id3 = send_message(&db, gid, m3, MachineId([0; 16]), "msg3".into()).unwrap();

        let all = list_messages(&db, gid, None, 10).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, id3);
        assert_eq!(all[1].id, id2);
        assert_eq!(all[2].id, id1);

        let page = list_messages(&db, gid, Some(id3), 2).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, id2);
        assert_eq!(page[1].id, id1);
    }
}

// ----------------------------------------------------------------
// proptest module: manifest merge commutativity + idempotence
// ----------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::group::manifest::merge_manifests;
    use proptest::prelude::*;
    use zero_crypto::aad::{IdentityId, MachineId};

    fn arb_identity_id() -> impl Strategy<Value = IdentityId> {
        proptest::array::uniform16(any::<u8>()).prop_map(IdentityId)
    }

    fn arb_machine_id() -> impl Strategy<Value = MachineId> {
        proptest::array::uniform16(any::<u8>()).prop_map(MachineId)
    }

    fn arb_role() -> impl Strategy<Value = Role> {
        prop_oneof![
            Just(Role::Owner),
            Just(Role::Admin),
            Just(Role::Moderator),
            Just(Role::Member),
        ]
    }

    fn arb_group_member() -> impl Strategy<Value = GroupMember> {
        (
            arb_identity_id(),
            arb_machine_id(),
            arb_role(),
            any::<u64>(),
        )
            .prop_map(|(identity_id, machine_id, role, added_at_ms)| GroupMember {
                identity_id,
                machine_id,
                role,
                added_at_ms,
            })
    }

    fn arb_group_id() -> impl Strategy<Value = GroupId> {
        proptest::array::uniform16(any::<u8>()).prop_map(GroupId)
    }

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn manifest_merge_commutative(
            gid in arb_group_id(),
            a_rest in ("[a-z]{1,8}", arb_identity_id(), proptest::collection::vec(arb_group_member(), 0..4), any::<u64>(), any::<u64>(), any::<u64>()),
            b_rest in ("[a-z]{1,8}", arb_identity_id(), proptest::collection::vec(arb_group_member(), 0..4), any::<u64>(), any::<u64>(), any::<u64>()),
        ) {
            let a = GroupManifest {
                group_id: gid,
                name: a_rest.0,
                creator: a_rest.1,
                members: a_rest.2,
                mls_epoch: a_rest.3,
                mls_state_blob: Vec::new(),
                created_at_ms: a_rest.4,
                updated_at_ms: a_rest.5,
            };
            let b = GroupManifest {
                group_id: gid,
                name: b_rest.0,
                creator: b_rest.1,
                members: b_rest.2,
                mls_epoch: b_rest.3,
                mls_state_blob: Vec::new(),
                created_at_ms: b_rest.4,
                updated_at_ms: b_rest.5,
            };
            let ab = merge_manifests(&a, &b);
            let ba = merge_manifests(&b, &a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn manifest_merge_idempotent(
            gid in arb_group_id(),
            rest in ("[a-z]{1,8}", arb_identity_id(), proptest::collection::vec(arb_group_member(), 0..4), any::<u64>(), any::<u64>(), any::<u64>()),
        ) {
            let a = GroupManifest {
                group_id: gid,
                name: rest.0,
                creator: rest.1,
                members: rest.2,
                mls_epoch: rest.3,
                mls_state_blob: Vec::new(),
                created_at_ms: rest.4,
                updated_at_ms: rest.5,
            };
            let mut expected = a.clone();
            crate::group::manifest::normalize_members(&mut expected);
            let aa = merge_manifests(&a, &a);
            prop_assert_eq!(aa, expected);
        }
    }
}

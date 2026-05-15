//! Permission table and check function for group actions.

use super::types::{GroupAction, Role};

/// Permission matrix as a const table.
/// Row index: Role ordinal (Owner=0, Admin=1, Moderator=2, Member=3).
/// Column index: GroupAction ordinal (SendMessage=0 .. DeleteGroup=5).
/// Special case: Moderator::RemoveMember is only permitted when target is Member.
pub const PERMISSION_TABLE: [[bool; 6]; 4] = [
    // Owner: all actions permitted
    [true, true, true, true, true, true],
    // Admin: SendMsg, AddMember, RemoveMember, PromoteDemoteMod; NOT PromoteDemoteAdmin or Delete
    [true, true, true, true, false, false],
    // Moderator: SendMsg, RemoveMember (Member only -- enforced in check_permission); nothing else
    [true, false, true, false, false, false],
    // Member: SendMsg only
    [true, false, false, false, false, false],
];

#[inline]
fn role_idx(r: Role) -> usize {
    match r {
        Role::Owner => 0,
        Role::Admin => 1,
        Role::Moderator => 2,
        Role::Member => 3,
    }
}

#[inline]
fn action_idx(a: GroupAction) -> usize {
    match a {
        GroupAction::SendMessage => 0,
        GroupAction::AddMember => 1,
        GroupAction::RemoveMember => 2,
        GroupAction::PromoteDemoteMod => 3,
        GroupAction::PromoteDemoteAdmin => 4,
        GroupAction::DeleteGroup => 5,
    }
}

/// Check whether `actor_role` may perform `action`.
///
/// `target_role` is consulted only for `RemoveMember`: a Moderator may remove
/// Members but not Moderators, Admins, or Owners.
pub fn check_permission(actor_role: Role, action: GroupAction, target_role: Option<Role>) -> bool {
    let permitted = PERMISSION_TABLE[role_idx(actor_role)][action_idx(action)];
    if !permitted {
        return false;
    }
    // Moderator can only remove plain Members, not peers or superiors.
    if actor_role == Role::Moderator && action == GroupAction::RemoveMember {
        return target_role == Some(Role::Member);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- targeted spec examples -----

    #[test]
    fn owner_deletes_group() {
        assert!(check_permission(
            Role::Owner,
            GroupAction::DeleteGroup,
            None
        ));
    }

    #[test]
    fn member_send_only() {
        assert!(check_permission(
            Role::Member,
            GroupAction::SendMessage,
            None
        ));
        assert!(!check_permission(
            Role::Member,
            GroupAction::AddMember,
            None
        ));
        assert!(!check_permission(
            Role::Member,
            GroupAction::RemoveMember,
            Some(Role::Member)
        ));
        assert!(!check_permission(
            Role::Member,
            GroupAction::PromoteDemoteMod,
            None
        ));
        assert!(!check_permission(
            Role::Member,
            GroupAction::PromoteDemoteAdmin,
            None
        ));
        assert!(!check_permission(
            Role::Member,
            GroupAction::DeleteGroup,
            None
        ));
    }

    #[test]
    fn moderator_remove_target_role_matrix() {
        // Mod may remove a Member
        assert!(check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Member)
        ));
        // Mod may NOT remove a Moderator, Admin, or Owner
        assert!(!check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            Some(Role::Moderator)
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
        // Mod may NOT remove when target_role is None
        assert!(!check_permission(
            Role::Moderator,
            GroupAction::RemoveMember,
            None
        ));
    }

    #[test]
    fn admin_remove_target_role_coverage() {
        // Admin can remove anyone (table says true; no extra restriction for Admin)
        assert!(check_permission(
            Role::Admin,
            GroupAction::RemoveMember,
            Some(Role::Member)
        ));
        assert!(check_permission(
            Role::Admin,
            GroupAction::RemoveMember,
            Some(Role::Moderator)
        ));
        // Admin removing Owner is allowed by the table (Owner-level enforcement is caller-side)
        assert!(check_permission(
            Role::Admin,
            GroupAction::RemoveMember,
            Some(Role::Owner)
        ));
    }

    #[test]
    fn admin_promotes_admin_denied() {
        assert!(!check_permission(
            Role::Admin,
            GroupAction::PromoteDemoteAdmin,
            None
        ));
    }

    #[test]
    fn owner_remove_any_target() {
        for target in [Role::Owner, Role::Admin, Role::Moderator, Role::Member] {
            assert!(
                check_permission(Role::Owner, GroupAction::RemoveMember, Some(target)),
                "Owner should be able to remove {target:?}"
            );
        }
    }

    /// Exhaustive 4x6 check: verifies every cell of PERMISSION_TABLE matches
    /// the check_permission return value (ignoring the Mod/RemoveMember special case).
    #[test]
    fn exhaustive_table_check() {
        let roles = [Role::Owner, Role::Admin, Role::Moderator, Role::Member];
        let actions = [
            GroupAction::SendMessage,
            GroupAction::AddMember,
            GroupAction::RemoveMember,
            GroupAction::PromoteDemoteMod,
            GroupAction::PromoteDemoteAdmin,
            GroupAction::DeleteGroup,
        ];

        for (ri, &role) in roles.iter().enumerate() {
            for (ai, &action) in actions.iter().enumerate() {
                let table_val = PERMISSION_TABLE[ri][ai];

                if role == Role::Moderator && action == GroupAction::RemoveMember {
                    // Special case: table says true but target_role gates the result.
                    assert!(table_val, "table must be true for Mod/RemoveMember row");
                    // With Member target -> permitted
                    assert!(check_permission(role, action, Some(Role::Member)));
                    // With non-Member target -> denied
                    assert!(!check_permission(role, action, Some(Role::Admin)));
                } else {
                    // For all other cells use None target (not consulted).
                    let got = check_permission(role, action, None);
                    assert_eq!(
                        got, table_val,
                        "mismatch at Role={role:?} Action={action:?}: table={table_val} got={got}"
                    );
                }
            }
        }
    }
}

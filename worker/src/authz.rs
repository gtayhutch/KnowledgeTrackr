//! Authorization decisions for company knowledge.
//!
//! D1 does not enforce row access. Every read and write calls [`authorize`]
//! with the caller's membership in the company being touched.

use serde::{Deserialize, Serialize};

/// A person who has presented a live session, or nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// No session cookie, or the session is expired or revoked.
    SignedOut,
    /// A signed-in user. Membership is loaded separately per company.
    User { user_id: String },
}

/// Role inside one company.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads and writes that company's articles and files.
    Member,
    /// Member rights, plus membership changes and company rename.
    Admin,
}

/// The caller's relationship to one company.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// Company the row belongs to.
    pub company_id: String,
    /// User the row belongs to.
    pub user_id: String,
    /// What that user may do in the company.
    pub role: Role,
}

/// An action on one company's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read the company name and the caller's role.
    ReadCompany,
    /// Change the company name.
    UpdateCompany,
    /// Add or change a member.
    ManageMembers,
    /// List or open articles and their files.
    ReadArticle,
    /// Create, edit, or delete articles and files.
    WriteArticle,
}

/// Why [`authorize`] refused an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The request had no usable session.
    SignedOut,
    /// The session's user is not a member of this company.
    NotAMember,
    /// The user is a member, and this action is reserved for admins.
    NotAnAdmin,
    /// The session is older than the window required for this action.
    ReauthenticationRequired,
}

/// Returns whether `actor` may perform `action` on `company_id`.
///
/// `membership` is the actor's row in that company, when one exists.
/// `session_age_ms` is how long ago the session was created.
/// Admin membership changes require a session younger than
/// [`crate::limits::REAUTH_WINDOW_MS`].
pub fn authorize(
    actor: &Actor,
    company_id: &str,
    membership: Option<&Membership>,
    action: Action,
    session_age_ms: i64,
) -> Result<(), Denial> {
    let Actor::User { user_id } = actor else {
        return Err(Denial::SignedOut);
    };
    let Some(membership) = membership else {
        return Err(Denial::NotAMember);
    };
    if membership.company_id != company_id || &membership.user_id != user_id {
        return Err(Denial::NotAMember);
    }
    match action {
        Action::ReadCompany | Action::ReadArticle | Action::WriteArticle => Ok(()),
        Action::UpdateCompany | Action::ManageMembers => {
            if membership.role != Role::Admin {
                return Err(Denial::NotAnAdmin);
            }
            if session_age_ms > crate::limits::REAUTH_WINDOW_MS {
                return Err(Denial::ReauthenticationRequired);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::REAUTH_WINDOW_MS;

    fn member(role: Role) -> Membership {
        Membership {
            company_id: "company-1".to_string(),
            user_id: "user-1".to_string(),
            role,
        }
    }

    fn user() -> Actor {
        Actor::User {
            user_id: "user-1".to_string(),
        }
    }

    #[test]
    fn signed_out_callers_are_denied() {
        let denial = authorize(&Actor::SignedOut, "company-1", None, Action::ReadArticle, 0);
        assert_eq!(denial, Err(Denial::SignedOut));
    }

    #[test]
    fn a_member_reads_and_writes_articles() {
        let membership = member(Role::Member);
        assert!(authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::ReadArticle,
            0
        )
        .is_ok());
        assert!(authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::WriteArticle,
            REAUTH_WINDOW_MS + 1
        )
        .is_ok());
    }

    #[test]
    fn a_member_cannot_manage_members() {
        let membership = member(Role::Member);
        let denial = authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::ManageMembers,
            0,
        );
        assert_eq!(denial, Err(Denial::NotAnAdmin));
    }

    #[test]
    fn an_admin_manages_members_inside_the_reauth_window() {
        let membership = member(Role::Admin);
        assert!(authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::ManageMembers,
            REAUTH_WINDOW_MS
        )
        .is_ok());
    }

    #[test]
    fn an_old_admin_session_must_sign_in_again() {
        let membership = member(Role::Admin);
        let denial = authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::UpdateCompany,
            REAUTH_WINDOW_MS + 1,
        );
        assert_eq!(denial, Err(Denial::ReauthenticationRequired));
    }

    #[test]
    fn another_companys_membership_does_not_apply() {
        let mut membership = member(Role::Admin);
        membership.company_id = "company-2".to_string();
        let denial = authorize(
            &user(),
            "company-1",
            Some(&membership),
            Action::ReadArticle,
            0,
        );
        assert_eq!(denial, Err(Denial::NotAMember));
    }

    #[test]
    fn a_user_without_a_membership_is_denied() {
        let denial = authorize(&user(), "company-1", None, Action::ReadCompany, 0);
        assert_eq!(denial, Err(Denial::NotAMember));
    }
}

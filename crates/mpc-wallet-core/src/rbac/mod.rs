//! Role-Based Access Control (RBAC) for MPC wallet operations (Epic A).
//!
//! Defines API roles, authorization context, and permission checks that gate
//! access to signing sessions, key management, and administrative operations.

use crate::error::CoreError;

/// API roles that can be assigned to authenticated users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiRole {
    /// Can initiate signing sessions and submit transactions.
    Initiator,
    /// Can approve pending signing sessions (maker/checker separation).
    Approver,
    /// Full administrative access: policy management, key rotation, freeze/unfreeze.
    Admin,
}

/// Authorization context extracted from a validated identity token.
///
/// Produced by [`crate::identity::JwtValidator::validate`] and consumed by
/// permission-checking functions like [`require_role`] and [`require_any_role`].
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Unique user identifier (from JWT `sub` claim).
    pub user_id: String,
    /// Roles assigned to this user.
    pub roles: Vec<ApiRole>,
}

impl AuthContext {
    /// Create a new authorization context.
    pub fn new(user_id: String, roles: Vec<ApiRole>) -> Self {
        Self { user_id, roles }
    }

    /// Check whether this context includes the given role.
    pub fn has_role(&self, role: ApiRole) -> bool {
        self.roles.contains(&role)
    }
}

/// Require that the auth context has the specified role.
///
/// Returns `Err(CoreError::Unauthorized)` if the role is missing.
pub fn require_role(ctx: &AuthContext, role: ApiRole) -> Result<(), CoreError> {
    if ctx.has_role(role) {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(format!(
            "user '{}' lacks required role: {:?}",
            ctx.user_id, role
        )))
    }
}

/// Require that the auth context has at least one of the specified roles.
///
/// Returns `Err(CoreError::Unauthorized)` if none of the roles are present.
pub fn require_any_role(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), CoreError> {
    if roles.iter().any(|r| ctx.has_role(*r)) {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(format!(
            "user '{}' lacks any of the required roles: {:?}",
            ctx.user_id, roles
        )))
    }
}

/// Permission flags for fine-grained access control.
#[derive(Debug, Clone, Default)]
pub struct Permissions {
    pub can_initiate_signing: bool,
    pub can_approve_signing: bool,
    pub can_manage_policies: bool,
    pub can_manage_keys: bool,
    pub can_freeze_keys: bool,
}

impl Permissions {
    /// Derive permissions from the roles in an auth context.
    pub fn from_context(ctx: &AuthContext) -> Self {
        let mut perms = Permissions::default();
        for role in &ctx.roles {
            match role {
                ApiRole::Initiator => {
                    perms.can_initiate_signing = true;
                }
                ApiRole::Approver => {
                    perms.can_approve_signing = true;
                }
                ApiRole::Admin => {
                    perms.can_initiate_signing = true;
                    perms.can_approve_signing = true;
                    perms.can_manage_policies = true;
                    perms.can_manage_keys = true;
                    perms.can_freeze_keys = true;
                }
            }
        }
        perms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_role_passes() {
        let ctx = AuthContext::new("alice".into(), vec![ApiRole::Initiator]);
        assert!(require_role(&ctx, ApiRole::Initiator).is_ok());
    }

    #[test]
    fn test_require_role_fails() {
        let ctx = AuthContext::new("alice".into(), vec![ApiRole::Initiator]);
        assert!(require_role(&ctx, ApiRole::Admin).is_err());
    }

    #[test]
    fn test_require_any_role_passes() {
        let ctx = AuthContext::new("bob".into(), vec![ApiRole::Approver]);
        assert!(require_any_role(&ctx, &[ApiRole::Initiator, ApiRole::Approver]).is_ok());
    }

    #[test]
    fn test_require_any_role_fails() {
        let ctx = AuthContext::new("bob".into(), vec![ApiRole::Approver]);
        assert!(require_any_role(&ctx, &[ApiRole::Admin]).is_err());
    }

    #[test]
    fn test_permissions_from_admin() {
        let ctx = AuthContext::new("admin".into(), vec![ApiRole::Admin]);
        let perms = Permissions::from_context(&ctx);
        assert!(perms.can_initiate_signing);
        assert!(perms.can_approve_signing);
        assert!(perms.can_manage_policies);
        assert!(perms.can_manage_keys);
        assert!(perms.can_freeze_keys);
    }
}

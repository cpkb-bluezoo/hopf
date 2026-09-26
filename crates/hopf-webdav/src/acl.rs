// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 3744 WebDAV ACL live properties and privilege evaluation.

use std::io;
use std::sync::Arc;

use hopf_auth::RolePolicy;

use crate::constants::{
    ELEM_ABSTRACT, ELEM_ACE, ELEM_ALL, ELEM_AUTHENTICATED, ELEM_DESCRIPTION, ELEM_GRANT,
    ELEM_PRINCIPAL, ELEM_PRIVILEGE, ELEM_SUPPORTED_PRIVILEGE, ELEM_WRITE, PRIV_BIND, PRIV_READ,
    PRIV_READ_ACL, PRIV_READ_CURRENT_USER_PRIVILEGE_SET, PRIV_UNBIND, PRIV_UNLOCK,
    PRIV_WRITE_ACL, PRIV_WRITE_CONTENT, PRIV_WRITE_PROPERTIES, PROP_ACL,
    PROP_CURRENT_USER_PRIVILEGE_SET, PROP_GROUP, PROP_OWNER, PROP_PRINCIPAL_COLLECTION_SET,
    PROP_SUPPORTED_PRIVILEGE_SET, ROLE_PREFIX,
};
use crate::xml_out::{dav_element_text, dav_end, dav_empty, dav_start, DavWriter};

/// Per-request RFC 3744 state.
#[derive(Clone)]
pub(crate) struct AclContext {
    pub enabled: bool,
    pub username: Option<String>,
    pub roles: Option<Arc<dyn RolePolicy>>,
}

impl AclContext {
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            username: None,
            roles: None,
        }
    }
}

const LEAF_PRIVILEGES: &[&str] = &[
    PRIV_READ,
    PRIV_WRITE_PROPERTIES,
    PRIV_WRITE_CONTENT,
    PRIV_UNLOCK,
    PRIV_READ_ACL,
    PRIV_READ_CURRENT_USER_PRIVILEGE_SET,
    PRIV_WRITE_ACL,
    PRIV_BIND,
    PRIV_UNBIND,
];

pub(crate) fn acl_live_property_names() -> &'static [&'static str] {
    &[
        PROP_OWNER,
        PROP_GROUP,
        PROP_SUPPORTED_PRIVILEGE_SET,
        PROP_CURRENT_USER_PRIVILEGE_SET,
        PROP_ACL,
        PROP_PRINCIPAL_COLLECTION_SET,
    ]
}

fn has_privilege(roles: &dyn RolePolicy, username: Option<&str>, privilege_local: &str) -> bool {
    let Some(username) = username else {
        return false;
    };
    if roles.is_user_in_role(username, &format!("{ROLE_PREFIX}{ELEM_ALL}")) {
        return true;
    }
    roles.is_user_in_role(username, &format!("{ROLE_PREFIX}{privilege_local}"))
}

fn has_write_privilege(roles: &dyn RolePolicy, username: Option<&str>) -> bool {
    if has_privilege(roles, username, ELEM_WRITE) {
        return true;
    }
    has_privilege(roles, username, PRIV_WRITE_PROPERTIES)
        && has_privilege(roles, username, PRIV_WRITE_CONTENT)
        && has_privilege(roles, username, PRIV_BIND)
        && has_privilege(roles, username, PRIV_UNBIND)
}

fn write_privilege(w: &mut DavWriter, local: &str) -> io::Result<()> {
    dav_start(w, ELEM_PRIVILEGE)?;
    dav_empty(w, local)?;
    dav_end(w)
}

fn write_current_user_privilege_set(
    w: &mut DavWriter,
    roles: &dyn RolePolicy,
    username: Option<&str>,
) -> io::Result<()> {
    if has_privilege(roles, username, ELEM_ALL) {
        write_privilege(w, ELEM_ALL)?;
        return Ok(());
    }
    if has_write_privilege(roles, username) {
        write_privilege(w, ELEM_WRITE)?;
    }
    for p in LEAF_PRIVILEGES {
        if has_privilege(roles, username, p) {
            write_privilege(w, p)?;
        }
    }
    Ok(())
}

fn write_acl(w: &mut DavWriter, roles: &dyn RolePolicy, username: Option<&str>) -> io::Result<()> {
    let Some(username) = username else {
        return Ok(());
    };
    let mut granted: Vec<&str> = Vec::new();
    if has_privilege(roles, Some(username), ELEM_ALL) {
        granted.push(ELEM_ALL);
    } else {
        if has_write_privilege(roles, Some(username)) {
            granted.push(ELEM_WRITE);
        }
        for p in LEAF_PRIVILEGES {
            if has_privilege(roles, Some(username), p) {
                granted.push(p);
            }
        }
    }
    if granted.is_empty() {
        return Ok(());
    }
    dav_start(w, ELEM_ACE)?;
    dav_start(w, ELEM_PRINCIPAL)?;
    dav_empty(w, ELEM_AUTHENTICATED)?;
    dav_end(w)?;
    dav_start(w, ELEM_GRANT)?;
    for p in granted {
        write_privilege(w, p)?;
    }
    dav_end(w)?;
    dav_end(w)
}

fn write_supported_privilege(w: &mut DavWriter, local: &str, description: &str) -> io::Result<()> {
    dav_start(w, ELEM_SUPPORTED_PRIVILEGE)?;
    write_privilege(w, local)?;
    dav_element_text(w, ELEM_DESCRIPTION, description)?;
    dav_end(w)
}

fn write_abstract_supported_privilege(
    w: &mut DavWriter,
    local: &str,
    description: &str,
) -> io::Result<()> {
    dav_start(w, ELEM_SUPPORTED_PRIVILEGE)?;
    write_privilege(w, local)?;
    dav_empty(w, ELEM_ABSTRACT)?;
    dav_element_text(w, ELEM_DESCRIPTION, description)?;
    dav_end(w)
}

fn write_supported_privilege_set(w: &mut DavWriter) -> io::Result<()> {
    dav_start(w, ELEM_SUPPORTED_PRIVILEGE)?;
    write_privilege(w, ELEM_ALL)?;
    dav_empty(w, ELEM_ABSTRACT)?;
    dav_element_text(w, ELEM_DESCRIPTION, "All privileges")?;

    dav_start(w, ELEM_SUPPORTED_PRIVILEGE)?;
    write_privilege(w, PRIV_READ)?;
    dav_element_text(w, ELEM_DESCRIPTION, "Read")?;
    write_abstract_supported_privilege(w, PRIV_READ_ACL, "Read ACL")?;
    write_abstract_supported_privilege(
        w,
        PRIV_READ_CURRENT_USER_PRIVILEGE_SET,
        "Read current user privilege set",
    )?;
    dav_end(w)?;

    dav_start(w, ELEM_SUPPORTED_PRIVILEGE)?;
    write_privilege(w, ELEM_WRITE)?;
    dav_element_text(w, ELEM_DESCRIPTION, "Write")?;
    write_supported_privilege(w, PRIV_WRITE_PROPERTIES, "Write properties")?;
    write_supported_privilege(w, PRIV_WRITE_CONTENT, "Write content")?;
    write_supported_privilege(w, PRIV_BIND, "Add member (bind)")?;
    write_supported_privilege(w, PRIV_UNBIND, "Remove member (unbind)")?;
    write_abstract_supported_privilege(w, PRIV_WRITE_ACL, "Write ACL")?;
    write_supported_privilege(w, PRIV_UNLOCK, "Unlock")?;
    dav_end(w)?;

    dav_end(w)
}

/// RFC 3744 §5 live properties inside an open `<D:prop>`.
pub(crate) fn write_acl_live_properties(
    w: &mut DavWriter,
    ctx: &AclContext,
) -> Result<(), u16> {
    if !ctx.enabled {
        return Ok(());
    }
    let roles = ctx.roles.as_deref().ok_or(500u16)?;
    let username = ctx.username.as_deref();

    io_result(dav_empty(w, PROP_OWNER))?;
    io_result(dav_empty(w, PROP_GROUP))?;

    io_result(dav_start(w, PROP_SUPPORTED_PRIVILEGE_SET))?;
    io_result(write_supported_privilege_set(w))?;
    io_result(dav_end(w))?;

    io_result(dav_start(w, PROP_CURRENT_USER_PRIVILEGE_SET))?;
    io_result(write_current_user_privilege_set(w, roles, username))?;
    io_result(dav_end(w))?;

    io_result(dav_start(w, PROP_ACL))?;
    io_result(write_acl(w, roles, username))?;
    io_result(dav_end(w))?;

    io_result(dav_empty(w, PROP_PRINCIPAL_COLLECTION_SET))?;
    Ok(())
}

fn io_result(r: io::Result<()>) -> Result<(), u16> {
    r.map_err(|_| 500u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_auth::RoleMembership;

    fn ctx_for(username: Option<&str>, roles: RoleMembership) -> AclContext {
        AclContext {
            enabled: true,
            username: username.map(|s| s.to_string()),
            roles: Some(roles.shared()),
        }
    }

    fn privilege_xml(username: Option<&str>, roles: RoleMembership) -> String {
        let mut w = crate::xml_out::PropXmlWriter::new_vec();
        let ctx = ctx_for(username, roles);
        let roles_ref = ctx.roles.as_deref().unwrap();
        dav_start(&mut w, PROP_CURRENT_USER_PRIVILEGE_SET).unwrap();
        write_current_user_privilege_set(&mut w, roles_ref, ctx.username.as_deref()).unwrap();
        dav_end(&mut w).unwrap();
        let _ = w.flush();
        String::from_utf8(w.into_inner()).unwrap()
    }

    #[test]
    fn current_user_privilege_set_reflects_roles() {
        let roles = RoleMembership::new()
            .with_role("alice", "webdav:read")
            .with_role("alice", "webdav:write");
        let xml = privilege_xml(Some("alice"), roles);
        assert!(xml.contains("read"));
        assert!(xml.contains("write"));
    }

    #[test]
    fn current_user_privilege_set_empty_without_auth() {
        let roles = RoleMembership::new().with_role("alice", "webdav:read");
        let xml = privilege_xml(None, roles);
        assert!(!xml.contains(":read"));
        assert!(!xml.contains(":write"));
        assert!(!xml.contains(":all"));
    }

    #[test]
    fn all_role_grants_all_privilege() {
        let roles = RoleMembership::new().with_role("erin", "webdav:all");
        let xml = privilege_xml(Some("erin"), roles);
        assert!(xml.contains("all"));
    }
}

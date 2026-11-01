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

/// The privileges that contain `privilege` in the supported-privilege-set
/// tree below: holding one of these holds `privilege` too (RFC 3744 section 3).
fn containers(privilege: &str) -> &'static [&'static str] {
    match privilege {
        ELEM_ALL => &[],
        PRIV_READ | ELEM_WRITE => &[ELEM_ALL],
        PRIV_READ_ACL | PRIV_READ_CURRENT_USER_PRIVILEGE_SET => &[PRIV_READ, ELEM_ALL],
        _ => &[ELEM_WRITE, ELEM_ALL],
    }
}

fn has_role(roles: &dyn RolePolicy, username: &str, privilege_local: &str) -> bool {
    roles.is_user_in_role(username, &format!("{ROLE_PREFIX}{privilege_local}"))
}

/// Does `username` hold `privilege_local`: by a role for it, or for a
/// privilege that contains it?
fn has_privilege(roles: &dyn RolePolicy, username: Option<&str>, privilege_local: &str) -> bool {
    let Some(username) = username else {
        return false;
    };
    has_role(roles, username, privilege_local)
        || containers(privilege_local).iter().any(|c| has_role(roles, username, c))
}

/// `write` is held outright, or by holding each of the privileges it is
/// made of.
fn has_write_privilege(roles: &dyn RolePolicy, username: Option<&str>) -> bool {
    if has_privilege(roles, username, ELEM_WRITE) {
        return true;
    }
    has_privilege(roles, username, PRIV_WRITE_PROPERTIES)
        && has_privilege(roles, username, PRIV_WRITE_CONTENT)
        && has_privilege(roles, username, PRIV_BIND)
        && has_privilege(roles, username, PRIV_UNBIND)
}

/// Every privilege `username` holds, aggregates first, in a stable order.
fn held_privileges(roles: &dyn RolePolicy, username: Option<&str>) -> Vec<&'static str> {
    let mut held = Vec::new();
    if has_privilege(roles, username, ELEM_ALL) {
        held.push(ELEM_ALL);
    }
    if has_privilege(roles, username, PRIV_READ) {
        held.push(PRIV_READ);
    }
    if has_write_privilege(roles, username) {
        held.push(ELEM_WRITE);
    }
    held.extend(LEAF_PRIVILEGES.iter().copied().filter(|p| *p != PRIV_READ && has_privilege(roles, username, p)));
    held
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
    for p in held_privileges(roles, username) {
        write_privilege(w, p)?;
    }
    Ok(())
}

fn write_acl(w: &mut DavWriter, roles: &dyn RolePolicy, username: Option<&str>) -> io::Result<()> {
    let granted = held_privileges(roles, username);
    if username.is_none() || granted.is_empty() {
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

    /// The live properties for `username` as one string.
    fn live_xml(username: Option<&str>, roles: RoleMembership) -> String {
        let mut w = crate::xml_out::PropXmlWriter::new_vec();
        let ctx = ctx_for(username, roles);
        write_acl_live_properties(&mut w, &ctx).unwrap();
        let _ = w.flush();
        String::from_utf8(w.into_inner()).unwrap()
    }

    /// The privilege names (`<privilege><name/></privilege>`) in `xml`, in order.
    fn privileges_in(xml: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = xml;
        while let Some(i) = rest.find("privilege>") {
            rest = &rest[i + "privilege>".len()..];
            if let Some(start) = rest.find('<') {
                let tail = &rest[start + 1..];
                if let Some(end) = tail.find("/>") {
                    let name = &tail[..end];
                    if !name.contains('<') && !name.starts_with('/') {
                        out.push(name.rsplit(':').next().unwrap().to_string());
                    }
                }
            }
        }
        out
    }

    /// Just the `current-user-privilege-set` part, as privilege names.
    fn granted(username: Option<&str>, roles: RoleMembership) -> Vec<String> {
        let xml = privilege_xml(username, roles);
        privileges_in(&xml)
    }

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

    fn has(v: &[String], name: &str) -> bool {
        v.iter().any(|p| p == name)
    }

    #[test]
    fn nothing_is_granted_to_a_user_with_no_roles_or_to_nobody() {
        assert!(granted(Some("alice"), RoleMembership::new()).is_empty());
        assert!(granted(None, RoleMembership::new().with_role("alice", "webdav:all")).is_empty());
    }

    #[test]
    fn read_includes_the_privileges_that_hang_off_it() {
        // The supported-privilege-set puts read-acl and
        // read-current-user-privilege-set under read: holding read holds them.
        let g = granted(Some("alice"), RoleMembership::new().with_role("alice", "webdav:read"));
        for p in ["read", "read-acl", "read-current-user-privilege-set"] {
            assert!(has(&g, p), "{p} in {g:?}");
        }
        for p in ["write", "write-content", "bind", "unbind", "all"] {
            assert!(!has(&g, p), "{p} not in {g:?}");
        }
    }

    #[test]
    fn write_includes_the_privileges_that_hang_off_it() {
        let g = granted(Some("alice"), RoleMembership::new().with_role("alice", "webdav:write"));
        for p in ["write", "write-properties", "write-content", "bind", "unbind", "write-acl", "unlock"] {
            assert!(has(&g, p), "{p} in {g:?}");
        }
        assert!(!has(&g, "read") && !has(&g, "all"), "{g:?}");
    }

    #[test]
    fn all_is_every_privilege() {
        let g = granted(Some("erin"), RoleMembership::new().with_role("erin", "webdav:all"));
        for p in [
            "all", "read", "read-acl", "read-current-user-privilege-set", "write", "write-properties",
            "write-content", "bind", "unbind", "write-acl", "unlock",
        ] {
            assert!(has(&g, p), "{p} in {g:?}");
        }
    }

    #[test]
    fn a_single_leaf_privilege_is_only_that_privilege() {
        let g = granted(Some("alice"), RoleMembership::new().with_role("alice", "webdav:write-content"));
        assert_eq!(g, ["write-content"]);
    }

    #[test]
    fn holding_all_the_write_leaves_is_holding_write() {
        let roles = RoleMembership::new()
            .with_role("alice", "webdav:write-properties")
            .with_role("alice", "webdav:write-content")
            .with_role("alice", "webdav:bind")
            .with_role("alice", "webdav:unbind");
        let g = granted(Some("alice"), roles);
        assert!(has(&g, "write"), "{g:?}");
        let partial = RoleMembership::new()
            .with_role("alice", "webdav:write-properties")
            .with_role("alice", "webdav:write-content")
            .with_role("alice", "webdav:bind");
        assert!(!has(&granted(Some("alice"), partial), "write"));
    }

    #[test]
    fn privileges_are_per_user() {
        let roles = RoleMembership::new().with_role("alice", "webdav:read").with_role("bob", "webdav:write");
        assert!(has(&granted(Some("alice"), roles.clone()), "read"));
        assert!(!has(&granted(Some("bob"), roles.clone()), "read"));
        assert!(!has(&granted(Some("carol"), roles), "read"));
    }

    #[test]
    fn roles_without_the_webdav_prefix_grant_nothing() {
        let roles = RoleMembership::new().with_role("alice", "read").with_role("alice", "admin");
        assert!(granted(Some("alice"), roles).is_empty());
    }

    #[test]
    fn the_live_properties_are_all_present_in_order() {
        let xml = live_xml(Some("alice"), RoleMembership::new().with_role("alice", "webdav:read"));
        let positions: Vec<usize> = ["owner", "group", "supported-privilege-set", "current-user-privilege-set", "acl", "principal-collection-set"]
            .iter()
            .map(|n| xml.find(&format!(":{n}")).unwrap_or_else(|| panic!("{n} missing in {xml}")))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?} in {xml}");
    }

    #[test]
    fn the_supported_privilege_set_describes_the_whole_tree() {
        let xml = live_xml(Some("alice"), RoleMembership::new());
        let set = &xml[xml.find("supported-privilege-set").unwrap()..xml.rfind("supported-privilege-set").unwrap()];
        for p in [
            "all", "read", "read-acl", "read-current-user-privilege-set", "write", "write-properties",
            "write-content", "bind", "unbind", "write-acl", "unlock",
        ] {
            assert!(set.contains(&format!(":{p}/>")), "{p} missing from {set}");
        }
        assert!(set.contains("All privileges") && set.contains("Write content"));
        // every <supported-privilege> that opens is closed again
        assert_eq!(set.matches("<D:supported-privilege>").count(), set.matches("</D:supported-privilege>").count(), "{set}");
        // all is abstract
        let all = &set[..set.find("Read").unwrap()];
        assert!(all.contains(":abstract/>"), "{all}");
    }

    #[test]
    fn the_acl_property_names_what_the_current_user_may_do() {
        let xml = live_xml(Some("alice"), RoleMembership::new().with_role("alice", "webdav:read"));
        let acl = &xml[xml.find("<D:acl>").unwrap()..xml.find("</D:acl>").unwrap()];
        assert!(acl.contains("<D:ace>") && acl.contains(":authenticated/>") && acl.contains("<D:grant>"), "{acl}");
        assert!(acl.contains(":read/>"), "{acl}");
        assert!(!acl.contains(":write/>"), "{acl}");
    }

    #[test]
    fn the_acl_property_is_empty_without_privileges_or_a_user() {
        for (user, roles) in [
            (None, RoleMembership::new().with_role("alice", "webdav:all")),
            (Some("alice"), RoleMembership::new()),
        ] {
            let xml = live_xml(user, roles);
            assert!(!xml.contains("<D:ace>"), "{xml}");
        }
    }

    #[test]
    fn nothing_is_written_when_acl_is_disabled() {
        let mut w = crate::xml_out::PropXmlWriter::new_vec();
        let ctx = AclContext { enabled: false, username: Some("alice".into()), roles: None };
        write_acl_live_properties(&mut w, &ctx).unwrap();
        let _ = w.flush();
        assert!(w.into_inner().is_empty());
    }

    #[test]
    fn enabled_acl_without_a_role_policy_is_a_server_error() {
        let mut w = crate::xml_out::PropXmlWriter::new_vec();
        let ctx = AclContext { enabled: true, username: Some("alice".into()), roles: None };
        assert_eq!(write_acl_live_properties(&mut w, &ctx), Err(500));
    }

    #[test]
    fn the_property_name_list_matches_what_is_written() {
        let xml = live_xml(Some("alice"), RoleMembership::new());
        for name in acl_live_property_names() {
            assert!(xml.contains(&format!(":{name}")), "{name} not written in {xml}");
        }
        assert_eq!(acl_live_property_names().len(), 6);
    }
}

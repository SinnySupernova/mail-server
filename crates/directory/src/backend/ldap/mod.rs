/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed::Pool;
use ldap3::{
    asn1::{StructureTag, PL},
    ldap_escape, LdapConnSettings, ResultEntry,
};
use std::fmt;
use store::Store;

pub mod config;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    auth_bind: Option<AuthBind>,
    pub(crate) data_store: Store,
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_name: LdapFilter,
    filter_email: LdapFilter,
    attr_name: Vec<String>,
    attr_type: Vec<String>,
    attr_groups: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_email_address: Vec<String>,
    attr_email_alias: Vec<String>,
    attr_quota: Vec<String>,
    attrs_principal: Vec<String>,
}

#[derive(Debug, Default)]
struct LdapFilter {
    filter: Vec<String>,
}

impl LdapFilter {
    pub fn build(&self, value: &str) -> String {
        let value = ldap_escape(value);
        self.filter.join(value.as_ref())
    }
}

pub(crate) struct LdapConnectionManager {
    address: String,
    settings: LdapConnSettings,
    bind_dn: Option<Bind>,
}

pub(crate) struct Bind {
    dn: String,
    password: String,
}

impl LdapConnectionManager {
    pub fn new(address: String, settings: LdapConnSettings, bind_dn: Option<Bind>) -> Self {
        Self {
            address,
            settings,
            bind_dn,
        }
    }
}

impl Bind {
    pub fn new(dn: String, password: String) -> Self {
        Self { dn, password }
    }
}

pub(crate) struct AuthBind {
    filter: LdapFilter,
    search: bool,
}

pub struct DisplayableResultEntry<'a>(&'a ResultEntry);

impl<'a> fmt::Display for DisplayableResultEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let structure_tag = &self.0 .0;
        write!(f, "{}", DisplayableStructureTag(structure_tag))
    }
}

pub struct DisplayableStructureTag<'a>(&'a StructureTag);

impl<'a> fmt::Display for DisplayableStructureTag<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StructureTag {{ class: {:?}, id: {}",
            self.0.class, self.0.id
        )?;
        match &self.0.payload {
            PL::P(data) => {
                if let Ok(string) = String::from_utf8(data.clone()) {
                    write!(f, ", payload: \"{}\"", string)?;
                } else {
                    write!(f, ", payload: {data:?}")?;
                }
            }
            PL::C(tags) => {
                write!(
                    f,
                    ", payload: [{}]",
                    tags.into_iter()
                        .map(|tag| DisplayableStructureTag(&tag).to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                )?;
            }
        };
        write!(f, "}}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3::asn1::TagClass;

    #[test]
    fn test_displayable_result_entry_with_primitive_payload() {
        let tag = StructureTag {
            class: TagClass::Universal,
            id: 1,
            payload: PL::P(vec![72, 101, 108, 108, 111]), // "Hello"
        };

        let entry = ResultEntry::new(tag);

        let displayable_entry = DisplayableResultEntry(&entry);

        let expected_output = "StructureTag { class: Universal, id: 1, payload: \"Hello\"}";

        assert_eq!(displayable_entry.to_string(), expected_output);
    }

    #[test]
    fn test_displayable_result_entry_with_constructed_payload() {
        let nested_tag1 = StructureTag {
            class: TagClass::Universal,
            id: 2,
            payload: PL::P(vec![72, 101, 108, 108, 111]), // "Hello"
        };

        let nested_tag2 = StructureTag {
            class: TagClass::Universal,
            id: 3,
            payload: PL::P(vec![87, 111, 114, 108, 100]), // "World"
        };

        let main_tag = StructureTag {
            class: TagClass::Universal,
            id: 1,
            payload: PL::C(vec![nested_tag1, nested_tag2]),
        };

        let entry = ResultEntry::new(main_tag);

        let displayable_entry = DisplayableResultEntry(&entry);

        let expected_output = "StructureTag { class: Universal, id: 1, payload: [StructureTag { class: Universal, id: 2, payload: \"Hello\"}, StructureTag { class: Universal, id: 3, payload: \"World\"}]}";

        assert_eq!(displayable_entry.to_string(), expected_output);
    }
}

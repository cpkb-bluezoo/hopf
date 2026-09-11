// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Decoded ASN.1 element (tag, length, value / children).

use super::error::Asn1Error;
use super::types::Asn1Type;
use std::fmt;

/// A decoded ASN.1 element.
///
/// An ASN.1 element consists of a tag, length, and value. For constructed
/// types, the value contains child elements. For primitive types, the value
/// contains raw bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Asn1Element {
    tag: u8,
    value: Option<Vec<u8>>,
    children: Option<Vec<Asn1Element>>,
}

impl Asn1Element {
    /// Creates a primitive element.
    pub fn primitive(tag: u8, value: Vec<u8>) -> Self {
        Self {
            tag,
            value: Some(value),
            children: None,
        }
    }

    /// Creates a constructed element.
    pub fn constructed(tag: u8, children: Vec<Asn1Element>) -> Self {
        Self {
            tag,
            value: None,
            children: Some(children),
        }
    }

    /// Returns the tag byte.
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Returns the tag class.
    pub fn tag_class(&self) -> u8 {
        Asn1Type::tag_class(self.tag)
    }

    /// Returns the tag number (0–30).
    pub fn tag_number(&self) -> u8 {
        Asn1Type::tag_number(self.tag)
    }

    /// Returns whether this element is constructed.
    pub fn is_constructed(&self) -> bool {
        Asn1Type::is_constructed(self.tag)
    }

    /// Returns the raw value bytes, or `None` for constructed elements.
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// Returns the child elements, or `None` for primitive elements.
    pub fn children(&self) -> Option<&[Asn1Element]> {
        self.children.as_deref()
    }

    /// Returns the number of children, or 0 for primitive elements.
    pub fn child_count(&self) -> usize {
        self.children.as_ref().map_or(0, Vec::len)
    }

    /// Returns a specific child element.
    ///
    /// # Panics
    ///
    /// Panics if this is a primitive element or `index` is out of range.
    pub fn child(&self, index: usize) -> &Asn1Element {
        match &self.children {
            None => panic!("Primitive element has no children"),
            Some(children) => &children[index],
        }
    }

    /// Returns the value as a boolean.
    pub fn as_bool(&self) -> Result<bool, Asn1Error> {
        match &self.value {
            Some(v) if v.len() == 1 => Ok(v[0] != 0),
            _ => Err(Asn1Error::new("Invalid BOOLEAN encoding")),
        }
    }

    /// Returns the value as a 32-bit integer.
    pub fn as_i32(&self) -> Result<i32, Asn1Error> {
        let value = match &self.value {
            Some(v) if !v.is_empty() && v.len() <= 4 => v.as_slice(),
            _ => return Err(Asn1Error::new("Invalid INTEGER encoding")),
        };
        let mut result: u32 = 0;
        for &b in value {
            result = (result << 8) | u32::from(b);
        }
        // Sign extension (matches Gumdrop ASN1Element.asInt)
        if (value[0] & 0x80) != 0 {
            for i in value.len()..4 {
                result |= 0xFF_u32 << (i * 8);
            }
        }
        Ok(result as i32)
    }

    /// Returns the value as a 64-bit integer.
    pub fn as_i64(&self) -> Result<i64, Asn1Error> {
        let value = match &self.value {
            Some(v) if !v.is_empty() && v.len() <= 8 => v.as_slice(),
            _ => return Err(Asn1Error::new("Invalid INTEGER encoding")),
        };
        let mut result: u64 = 0;
        for &b in value {
            result = (result << 8) | u64::from(b);
        }
        // Sign extension (matches Gumdrop ASN1Element.asLong)
        if (value[0] & 0x80) != 0 {
            for i in value.len()..8 {
                result |= 0xFF_u64 << (i * 8);
            }
        }
        Ok(result as i64)
    }

    /// Returns the value as a UTF-8 string, or `None` for constructed elements.
    ///
    /// Invalid UTF-8 is replaced with the Unicode replacement character,
    /// matching Java's `new String(bytes, UTF_8)` lossy behaviour for typical
    /// printable LDAP content; use [`Self::value`] for exact bytes.
    pub fn as_string(&self) -> Option<String> {
        self.value
            .as_ref()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// Returns the value as an octet string (raw bytes).
    pub fn as_octet_string(&self) -> Option<&[u8]> {
        self.value()
    }
}

impl fmt::Display for Asn1Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indent(f, 0)
    }
}

impl fmt::Debug for Asn1Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Asn1Element {
    fn fmt_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        for _ in 0..indent {
            write!(f, "  ")?;
        }
        write!(f, "{}", Asn1Type::tag_name(self.tag))?;
        if self.is_constructed() {
            if let Some(children) = &self.children {
                writeln!(f, " {{")?;
                for child in children {
                    child.fmt_indent(f, indent + 1)?;
                }
                for _ in 0..indent {
                    write!(f, "  ")?;
                }
                writeln!(f, "}}")?;
            } else {
                writeln!(f)?;
            }
        } else if let Some(value) = &self.value {
            write!(f, " = ")?;
            if value.len() <= 32 {
                let printable = value.iter().all(|&b| (0x20..=0x7E).contains(&b));
                if printable {
                    write!(f, "\"{}\"", self.as_string().unwrap_or_default())?;
                } else {
                    write!(f, "{}", hex_dump(value))?;
                }
            } else {
                write!(f, "[{} bytes]", value.len())?;
            }
            writeln!(f)?;
        } else {
            writeln!(f)?;
        }
        Ok(())
    }
}

fn hex_dump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::Asn1Element;
    use crate::asn1::types::Asn1Type;

    #[test]
    fn primitive_element() {
        let value = vec![0x01, 0x02, 0x03];
        let element = Asn1Element::primitive(Asn1Type::OCTET_STRING, value.clone());
        assert_eq!(element.tag(), Asn1Type::OCTET_STRING);
        assert_eq!(element.value(), Some(value.as_slice()));
        assert!(element.children().is_none());
        assert!(!element.is_constructed());
    }

    #[test]
    fn primitive_element_empty_value() {
        let element = Asn1Element::primitive(Asn1Type::NULL, Vec::new());
        assert_eq!(element.tag(), Asn1Type::NULL);
        assert_eq!(element.value().unwrap().len(), 0);
    }

    #[test]
    fn constructed_element() {
        let children = vec![
            Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]),
            Asn1Element::primitive(Asn1Type::INTEGER, vec![0x02]),
        ];
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, children);
        assert_eq!(element.tag(), Asn1Type::SEQUENCE);
        assert!(element.is_constructed());
        assert!(element.value().is_none());
        assert!(element.children().is_some());
        assert_eq!(element.child_count(), 2);
    }

    #[test]
    fn constructed_element_empty_children() {
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, Vec::new());
        assert_eq!(element.child_count(), 0);
    }

    #[test]
    fn get_tag_class_universal() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]);
        assert_eq!(element.tag_class(), Asn1Type::CLASS_UNIVERSAL);
    }

    #[test]
    fn get_tag_class_context() {
        let context_tag = Asn1Type::context_tag(5, false);
        let element = Asn1Element::primitive(context_tag, vec![0x01]);
        assert_eq!(element.tag_class(), Asn1Type::CLASS_CONTEXT);
    }

    #[test]
    fn get_tag_class_application() {
        let app_tag = Asn1Type::application_tag(3, true);
        let element = Asn1Element::constructed(app_tag, Vec::new());
        assert_eq!(element.tag_class(), Asn1Type::CLASS_APPLICATION);
    }

    #[test]
    fn get_tag_number() {
        let int_element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]);
        assert_eq!(int_element.tag_number(), 2);

        let ctx_tag7 = Asn1Type::context_tag(7, false);
        let ctx_element = Asn1Element::primitive(ctx_tag7, vec![0x01]);
        assert_eq!(ctx_element.tag_number(), 7);
    }

    #[test]
    fn as_bool_true() {
        let element = Asn1Element::primitive(Asn1Type::BOOLEAN, vec![0xFF]);
        assert!(element.as_bool().unwrap());
    }

    #[test]
    fn as_bool_false() {
        let element = Asn1Element::primitive(Asn1Type::BOOLEAN, vec![0x00]);
        assert!(!element.as_bool().unwrap());
    }

    #[test]
    fn as_bool_non_zero() {
        let element = Asn1Element::primitive(Asn1Type::BOOLEAN, vec![0x01]);
        assert!(element.as_bool().unwrap());
    }

    #[test]
    fn as_bool_invalid_length() {
        let element = Asn1Element::primitive(Asn1Type::BOOLEAN, vec![0x00, 0x01]);
        assert!(element.as_bool().is_err());
    }

    #[test]
    fn as_i32_positive() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x2A]);
        assert_eq!(element.as_i32().unwrap(), 42);
    }

    #[test]
    fn as_i32_negative() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0xFF]);
        assert_eq!(element.as_i32().unwrap(), -1);
    }

    #[test]
    fn as_i32_two_bytes() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01, 0x00]);
        assert_eq!(element.as_i32().unwrap(), 256);
    }

    #[test]
    fn as_i32_four_bytes() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(element.as_i32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn as_i32_negative_two_bytes() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0xFF, 0x00]);
        assert_eq!(element.as_i32().unwrap(), -256);
    }

    #[test]
    fn as_i32_empty() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, Vec::new());
        assert!(element.as_i32().is_err());
    }

    #[test]
    fn as_i64() {
        let element = Asn1Element::primitive(
            Asn1Type::INTEGER,
            vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(element.as_i64().unwrap(), 0x1_0000_0000);
    }

    #[test]
    fn as_string() {
        let element = Asn1Element::primitive(Asn1Type::OCTET_STRING, b"hello".to_vec());
        assert_eq!(element.as_string().as_deref(), Some("hello"));
    }

    #[test]
    fn as_string_empty() {
        let element = Asn1Element::primitive(Asn1Type::OCTET_STRING, Vec::new());
        assert_eq!(element.as_string().as_deref(), Some(""));
    }

    #[test]
    fn as_string_none_for_constructed() {
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, Vec::new());
        assert!(element.as_string().is_none());
    }

    #[test]
    fn as_octet_string() {
        let value = vec![0x01, 0x02, 0x03];
        let element = Asn1Element::primitive(Asn1Type::OCTET_STRING, value.clone());
        assert_eq!(element.as_octet_string(), Some(value.as_slice()));
    }

    #[test]
    fn get_child() {
        let children = vec![
            Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]),
            Asn1Element::primitive(Asn1Type::INTEGER, vec![0x02]),
            Asn1Element::primitive(Asn1Type::INTEGER, vec![0x03]),
        ];
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, children);
        assert_eq!(element.child(0).as_i32().unwrap(), 1);
        assert_eq!(element.child(1).as_i32().unwrap(), 2);
        assert_eq!(element.child(2).as_i32().unwrap(), 3);
    }

    #[test]
    #[should_panic]
    fn get_child_out_of_bounds() {
        let children = vec![Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01])];
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, children);
        let _ = element.child(5);
    }

    #[test]
    #[should_panic(expected = "Primitive element has no children")]
    fn get_child_from_primitive() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]);
        let _ = element.child(0);
    }

    #[test]
    fn get_child_count_primitive() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01]);
        assert_eq!(element.child_count(), 0);
    }

    #[test]
    fn to_string_primitive() {
        let element = Asn1Element::primitive(Asn1Type::INTEGER, vec![0x2A]);
        let s = element.to_string();
        assert!(s.contains("INTEGER"));
    }

    #[test]
    fn to_string_octet_string() {
        let element = Asn1Element::primitive(Asn1Type::OCTET_STRING, b"test".to_vec());
        let s = element.to_string();
        assert!(s.contains("OCTET STRING"));
        assert!(s.contains("test"));
    }

    #[test]
    fn to_string_constructed() {
        let children = vec![Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01])];
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, children);
        let s = element.to_string();
        assert!(s.contains("SEQUENCE"));
        assert!(s.contains("INTEGER"));
    }

    #[test]
    fn to_string_context_tag() {
        let ctx_tag = Asn1Type::context_tag(3, false);
        let element = Asn1Element::primitive(ctx_tag, vec![0x01]);
        let s = element.to_string();
        assert!(s.contains("CONTEXT"));
        assert!(s.contains('3'));
    }

    #[test]
    fn children_list_owned_copy() {
        let mut children = vec![Asn1Element::primitive(Asn1Type::INTEGER, vec![0x01])];
        let element = Asn1Element::constructed(Asn1Type::SEQUENCE, children.clone());
        children.push(Asn1Element::primitive(Asn1Type::INTEGER, vec![0x02]));
        assert_eq!(element.child_count(), 1);
    }
}

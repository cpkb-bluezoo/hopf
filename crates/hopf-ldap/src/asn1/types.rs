// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ASN.1 type constants and tag manipulation utilities.
//!
//! ASN.1 tags are encoded as follows:
//!
//! ```text
//! Bits 7-6: Class
//!   00 = Universal
//!   01 = Application
//!   10 = Context-specific
//!   11 = Private
//!
//! Bit 5: Primitive/Constructed
//!   0 = Primitive
//!   1 = Constructed
//!
//! Bits 4-0: Tag number (0-30, or 31 for multi-byte tag)
//! ```

/// ASN.1 type constants and tag manipulation utilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Type;

impl Asn1Type {
    // Tag classes (bits 7-6)
    /// Universal class (00).
    pub const CLASS_UNIVERSAL: u8 = 0x00;
    /// Application class (01).
    pub const CLASS_APPLICATION: u8 = 0x40;
    /// Context-specific class (10).
    pub const CLASS_CONTEXT: u8 = 0x80;
    /// Private class (11).
    pub const CLASS_PRIVATE: u8 = 0xC0;

    // Primitive/Constructed flag (bit 5)
    /// Primitive encoding.
    pub const PRIMITIVE: u8 = 0x00;
    /// Constructed encoding.
    pub const CONSTRUCTED: u8 = 0x20;

    // Universal type tags
    /// End-of-contents marker.
    pub const EOC: u8 = 0x00;
    /// Boolean type.
    pub const BOOLEAN: u8 = 0x01;
    /// Integer type.
    pub const INTEGER: u8 = 0x02;
    /// Bit string type.
    pub const BIT_STRING: u8 = 0x03;
    /// Octet string type.
    pub const OCTET_STRING: u8 = 0x04;
    /// Null type.
    pub const NULL: u8 = 0x05;
    /// Object identifier type.
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    /// Object descriptor type.
    pub const OBJECT_DESCRIPTOR: u8 = 0x07;
    /// External type.
    pub const EXTERNAL: u8 = 0x08;
    /// Real (floating point) type.
    pub const REAL: u8 = 0x09;
    /// Enumerated type.
    pub const ENUMERATED: u8 = 0x0A;
    /// Embedded PDV type.
    pub const EMBEDDED_PDV: u8 = 0x0B;
    /// UTF-8 string type.
    pub const UTF8_STRING: u8 = 0x0C;
    /// Relative OID type.
    pub const RELATIVE_OID: u8 = 0x0D;
    /// Sequence type (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// Set type (constructed).
    pub const SET: u8 = 0x31;
    /// Numeric string type.
    pub const NUMERIC_STRING: u8 = 0x12;
    /// Printable string type.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// T61 (Teletex) string type.
    pub const T61_STRING: u8 = 0x14;
    /// Videotex string type.
    pub const VIDEOTEX_STRING: u8 = 0x15;
    /// IA5 string type.
    pub const IA5_STRING: u8 = 0x16;
    /// UTC time type.
    pub const UTC_TIME: u8 = 0x17;
    /// Generalized time type.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// Graphic string type.
    pub const GRAPHIC_STRING: u8 = 0x19;
    /// Visible (ISO646) string type.
    pub const VISIBLE_STRING: u8 = 0x1A;
    /// General string type.
    pub const GENERAL_STRING: u8 = 0x1B;
    /// Universal string type.
    pub const UNIVERSAL_STRING: u8 = 0x1C;
    /// Character string type.
    pub const CHARACTER_STRING: u8 = 0x1D;
    /// BMP (Basic Multilingual Plane) string type.
    pub const BMP_STRING: u8 = 0x1E;

    const CLASS_MASK: u8 = 0xC0;
    const CONSTRUCTED_MASK: u8 = 0x20;
    const TAG_MASK: u8 = 0x1F;

    /// Returns the class of the given tag.
    pub fn tag_class(tag: u8) -> u8 {
        tag & Self::CLASS_MASK
    }

    /// Returns whether the tag indicates a constructed type.
    pub fn is_constructed(tag: u8) -> bool {
        (tag & Self::CONSTRUCTED_MASK) != 0
    }

    /// Returns the tag number portion of the tag (0–30, or 31 for multi-byte).
    pub fn tag_number(tag: u8) -> u8 {
        tag & Self::TAG_MASK
    }

    /// Creates a context-specific tag.
    pub fn context_tag(tag_number: u8, constructed: bool) -> u8 {
        Self::CLASS_CONTEXT
            | if constructed {
                Self::CONSTRUCTED
            } else {
                Self::PRIMITIVE
            }
            | tag_number
    }

    /// Creates an application-specific tag.
    pub fn application_tag(tag_number: u8, constructed: bool) -> u8 {
        Self::CLASS_APPLICATION
            | if constructed {
                Self::CONSTRUCTED
            } else {
                Self::PRIMITIVE
            }
            | tag_number
    }

    /// Returns a human-readable name for the tag.
    pub fn tag_name(tag: u8) -> String {
        let tag_class = Self::tag_class(tag);
        if tag_class == Self::CLASS_UNIVERSAL {
            match tag & !Self::CONSTRUCTED_MASK {
                Self::BOOLEAN => "BOOLEAN".to_string(),
                Self::INTEGER => "INTEGER".to_string(),
                Self::BIT_STRING => "BIT STRING".to_string(),
                Self::OCTET_STRING => "OCTET STRING".to_string(),
                Self::NULL => "NULL".to_string(),
                Self::OBJECT_IDENTIFIER => "OBJECT IDENTIFIER".to_string(),
                Self::ENUMERATED => "ENUMERATED".to_string(),
                Self::UTF8_STRING => "UTF8String".to_string(),
                n if n == (Self::SEQUENCE & Self::TAG_MASK) => "SEQUENCE".to_string(),
                n if n == (Self::SET & Self::TAG_MASK) => "SET".to_string(),
                Self::PRINTABLE_STRING => "PrintableString".to_string(),
                Self::IA5_STRING => "IA5String".to_string(),
                Self::UTC_TIME => "UTCTime".to_string(),
                Self::GENERALIZED_TIME => "GeneralizedTime".to_string(),
                _ => format!("UNIVERSAL {}", Self::tag_number(tag)),
            }
        } else {
            let class_name = match tag_class {
                Self::CLASS_APPLICATION => "APPLICATION",
                Self::CLASS_CONTEXT => "CONTEXT",
                Self::CLASS_PRIVATE => "PRIVATE",
                _ => "UNKNOWN",
            };
            let kind = if Self::is_constructed(tag) {
                "constructed"
            } else {
                "primitive"
            };
            format!("{class_name} {} ({kind})", Self::tag_number(tag))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Asn1Type;

    #[test]
    fn get_tag_class_universal() {
        assert_eq!(Asn1Type::tag_class(Asn1Type::INTEGER), Asn1Type::CLASS_UNIVERSAL);
        assert_eq!(Asn1Type::tag_class(Asn1Type::BOOLEAN), Asn1Type::CLASS_UNIVERSAL);
        assert_eq!(
            Asn1Type::tag_class(Asn1Type::OCTET_STRING),
            Asn1Type::CLASS_UNIVERSAL
        );
        assert_eq!(Asn1Type::tag_class(Asn1Type::SEQUENCE), Asn1Type::CLASS_UNIVERSAL);
    }

    #[test]
    fn get_tag_class_application() {
        let app_tag = Asn1Type::application_tag(5, false);
        assert_eq!(Asn1Type::tag_class(app_tag), Asn1Type::CLASS_APPLICATION);
    }

    #[test]
    fn get_tag_class_context() {
        let ctx_tag = Asn1Type::context_tag(3, false);
        assert_eq!(Asn1Type::tag_class(ctx_tag), Asn1Type::CLASS_CONTEXT);
    }

    #[test]
    fn is_constructed_primitive() {
        assert!(!Asn1Type::is_constructed(Asn1Type::INTEGER));
        assert!(!Asn1Type::is_constructed(Asn1Type::BOOLEAN));
        assert!(!Asn1Type::is_constructed(Asn1Type::OCTET_STRING));
    }

    #[test]
    fn is_constructed_sequence() {
        assert!(Asn1Type::is_constructed(Asn1Type::SEQUENCE));
        assert!(Asn1Type::is_constructed(Asn1Type::SET));
    }

    #[test]
    fn is_constructed_context_tags() {
        let primitive_ctx = Asn1Type::context_tag(0, false);
        let constructed_ctx = Asn1Type::context_tag(0, true);
        assert!(!Asn1Type::is_constructed(primitive_ctx));
        assert!(Asn1Type::is_constructed(constructed_ctx));
    }

    #[test]
    fn get_tag_number() {
        assert_eq!(Asn1Type::tag_number(Asn1Type::INTEGER), 2);
        assert_eq!(Asn1Type::tag_number(Asn1Type::BOOLEAN), 1);
        assert_eq!(Asn1Type::tag_number(Asn1Type::OCTET_STRING), 4);
        assert_eq!(Asn1Type::tag_number(Asn1Type::SEQUENCE), 16);
    }

    #[test]
    fn get_tag_number_context() {
        assert_eq!(Asn1Type::tag_number(Asn1Type::context_tag(5, false)), 5);
        assert_eq!(Asn1Type::tag_number(Asn1Type::context_tag(0, true)), 0);
    }

    #[test]
    fn context_tag() {
        assert_eq!(Asn1Type::context_tag(0, false), 0x80);
        assert_eq!(Asn1Type::context_tag(0, true), 0xA0);
        assert_eq!(Asn1Type::context_tag(3, false), 0x83);
        assert_eq!(Asn1Type::context_tag(7, true), 0xA7);
    }

    #[test]
    fn application_tag() {
        assert_eq!(Asn1Type::application_tag(0, false), 0x40);
        assert_eq!(Asn1Type::application_tag(0, true), 0x60);
        assert_eq!(Asn1Type::application_tag(3, false), 0x43);
    }

    #[test]
    fn get_tag_name_universal() {
        assert_eq!(Asn1Type::tag_name(Asn1Type::BOOLEAN), "BOOLEAN");
        assert_eq!(Asn1Type::tag_name(Asn1Type::INTEGER), "INTEGER");
        assert_eq!(Asn1Type::tag_name(Asn1Type::OCTET_STRING), "OCTET STRING");
        assert_eq!(Asn1Type::tag_name(Asn1Type::SEQUENCE), "SEQUENCE");
        assert_eq!(Asn1Type::tag_name(Asn1Type::SET), "SET");
        assert_eq!(Asn1Type::tag_name(Asn1Type::NULL), "NULL");
        assert_eq!(Asn1Type::tag_name(Asn1Type::ENUMERATED), "ENUMERATED");
    }

    #[test]
    fn get_tag_name_context() {
        let name = Asn1Type::tag_name(Asn1Type::context_tag(3, false));
        assert!(name.contains("CONTEXT"));
        assert!(name.contains('3'));
        assert!(name.contains("primitive"));

        let name2 = Asn1Type::tag_name(Asn1Type::context_tag(5, true));
        assert!(name2.contains("CONTEXT"));
        assert!(name2.contains('5'));
        assert!(name2.contains("constructed"));
    }

    #[test]
    fn get_tag_name_application() {
        let name = Asn1Type::tag_name(Asn1Type::application_tag(0, true));
        assert!(name.contains("APPLICATION"));
        assert!(name.contains('0'));
    }

    #[test]
    fn universal_type_constants() {
        assert_eq!(Asn1Type::BOOLEAN, 0x01);
        assert_eq!(Asn1Type::INTEGER, 0x02);
        assert_eq!(Asn1Type::BIT_STRING, 0x03);
        assert_eq!(Asn1Type::OCTET_STRING, 0x04);
        assert_eq!(Asn1Type::NULL, 0x05);
        assert_eq!(Asn1Type::OBJECT_IDENTIFIER, 0x06);
        assert_eq!(Asn1Type::ENUMERATED, 0x0A);
        assert_eq!(Asn1Type::UTF8_STRING, 0x0C);
        assert_eq!(Asn1Type::SEQUENCE, 0x30);
        assert_eq!(Asn1Type::SET, 0x31);
    }

    #[test]
    fn class_constants() {
        assert_eq!(Asn1Type::CLASS_UNIVERSAL, 0x00);
        assert_eq!(Asn1Type::CLASS_APPLICATION, 0x40);
        assert_eq!(Asn1Type::CLASS_CONTEXT, 0x80);
        assert_eq!(Asn1Type::CLASS_PRIVATE, 0xC0);
    }

    #[test]
    fn constructed_constant() {
        assert_eq!(Asn1Type::CONSTRUCTED, 0x20);
        assert_eq!(Asn1Type::PRIMITIVE, 0x00);
    }
}

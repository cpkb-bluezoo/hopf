// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-based parser for `.proto` files (proto2 and proto3 subset).
//!
//! - `import` statements are skipped (path consumed, not resolved); the
//!   `google.protobuf` well-known types are built in and added to the
//!   [`ProtoFile`] when a field or rpc refers to them
//! - options are parsed and discarded, except `json_name` (kept on the field)
//!   and `allow_alias` (which permits enum aliases)
//! - type names are resolved once the whole file has been read, innermost
//!   scope first, so a type can be used before it is declared

use std::collections::HashSet;

use super::{
    EnumDescriptor, FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ProtoParseError,
    RpcDescriptor, ServiceDescriptor,
};

const MAX_FIELD_NUMBER: i64 = 536_870_911;
const MAX_NESTING: usize = 64;

/// Push-based parser for `.proto` files.
pub struct ProtoFileParser {
    input: String,
    /// Bytes of an incomplete UTF-8 sequence at the end of the last chunk.
    partial: Vec<u8>,
    pos: usize,
    line: i32,
    column: i32,
    closed: bool,
    syntax: String,
    depth: usize,
    defined: HashSet<String>,
}

impl Default for ProtoFileParser {
    fn default() -> Self {
        Self::new()
    }
}

/// A constant on the right of an option; only strings and booleans are kept.
enum Constant {
    Str(String),
    Bool(bool),
    Other,
}

/// Numbers and names claimed by `reserved` statements.
#[derive(Default)]
struct Reserved {
    ranges: Vec<(i64, i64)>,
    names: HashSet<String>,
}

impl Reserved {
    fn merge(&mut self, other: Reserved) {
        self.ranges.extend(other.ranges);
        self.names.extend(other.names);
    }

    fn has_number(&self, n: i64) -> bool {
        self.ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&n))
    }
}

/// Field numbers and names used so far in a message, oneofs included.
#[derive(Default)]
struct FieldSet {
    numbers: HashSet<i32>,
    names: HashSet<String>,
    entries: Vec<(String, i32)>,
}

impl ProtoFileParser {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            partial: Vec::new(),
            pos: 0,
            line: 1,
            column: 1,
            closed: false,
            syntax: "proto3".to_string(),
            depth: 0,
            defined: HashSet::new(),
        }
    }

    /// Pushes bytes into the parser (UTF-8). A character may be split
    /// across calls.
    pub fn receive(&mut self, data: &[u8]) {
        if self.closed {
            panic!("Parser already closed");
        }
        self.partial.extend_from_slice(data);
        loop {
            match std::str::from_utf8(&self.partial) {
                Ok(s) => {
                    self.input.push_str(s);
                    self.partial.clear();
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    self.input
                        .push_str(&String::from_utf8_lossy(&self.partial[..valid]));
                    match e.error_len() {
                        // The tail is the start of a character not yet complete.
                        None => {
                            self.partial.drain(..valid);
                            break;
                        }
                        Some(n) => {
                            self.input.push('\u{FFFD}');
                            self.partial.drain(..valid + n);
                        }
                    }
                }
            }
        }
    }

    /// Parses the accumulated input and returns the Proto model.
    pub fn close(mut self) -> Result<ProtoFile, ProtoParseError> {
        if self.closed {
            panic!("Parser already closed");
        }
        self.closed = true;
        if !self.partial.is_empty() {
            self.input.push('\u{FFFD}');
            self.partial.clear();
        }
        self.parse_internal()
    }

    /// Parses a `.proto` file from a character sequence.
    pub fn parse(source: &str) -> Result<ProtoFile, ProtoParseError> {
        let mut parser = ProtoFileParser::new();
        parser.input.push_str(source);
        parser.closed = true;
        parser.parse_internal()
    }

    fn parse_internal(&mut self) -> Result<ProtoFile, ProtoParseError> {
        self.pos = 0;
        self.line = 1;
        self.column = 1;
        self.depth = 0;
        self.syntax = "proto3".to_string();
        self.defined.clear();

        let mut pkg = String::new();
        let mut messages: Vec<MessageDescriptor> = Vec::new();
        let mut enums: Vec<EnumDescriptor> = Vec::new();
        let mut services: Vec<ServiceDescriptor> = Vec::new();

        loop {
            self.skip_whitespace_and_comments()?;
            match self.peek() {
                None => break,
                Some(';') => {
                    self.consume()?;
                    continue;
                }
                Some(_) => {}
            }

            let tok = self.next_identifier()?.ok_or_else(|| self.unexpected())?;
            match tok.as_str() {
                "syntax" => self.parse_syntax()?,
                "package" => pkg = self.parse_package()?,
                "import" => self.parse_import()?,
                "option" => {
                    self.parse_option()?;
                }
                "message" => messages.push(self.parse_message(&pkg)?),
                "enum" => enums.push(self.parse_enum(&pkg)?),
                "service" => services.push(self.parse_service(&pkg)?),
                other => {
                    return Err(self.parse_error(&format!("Unexpected '{other}'")));
                }
            }
        }

        let mut resolver = Resolver::new(&messages, &enums);
        for m in &mut messages {
            resolver.resolve_message(m);
        }
        for s in &mut services {
            resolver.resolve_service(s);
        }
        let (well_known_messages, well_known_enums) = resolver.well_known_used();
        messages.extend(well_known_messages);
        enums.extend(well_known_enums);

        let mut file_builder = ProtoFile::builder()
            .package_name(pkg)
            .syntax(self.syntax.clone());
        for m in messages {
            file_builder = file_builder.add_message(m);
        }
        for e in enums {
            file_builder = file_builder.add_enum(e);
        }
        for s in services {
            file_builder = file_builder.add_service(s);
        }
        Ok(file_builder.build())
    }

    fn parse_syntax(&mut self) -> Result<(), ProtoParseError> {
        self.expect('=')?;
        let val = self.next_string()?;
        match val.as_deref() {
            Some(v @ ("proto3" | "proto2")) => self.syntax = v.to_string(),
            _ => return Err(self.parse_error("Invalid syntax declaration")),
        }
        self.expect(';')?;
        Ok(())
    }

    fn parse_package(&mut self) -> Result<String, ProtoParseError> {
        let full_ident = self
            .next_full_ident()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect(';')?;
        Ok(full_ident)
    }

    fn parse_import(&mut self) -> Result<(), ProtoParseError> {
        // Imports are skipped, not resolved.
        if let Some(modifier) = self.next_identifier()? {
            if modifier != "public" && modifier != "weak" {
                return Err(self.parse_error("Invalid import"));
            }
        }
        if self.next_string()?.is_none() {
            return Err(self.parse_error("Expected string"));
        }
        self.expect(';')?;
        Ok(())
    }

    /// Parses `name = constant;` after the `option` keyword.
    fn parse_option(&mut self) -> Result<(String, Constant), ProtoParseError> {
        let name = self.next_option_name()?;
        self.expect('=')?;
        let value = self.parse_constant()?;
        self.expect(';')?;
        Ok((name, value))
    }

    /// An option name: `deprecated`, `(my.option)`, `(my.option).sub.path`.
    fn next_option_name(&mut self) -> Result<String, ProtoParseError> {
        let mut name = String::new();
        loop {
            self.skip_whitespace_and_comments()?;
            if self.peek() == Some('(') {
                self.consume()?;
                let ext = self
                    .next_type_name()?
                    .ok_or_else(|| self.parse_error("Expected identifier"))?;
                self.expect(')')?;
                name.push('(');
                name.push_str(&ext);
                name.push(')');
            } else {
                let part = self
                    .next_identifier()?
                    .ok_or_else(|| self.parse_error("Expected identifier"))?;
                name.push_str(&part);
            }
            self.skip_whitespace_and_comments()?;
            if self.peek() == Some('.') {
                self.consume()?;
                name.push('.');
            } else {
                return Ok(name);
            }
        }
    }

    fn parse_constant(&mut self) -> Result<Constant, ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        match self.peek() {
            Some('"') | Some('\'') => {
                let mut s = self.next_string()?.unwrap_or_default();
                // Adjacent string literals concatenate.
                loop {
                    self.skip_whitespace_and_comments()?;
                    if matches!(self.peek(), Some('"') | Some('\'')) {
                        s.push_str(&self.next_string()?.unwrap_or_default());
                    } else {
                        return Ok(Constant::Str(s));
                    }
                }
            }
            Some('{') => {
                self.skip_aggregate()?;
                Ok(Constant::Other)
            }
            Some(c) if c == '-' || c == '+' || c == '.' || c.is_ascii_digit() => {
                self.skip_numeric()?;
                Ok(Constant::Other)
            }
            _ => match self.next_full_ident()?.as_deref() {
                Some("true") => Ok(Constant::Bool(true)),
                Some("false") => Ok(Constant::Bool(false)),
                Some(_) => Ok(Constant::Other),
                None => Err(self.parse_error("Expected constant")),
            },
        }
    }

    /// Skips a number in any notation (`-5`, `0x1F`, `1.5e-3`, `-inf`).
    fn skip_numeric(&mut self) -> Result<(), ProtoParseError> {
        if matches!(self.peek(), Some('-') | Some('+')) {
            self.consume()?;
        }
        if self.peek().is_some_and(|c| c.is_alphabetic()) {
            self.next_identifier()?;
            return Ok(());
        }
        let start = self.pos;
        let mut prev = ' ';
        while let Some(c) = self.peek() {
            let exponent_sign = (c == '+' || c == '-') && (prev == 'e' || prev == 'E');
            if !(c.is_ascii_alphanumeric() || c == '.' || exponent_sign) {
                break;
            }
            prev = c;
            self.consume()?;
        }
        if self.pos == start {
            return Err(self.parse_error("Expected number"));
        }
        Ok(())
    }

    /// Skips a `{ ... }` text-format value, braces inside strings included.
    fn skip_aggregate(&mut self) -> Result<(), ProtoParseError> {
        self.expect('{')?;
        let mut depth = 1usize;
        while depth > 0 {
            self.skip_whitespace_and_comments()?;
            match self.peek() {
                None => return Err(self.parse_error("Unterminated option value")),
                Some('"') | Some('\'') => {
                    self.next_string()?;
                }
                Some('{') => {
                    depth += 1;
                    self.consume()?;
                }
                Some('}') => {
                    depth -= 1;
                    self.consume()?;
                }
                Some(_) => {
                    self.consume()?;
                }
            }
        }
        Ok(())
    }

    fn define(&mut self, full_name: &str) -> Result<(), ProtoParseError> {
        if !self.defined.insert(full_name.to_string()) {
            return Err(self.parse_error(&format!("Duplicate definition of {full_name}")));
        }
        Ok(())
    }

    fn parse_message(&mut self, parent: &str) -> Result<MessageDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = join_name(parent, &name);
        self.define(&full_name)?;
        self.expect('{')?;
        if self.depth >= MAX_NESTING {
            return Err(self.parse_error("Messages nested too deeply"));
        }
        self.depth += 1;

        let mut msg_builder = MessageDescriptor::builder()
            .name(name)
            .full_name(full_name.clone());
        let mut fields = FieldSet::default();
        let mut reserved = Reserved::default();

        loop {
            self.skip_whitespace_and_comments()?;
            match self.peek() {
                None | Some('}') => break,
                Some(';') => {
                    self.consume()?;
                    continue;
                }
                Some('.') => {
                    let ty = self
                        .next_type_name()?
                        .ok_or_else(|| self.parse_error("Expected identifier"))?;
                    let field = self.parse_field(None, &full_name, &mut fields, ty)?;
                    msg_builder = msg_builder.add_field(field);
                    continue;
                }
                Some(_) => {}
            }

            let tok = self.next_identifier()?.ok_or_else(|| self.unexpected())?;
            match tok.as_str() {
                "option" => {
                    self.parse_option()?;
                }
                "reserved" => reserved.merge(self.parse_reserved(MAX_FIELD_NUMBER)?),
                "message" => {
                    let nested = self.parse_message(&full_name)?;
                    msg_builder = msg_builder.add_nested_message(nested);
                }
                "enum" => {
                    let nested_enum = self.parse_enum(&full_name)?;
                    msg_builder = msg_builder.add_nested_enum(nested_enum);
                }
                "oneof" => {
                    msg_builder = self.parse_oneof(msg_builder, &full_name, &mut fields)?;
                }
                "map" => {
                    let map_field = self.parse_map_field(&full_name, &mut fields)?;
                    msg_builder = msg_builder.add_field(map_field);
                }
                "repeated" | "optional" | "required" => {
                    let ty = self
                        .next_type_name()?
                        .ok_or_else(|| self.parse_error("Expected identifier"))?;
                    let field = self.parse_field(Some(&tok), &full_name, &mut fields, ty)?;
                    msg_builder = msg_builder.add_field(field);
                }
                _ => {
                    let ty = self.continue_full_ident(tok)?;
                    let field = self.parse_field(None, &full_name, &mut fields, ty)?;
                    msg_builder = msg_builder.add_field(field);
                }
            }
        }

        self.expect('}')?;
        self.depth -= 1;
        for (name, number) in &fields.entries {
            if reserved.has_number(i64::from(*number)) {
                return Err(self.parse_error(&format!(
                    "Field {name} uses reserved number {number} in message {full_name}"
                )));
            }
            if reserved.names.contains(name) {
                return Err(self.parse_error(&format!(
                    "Field name {name} is reserved in message {full_name}"
                )));
            }
        }
        Ok(msg_builder.build())
    }

    /// Parses the list after `reserved`: numbers, `a to b`, `a to max`, names.
    fn parse_reserved(&mut self, max: i64) -> Result<Reserved, ProtoParseError> {
        let mut reserved = Reserved::default();
        loop {
            self.skip_whitespace_and_comments()?;
            if matches!(self.peek(), Some('"') | Some('\'')) {
                let name = self.next_string()?.unwrap_or_default();
                reserved.names.insert(name);
            } else {
                let lo = self.next_number()?;
                let mut hi = lo;
                self.skip_whitespace_and_comments()?;
                if self.peek().is_some_and(|c| c.is_alphabetic()) {
                    if self.next_identifier()?.as_deref() != Some("to") {
                        return Err(self.parse_error("Expected 'to'"));
                    }
                    self.skip_whitespace_and_comments()?;
                    if self.peek().is_some_and(|c| c.is_alphabetic()) {
                        if self.next_identifier()?.as_deref() != Some("max") {
                            return Err(self.parse_error("Expected 'max'"));
                        }
                        hi = max;
                    } else {
                        hi = self.next_number()?;
                    }
                }
                reserved.ranges.push((lo, hi));
            }
            self.skip_whitespace_and_comments()?;
            if self.peek() == Some(',') {
                self.consume()?;
            } else {
                break;
            }
        }
        self.expect(';')?;
        Ok(reserved)
    }

    fn parse_oneof(
        &mut self,
        mut msg_builder: MessageDescriptorBuilderOwned,
        parent_full_name: &str,
        fields: &mut FieldSet,
    ) -> Result<MessageDescriptorBuilderOwned, ProtoParseError> {
        let _oneof_name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('{')?;
        loop {
            self.skip_whitespace_and_comments()?;
            let ty = match self.peek() {
                None | Some('}') => break,
                Some(';') => {
                    self.consume()?;
                    continue;
                }
                Some('.') => self
                    .next_type_name()?
                    .ok_or_else(|| self.parse_error("Expected identifier"))?,
                Some(_) => {
                    let tok = self.next_identifier()?.ok_or_else(|| self.unexpected())?;
                    if tok == "option" {
                        self.parse_option()?;
                        continue;
                    }
                    self.continue_full_ident(tok)?
                }
            };
            let field = self.parse_field(None, parent_full_name, fields, ty)?;
            msg_builder = msg_builder.add_field(field);
        }
        self.expect('}')?;
        Ok(msg_builder)
    }

    fn parse_map_field(
        &mut self,
        parent_full_name: &str,
        fields: &mut FieldSet,
    ) -> Result<FieldDescriptor, ProtoParseError> {
        self.expect('<')?;
        let key_type = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect(',')?;
        let value_type = self
            .next_type_name()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('>')?;
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('=')?;
        let num = self.next_field_number()?;
        self.register_field(fields, &name, num, parent_full_name)?;
        let json_name = self.parse_field_options()?;
        self.expect(';')?;

        // The key must be a scalar that can be compared; the value a scalar
        // or a message/enum name, resolved with the other type names later.
        match self.scalar_type_from_name(&key_type)? {
            FieldType::Double | FieldType::Float | FieldType::Bytes => {
                return Err(self.parse_error(&format!("Invalid map key type: {key_type}")));
            }
            _ => {}
        }
        if is_scalar_type(&value_type) {
            self.scalar_type_from_name(&value_type)?;
        }

        let mut b = FieldDescriptor::builder()
            .number(num)
            .name(name)
            .field_type(FieldType::Map)
            .key_type_name(key_type)
            .value_type_name(value_type);
        if let Some(j) = json_name {
            b = b.json_name(j);
        }
        Ok(b.build())
    }

    fn register_field(
        &self,
        fields: &mut FieldSet,
        name: &str,
        number: i32,
        parent_full_name: &str,
    ) -> Result<(), ProtoParseError> {
        if !fields.numbers.insert(number) {
            return Err(self.parse_error(&format!(
                "Duplicate field number {number} in message {parent_full_name}"
            )));
        }
        if !fields.names.insert(name.to_string()) {
            return Err(self.parse_error(&format!(
                "Duplicate field name {name} in message {parent_full_name}"
            )));
        }
        fields.entries.push((name.to_string(), number));
        Ok(())
    }

    fn parse_field(
        &mut self,
        modifier: Option<&str>,
        parent_full_name: &str,
        fields: &mut FieldSet,
        type_name: String,
    ) -> Result<FieldDescriptor, ProtoParseError> {
        let repeated = modifier == Some("repeated");
        let optional = modifier == Some("optional");

        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('=')?;
        let num = self.next_field_number()?;
        self.register_field(fields, &name, num, parent_full_name)?;
        let json_name = self.parse_field_options()?;
        self.expect(';')?;

        let mut b = FieldDescriptor::builder()
            .number(num)
            .name(name)
            .repeated(repeated)
            .optional(optional);
        if is_scalar_type(&type_name) {
            b = b.field_type(self.scalar_type_from_name(&type_name)?);
        } else {
            // Message or enum: told apart, and made absolute, once the whole
            // file has been read.
            b = b.field_type(FieldType::Message).message_type_name(type_name);
        }
        if let Some(j) = json_name {
            b = b.json_name(j);
        }
        Ok(b.build())
    }

    /// Parses `[a = 1, (b.c) = "x", ...]`, returning the `json_name` if given.
    fn parse_field_options(&mut self) -> Result<Option<String>, ProtoParseError> {
        let mut json_name = None;
        self.skip_whitespace_and_comments()?;
        if self.peek() == Some('[') {
            self.consume()?;
            loop {
                let name = self.next_option_name()?;
                self.expect('=')?;
                let value = self.parse_constant()?;
                if name == "json_name" {
                    if let Constant::Str(s) = value {
                        json_name = Some(s);
                    }
                }
                self.skip_whitespace_and_comments()?;
                if self.peek() == Some(',') {
                    self.consume()?;
                } else {
                    break;
                }
            }
            self.expect(']')?;
        }
        Ok(json_name)
    }

    fn parse_enum(&mut self, parent: &str) -> Result<EnumDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = join_name(parent, &name);
        self.define(&full_name)?;
        self.expect('{')?;

        let mut enum_builder = EnumDescriptor::builder()
            .name(name)
            .full_name(full_name.clone());
        let mut reserved = Reserved::default();
        let mut allow_alias = false;
        let mut names: HashSet<String> = HashSet::new();
        let mut numbers: HashSet<i32> = HashSet::new();
        let mut values: Vec<(String, i32)> = Vec::new();

        loop {
            self.skip_whitespace_and_comments()?;
            match self.peek() {
                None | Some('}') => break,
                Some(';') => {
                    self.consume()?;
                    continue;
                }
                Some(_) => {}
            }

            let tok = self.next_identifier()?.ok_or_else(|| self.unexpected())?;
            match tok.as_str() {
                "option" => {
                    let (name, value) = self.parse_option()?;
                    if name == "allow_alias" {
                        allow_alias = matches!(value, Constant::Bool(true));
                    }
                }
                "reserved" => reserved.merge(self.parse_reserved(i64::from(i32::MAX))?),
                _ => {
                    self.expect('=')?;
                    let num = self.next_enum_number()?;
                    self.parse_field_options()?;
                    self.expect(';')?;
                    if !names.insert(tok.clone()) {
                        return Err(self.parse_error(&format!(
                            "Duplicate enum value name {tok} in {full_name}"
                        )));
                    }
                    values.push((tok, num));
                }
            }
        }

        self.expect('}')?;
        for (value_name, num) in values {
            if !numbers.insert(num) && !allow_alias {
                return Err(self.parse_error(&format!(
                    "Enum {full_name} reuses number {num} without allow_alias"
                )));
            }
            if reserved.has_number(i64::from(num)) || reserved.names.contains(&value_name) {
                return Err(self.parse_error(&format!(
                    "Enum value {value_name} is reserved in {full_name}"
                )));
            }
            enum_builder = enum_builder.add_value(num, value_name);
        }
        Ok(enum_builder.build())
    }

    fn parse_service(&mut self, parent: &str) -> Result<ServiceDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = join_name(parent, &name);
        self.define(&full_name)?;
        self.expect('{')?;

        let mut svc_builder = ServiceDescriptor::builder().name(name).full_name(full_name);

        loop {
            self.skip_whitespace_and_comments()?;
            match self.peek() {
                None | Some('}') => break,
                Some(';') => {
                    self.consume()?;
                    continue;
                }
                Some(_) => {}
            }

            let tok = self.next_identifier()?.ok_or_else(|| self.unexpected())?;
            match tok.as_str() {
                "option" => {
                    self.parse_option()?;
                }
                "rpc" => {
                    let rpc = self.parse_rpc()?;
                    svc_builder = svc_builder.add_rpc(rpc);
                }
                other => return Err(self.parse_error(&format!("Unexpected '{other}'"))),
            }
        }

        self.expect('}')?;
        Ok(svc_builder.build())
    }

    /// `( [stream] Type )`: the type is left as written.
    fn parse_rpc_type(&mut self) -> Result<(bool, String), ProtoParseError> {
        self.expect('(')?;
        let mut streaming = false;
        let mut ty = self
            .next_type_name()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        if ty == "stream" {
            self.skip_whitespace_and_comments()?;
            // A message that is itself called `stream` is `(stream)`.
            if self.peek() != Some(')') {
                streaming = true;
                ty = self
                    .next_type_name()?
                    .ok_or_else(|| self.parse_error("Expected identifier"))?;
            }
        }
        self.expect(')')?;
        Ok((streaming, ty))
    }

    fn parse_rpc(&mut self) -> Result<RpcDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let (client_streaming, input_type) = self.parse_rpc_type()?;
        if self.next_identifier()?.as_deref() != Some("returns") {
            return Err(self.parse_error("Invalid rpc definition"));
        }
        let (server_streaming, output_type) = self.parse_rpc_type()?;

        self.skip_whitespace_and_comments()?;
        if self.peek() == Some('{') {
            self.consume()?;
            loop {
                self.skip_whitespace_and_comments()?;
                match self.peek() {
                    Some('}') => {
                        self.consume()?;
                        break;
                    }
                    Some(';') => {
                        self.consume()?;
                    }
                    Some(_) => {
                        if self.next_identifier()?.as_deref() != Some("option") {
                            return Err(self.unexpected());
                        }
                        self.parse_option()?;
                    }
                    None => return Err(self.parse_error("Unexpected end of file")),
                }
            }
        } else {
            self.expect(';')?;
        }

        // Types are resolved against the file's names later.
        Ok(RpcDescriptor::builder()
            .name(name)
            .input_type_name(input_type)
            .output_type_name(output_type)
            .client_streaming(client_streaming)
            .server_streaming(server_streaming)
            .build())
    }

    // --- lexer helpers ---

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn consume(&mut self) -> Result<char, ProtoParseError> {
        let c = self
            .input[self.pos..]
            .chars()
            .next()
            .ok_or_else(|| ProtoParseError::new("Unexpected end of file"))?;
        let len = c.len_utf8();
        self.pos += len;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Ok(c)
    }

    fn expect(&mut self, expected: char) -> Result<(), ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        let c = self.peek();
        if c != Some(expected) {
            let ch = c.map(|c| c.to_string()).unwrap_or_else(|| "\u{FFFF}".to_string());
            // MessageFormat(err.unexpected_char, char, line) + " (line " + line + ")"
            return Err(ProtoParseError::new(format!(
                "Unexpected character '{ch}' at line {} (line {})",
                self.line, self.line
            )));
        }
        self.consume()?;
        Ok(())
    }

    fn skip_whitespace_and_comments(&mut self) -> Result<(), ProtoParseError> {
        loop {
            let rest = &self.input[self.pos..];
            let mut chars = rest.chars();
            match chars.next() {
                Some(' ') | Some('\t') | Some('\n') | Some('\r') => {
                    self.consume()?;
                }
                Some('/') => match chars.next() {
                    Some('/') => {
                        // Up to, not including, the newline: the loop counts it.
                        let len = rest.find('\n').unwrap_or(rest.len());
                        self.pos += len;
                    }
                    Some('*') => {
                        let end = rest[2..]
                            .find("*/")
                            .ok_or_else(|| self.parse_error("Unterminated comment"))?;
                        let len = 2 + end + 2;
                        let lines = rest[..len].matches('\n').count() as i32;
                        self.pos += len;
                        self.line += lines;
                    }
                    _ => break,
                },
                _ => break,
            }
        }
        Ok(())
    }

    fn next_identifier(&mut self) -> Result<Option<String>, ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        let c = self.input[self.pos..].chars().next().unwrap();
        if !c.is_alphabetic() && c != '_' {
            return Ok(None);
        }
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if !c.is_alphanumeric() && c != '_' {
                break;
            }
            self.pos += c.len_utf8();
            self.column += 1;
        }
        Ok(Some(self.input[start..self.pos].to_string()))
    }

    fn next_full_ident(&mut self) -> Result<Option<String>, ProtoParseError> {
        match self.next_identifier()? {
            Some(first) => self.continue_full_ident(first).map(Some),
            None => Ok(None),
        }
    }

    /// Extends an identifier already read with any `.part`s that follow.
    fn continue_full_ident(&mut self, first: String) -> Result<String, ProtoParseError> {
        let mut sb = first;
        self.skip_whitespace_and_comments()?;
        while self.peek() == Some('.') {
            self.consume()?;
            match self.next_identifier()? {
                Some(p) => {
                    sb.push('.');
                    sb.push_str(&p);
                }
                None => return Err(self.parse_error("Expected identifier")),
            }
            self.skip_whitespace_and_comments()?;
        }
        Ok(sb)
    }

    fn next_type_name(&mut self) -> Result<Option<String>, ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        if self.peek() == Some('.') {
            self.consume()?;
            let rest = self
                .next_full_ident()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?;
            return Ok(Some(format!(".{rest}")));
        }
        self.next_full_ident()
    }

    fn next_string(&mut self) -> Result<Option<String>, ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        let quote = match self.peek() {
            Some(q) if q == '"' || q == '\'' => q,
            _ => return Ok(None),
        };
        self.consume()?;
        let mut sb = String::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err(self.parse_error("Unterminated string")),
            };
            if c == quote {
                self.consume()?;
                return Ok(Some(sb));
            }
            if c == '\\' {
                self.consume()?;
                let esc = match self.peek() {
                    Some(e) => e,
                    None => return Err(self.parse_error("Unterminated string")),
                };
                match esc {
                    'n' => sb.push('\n'),
                    't' => sb.push('\t'),
                    'r' => sb.push('\r'),
                    other => sb.push(other),
                }
                self.consume()?;
            } else {
                sb.push(c);
                self.consume()?;
            }
        }
    }

    fn next_number(&mut self) -> Result<i64, ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        let start = self.pos;
        if matches!(self.peek(), Some('-') | Some('+')) {
            self.consume()?;
        }
        while self
            .peek()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            self.consume()?;
        }
        if self.pos == start
            || (self.pos == start + 1
                && matches!(self.input.as_bytes().get(start), Some(b'-') | Some(b'+')))
        {
            return Err(self.parse_error("Expected number"));
        }
        let s = &self.input[start..self.pos];
        s.parse::<i64>()
            .map_err(|_| self.parse_error("Expected number"))
    }

    /// A field number: 1 to 2^29 - 1, excluding the range the protobuf
    /// implementation keeps for itself.
    fn next_field_number(&mut self) -> Result<i32, ProtoParseError> {
        let n = self.next_number()?;
        if !(1..=MAX_FIELD_NUMBER).contains(&n) {
            return Err(self.parse_error(&format!("Field number {n} out of range")));
        }
        if (19000..=19999).contains(&n) {
            return Err(self.parse_error(&format!("Field number {n} is reserved")));
        }
        Ok(n as i32)
    }

    fn next_enum_number(&mut self) -> Result<i32, ProtoParseError> {
        let n = self.next_number()?;
        i32::try_from(n).map_err(|_| self.parse_error(&format!("Enum value {n} out of range")))
    }

    fn scalar_type_from_name(&self, name: &str) -> Result<FieldType, ProtoParseError> {
        match name {
            "double" => Ok(FieldType::Double),
            "float" => Ok(FieldType::Float),
            "int32" => Ok(FieldType::Int32),
            "int64" => Ok(FieldType::Int64),
            "uint32" => Ok(FieldType::Uint32),
            "uint64" => Ok(FieldType::Uint64),
            "sint32" => Ok(FieldType::Sint32),
            "sint64" => Ok(FieldType::Sint64),
            "fixed32" => Ok(FieldType::Fixed32),
            "fixed64" => Ok(FieldType::Fixed64),
            "sfixed32" => Ok(FieldType::Sfixed32),
            "sfixed64" => Ok(FieldType::Sfixed64),
            "bool" => Ok(FieldType::Bool),
            "string" => Ok(FieldType::String),
            "bytes" => Ok(FieldType::Bytes),
            _ => Err(self.parse_error(&format!("Unknown type: {name}"))),
        }
    }

    fn parse_error(&self, msg: &str) -> ProtoParseError {
        ProtoParseError::new(format!("{msg} (line {})", self.line))
    }

    /// The character (or end of file) the parser is stuck on.
    fn unexpected(&self) -> ProtoParseError {
        let what = self
            .peek()
            .map(|c| format!("'{c}'"))
            .unwrap_or_else(|| "end of file".to_string());
        self.parse_error(&format!("Unexpected {what}"))
    }
}

type MessageDescriptorBuilderOwned = super::message_descriptor::MessageDescriptorBuilder;

fn join_name(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}.{name}")
    }
}

fn is_scalar_type(name: &str) -> bool {
    matches!(
        name,
        "double"
            | "float"
            | "int32"
            | "int64"
            | "uint32"
            | "uint64"
            | "sint32"
            | "sint64"
            | "fixed32"
            | "fixed64"
            | "sfixed32"
            | "sfixed64"
            | "bool"
            | "string"
            | "bytes"
    )
}

/// What a type name written in the file turned out to name.
enum Resolved {
    Message(String),
    Enum(String),
    /// Not defined in this file (an imported type): the name as written.
    Unknown(String),
}

impl Resolved {
    fn into_name(self) -> String {
        match self {
            Resolved::Message(n) | Resolved::Enum(n) | Resolved::Unknown(n) => n,
        }
    }
}

const WELL_KNOWN: &[&str] = &[
    "Empty",
    "Timestamp",
    "Duration",
    "FieldMask",
    "Any",
    "DoubleValue",
    "FloatValue",
    "Int64Value",
    "UInt64Value",
    "Int32Value",
    "UInt32Value",
    "BoolValue",
    "StringValue",
    "BytesValue",
    "Struct",
    "Value",
    "ListValue",
];

/// The well-known enums.
const WELL_KNOWN_ENUMS: &[&str] = &["NullValue"];

/// The types that go together: `Struct` holds `Value`s, a `Value` can be a
/// `Struct` or a `ListValue`, and a `ListValue` holds `Value`s.
const JSON_TREE: &[&str] = &["Struct", "Value", "ListValue", "NullValue"];

/// Structure of a `google.protobuf` well-known type. Their proto3 JSON
/// mapping (an RFC 3339 string for a Timestamp and so on) is applied by the
/// JSON adapter and serializer for Timestamp, Duration, FieldMask, the
/// wrapper types, Struct, Value and ListValue; `Any` is an ordinary message
/// there.
fn well_known_type(simple: &str) -> Option<MessageDescriptor> {
    use FieldType::*;
    const VALUE: &str = "google.protobuf.Value";
    let named = |b: MessageDescriptorBuilderOwned| b.name(simple).full_name(format!("google.protobuf.{simple}"));
    match simple {
        "Struct" => {
            return Some(
                named(MessageDescriptor::builder())
                    .add_field(
                        FieldDescriptor::builder()
                            .number(1)
                            .name("fields")
                            .field_type(Map)
                            .key_type_name("string")
                            .value_type_name(VALUE)
                            .build(),
                    )
                    .build(),
            )
        }
        "ListValue" => {
            return Some(
                named(MessageDescriptor::builder())
                    .add_field(
                        FieldDescriptor::builder()
                            .number(1)
                            .name("values")
                            .field_type(Message)
                            .message_type_name(VALUE)
                            .repeated(true)
                            .build(),
                    )
                    .build(),
            )
        }
        "Value" => {
            let field = |number, name: &str, field_type| FieldDescriptor::builder().number(number).name(name).field_type(field_type);
            return Some(
                named(MessageDescriptor::builder())
                    .add_field(field(1, "null_value", Enum).enum_type_name("google.protobuf.NullValue").build())
                    .add_field(field(2, "number_value", Double).build())
                    .add_field(field(3, "string_value", String).build())
                    .add_field(field(4, "bool_value", Bool).build())
                    .add_field(field(5, "struct_value", Message).message_type_name("google.protobuf.Struct").build())
                    .add_field(field(6, "list_value", Message).message_type_name("google.protobuf.ListValue").build())
                    .build(),
            )
        }
        _ => {}
    }
    let fields: &[(&str, FieldType, i32, bool)] = match simple {
        "Empty" => &[],
        "Timestamp" | "Duration" => &[("seconds", Int64, 1, false), ("nanos", Int32, 2, false)],
        "FieldMask" => &[("paths", String, 1, true)],
        "Any" => &[("type_url", String, 1, false), ("value", Bytes, 2, false)],
        "DoubleValue" => &[("value", Double, 1, false)],
        "FloatValue" => &[("value", Float, 1, false)],
        "Int64Value" => &[("value", Int64, 1, false)],
        "UInt64Value" => &[("value", Uint64, 1, false)],
        "Int32Value" => &[("value", Int32, 1, false)],
        "UInt32Value" => &[("value", Uint32, 1, false)],
        "BoolValue" => &[("value", Bool, 1, false)],
        "StringValue" => &[("value", String, 1, false)],
        "BytesValue" => &[("value", Bytes, 1, false)],
        _ => return None,
    };
    let mut b = MessageDescriptor::builder()
        .name(simple)
        .full_name(format!("google.protobuf.{simple}"));
    for &(name, field_type, number, repeated) in fields {
        b = b.add_field(
            FieldDescriptor::builder()
                .number(number)
                .name(name)
                .field_type(field_type)
                .repeated(repeated)
                .build(),
        );
    }
    Some(b.build())
}

fn well_known_enum(simple: &str) -> Option<EnumDescriptor> {
    match simple {
        "NullValue" => Some(
            EnumDescriptor::builder()
                .name("NullValue")
                .full_name("google.protobuf.NullValue")
                .add_value(0, "NULL_VALUE")
                .build(),
        ),
        _ => None,
    }
}

/// Turns type names as written into full names, once every type in the file
/// is known.
struct Resolver {
    messages: HashSet<String>,
    enums: HashSet<String>,
    well_known_used: HashSet<String>,
}

impl Resolver {
    fn new(messages: &[MessageDescriptor], enums: &[EnumDescriptor]) -> Self {
        let mut r = Resolver {
            messages: HashSet::new(),
            enums: enums.iter().map(|e| e.full_name.clone()).collect(),
            well_known_used: HashSet::new(),
        };
        r.collect(messages.iter());
        r
    }

    fn collect<'a>(&mut self, messages: impl Iterator<Item = &'a MessageDescriptor>) {
        for m in messages {
            self.messages.insert(m.full_name.clone());
            self.enums
                .extend(m.nested_enums.values().map(|e| e.full_name.clone()));
            self.collect(m.nested_messages.values());
        }
    }

    fn is_well_known(&self, full_name: &str) -> bool {
        full_name
            .strip_prefix("google.protobuf.")
            .is_some_and(|s| WELL_KNOWN.contains(&s))
            && !self.messages.contains(full_name)
    }

    fn is_well_known_enum(&self, full_name: &str) -> bool {
        full_name
            .strip_prefix("google.protobuf.")
            .is_some_and(|s| WELL_KNOWN_ENUMS.contains(&s))
            && !self.enums.contains(full_name)
    }

    fn classify(&mut self, full_name: &str) -> Option<Resolved> {
        if self.messages.contains(full_name) {
            Some(Resolved::Message(full_name.to_string()))
        } else if self.enums.contains(full_name) {
            Some(Resolved::Enum(full_name.to_string()))
        } else if self.is_well_known_enum(full_name) {
            self.well_known_used.insert(full_name.to_string());
            Some(Resolved::Enum(full_name.to_string()))
        } else if self.is_well_known(full_name) {
            self.well_known_used.insert(full_name.to_string());
            Some(Resolved::Message(full_name.to_string()))
        } else {
            None
        }
    }

    /// Looks `raw` up from `scope` outwards: `scope.raw`, then the scope's
    /// parent, and so on to the top. A leading dot makes `raw` absolute.
    fn resolve(&mut self, scope: &str, raw: &str) -> Resolved {
        if let Some(abs) = raw.strip_prefix('.') {
            return self
                .classify(abs)
                .unwrap_or_else(|| Resolved::Unknown(abs.to_string()));
        }
        let mut scope = scope;
        loop {
            let candidate = join_name(scope, raw);
            if let Some(r) = self.classify(&candidate) {
                return r;
            }
            match scope.rfind('.') {
                Some(i) => scope = &scope[..i],
                None if scope.is_empty() => return Resolved::Unknown(raw.to_string()),
                None => scope = "",
            }
        }
    }

    fn resolve_message(&mut self, m: &mut MessageDescriptor) {
        let scope = m.full_name.clone();
        for f in &mut m.fields {
            match f.field_type {
                FieldType::Message => {
                    if let Some(raw) = f.message_type_name.take() {
                        match self.resolve(&scope, &raw) {
                            Resolved::Enum(n) => {
                                f.field_type = FieldType::Enum;
                                f.enum_type_name = Some(n);
                            }
                            other => f.message_type_name = Some(other.into_name()),
                        }
                    }
                }
                FieldType::Map => {
                    if let Some(raw) = f.value_type_name.take() {
                        f.value_type_name = Some(if is_scalar_type(&raw) {
                            raw
                        } else {
                            self.resolve(&scope, &raw).into_name()
                        });
                    }
                }
                _ => {}
            }
        }
        for nested in m.nested_messages.values_mut() {
            self.resolve_message(nested);
        }
    }

    fn resolve_service(&mut self, s: &mut ServiceDescriptor) {
        let scope = s.full_name.clone();
        for rpc in &mut s.rpcs {
            rpc.input_type_name = self.resolve(&scope, &rpc.input_type_name).into_name();
            rpc.output_type_name = self.resolve(&scope, &rpc.output_type_name).into_name();
        }
    }

    /// The well-known types the file refers to, to be added to it.
    fn well_known_used(self) -> (Vec<MessageDescriptor>, Vec<EnumDescriptor>) {
        let mut names = self.well_known_used;
        // Struct, Value and ListValue refer to each other, and Value to NullValue.
        if ["Struct", "Value", "ListValue"].iter().any(|n| names.contains(&format!("google.protobuf.{n}"))) {
            names.extend(JSON_TREE.iter().map(|n| format!("google.protobuf.{n}")));
        }
        let mut names: Vec<String> = names.into_iter().collect();
        names.sort();
        let simple = |n: &String| n.strip_prefix("google.protobuf.").map(str::to_string);
        let messages = names.iter().filter_map(simple).filter_map(|n| well_known_type(&n)).collect();
        let enums = names.iter().filter_map(simple).filter_map(|n| well_known_enum(&n)).collect();
        (messages, enums)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_service() {
        let src = r#"
            syntax = "proto3";
            package demo;
            message Req { string name = 1; }
            message Resp { int32 code = 1; }
            service Greeter {
              rpc SayHello (Req) returns (Resp);
            }
        "#;
        let pf = ProtoFileParser::parse(src).unwrap();
        assert_eq!(pf.package_name, "demo");
        assert!(pf.message("demo.Req").is_some());
        let rpc = pf.get_rpc_by_path("/demo.Greeter/SayHello").unwrap();
        assert_eq!(rpc.input_type_name, "demo.Req");
        assert_eq!(rpc.output_type_name, "demo.Resp");
    }

    #[test]
    fn skip_import() {
        let src = r#"
            syntax = "proto3";
            import "other.proto";
            message M { int32 x = 1; }
        "#;
        let pf = ProtoFileParser::parse(src).unwrap();
        assert!(pf.message("M").is_some());
    }

    fn parse(src: &str) -> ProtoFile {
        ProtoFileParser::parse(src).unwrap_or_else(|e| panic!("{src}\n=> {}", e.message()))
    }

    fn refused(src: &str) -> String {
        match ProtoFileParser::parse(src) {
            Ok(_) => panic!("should have been refused:\n{src}"),
            Err(e) => e.message().to_string(),
        }
    }

    fn field<'a>(pf: &'a ProtoFile, msg: &str, name: &str) -> &'a FieldDescriptor {
        pf.message(msg).unwrap_or_else(|| panic!("no message {msg}")).field_by_name(name).unwrap_or_else(|| panic!("no field {name}"))
    }

    // -- nested types and name resolution ------------------------------------

    #[test]
    fn nested_messages_and_enums_can_be_looked_up_by_full_name() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message Outer { message Inner { message Deep { int32 d = 1; } Deep deep = 1; } enum Kind { A = 0; B = 1; } Inner i = 1; Kind k = 2; }",
        );
        assert!(pf.message("demo.Outer").is_some());
        assert!(pf.message("demo.Outer.Inner").is_some());
        assert!(pf.message("demo.Outer.Inner.Deep").is_some());
        assert!(pf.enum_type("demo.Outer.Kind").is_some());
    }

    #[test]
    fn a_field_naming_a_nested_type_resolves_to_it() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message Outer { message Inner { int32 v = 1; } enum Kind { A = 0; } Inner i = 1; Kind k = 2; repeated Inner many = 3; }",
        );
        let i = field(&pf, "demo.Outer", "i");
        assert_eq!((i.field_type, i.message_type_name.as_deref()), (FieldType::Message, Some("demo.Outer.Inner")));
        let k = field(&pf, "demo.Outer", "k");
        assert_eq!((k.field_type, k.enum_type_name.as_deref(), k.message_type_name.as_deref()), (FieldType::Enum, Some("demo.Outer.Kind"), None));
        assert!(field(&pf, "demo.Outer", "many").repeated);
    }

    #[test]
    fn a_type_may_be_used_before_it_is_declared() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message A { B b = 1; Color c = 2; }
             message B { int32 x = 1; }
             enum Color { RED = 0; }",
        );
        assert_eq!(field(&pf, "demo.A", "b").message_type_name.as_deref(), Some("demo.B"));
        let c = field(&pf, "demo.A", "c");
        assert_eq!((c.field_type, c.enum_type_name.as_deref()), (FieldType::Enum, Some("demo.Color")));
    }

    #[test]
    fn names_are_looked_up_from_the_innermost_scope_outwards() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message Inner { int32 top = 1; }
             message Outer {
                 message Inner { int32 nested = 1; }
                 message Mid { message Leaf { Inner i = 1; Sibling s = 2; Top t = 3; } message Sibling {} Inner j = 1; }
                 Inner k = 1;
             }
             message Top {}",
        );
        assert_eq!(field(&pf, "demo.Outer", "k").message_type_name.as_deref(), Some("demo.Outer.Inner"), "the nested one hides the top-level one");
        assert_eq!(field(&pf, "demo.Outer.Mid", "j").message_type_name.as_deref(), Some("demo.Outer.Inner"));
        assert_eq!(field(&pf, "demo.Outer.Mid.Leaf", "i").message_type_name.as_deref(), Some("demo.Outer.Inner"));
        assert_eq!(field(&pf, "demo.Outer.Mid.Leaf", "s").message_type_name.as_deref(), Some("demo.Outer.Mid.Sibling"));
        assert_eq!(field(&pf, "demo.Outer.Mid.Leaf", "t").message_type_name.as_deref(), Some("demo.Top"));
    }

    #[test]
    fn qualified_names_resolve_whatever_their_form() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message Outer { message Inner {} }
             message U { Outer.Inner a = 1; .demo.Outer.Inner b = 2; demo.Outer.Inner c = 3; }",
        );
        for f in ["a", "b", "c"] {
            assert_eq!(field(&pf, "demo.U", f).message_type_name.as_deref(), Some("demo.Outer.Inner"), "{f}");
        }
    }

    #[test]
    fn a_type_from_elsewhere_keeps_the_name_it_was_written_with() {
        // An imported type: not defined here, so not resolvable here.
        let pf = parse("syntax = \"proto3\"; package demo; import \"other.proto\"; message M { other.pkg.Thing t = 1; }");
        assert_eq!(field(&pf, "demo.M", "t").message_type_name.as_deref(), Some("other.pkg.Thing"));
        let leading = parse("syntax = \"proto3\"; package demo; message M { .other.pkg.Thing t = 1; }");
        assert_eq!(field(&leading, "demo.M", "t").message_type_name.as_deref(), Some("other.pkg.Thing"));
    }

    #[test]
    fn map_values_resolve_like_field_types() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message M { message V {} enum E { X = 0; } map<string, V> a = 1; map<int32, E> b = 2; map<string, Later> c = 3; map<string, int64> d = 4; }
             message Later {}",
        );
        assert_eq!(field(&pf, "demo.M", "a").value_type_name.as_deref(), Some("demo.M.V"));
        assert_eq!(field(&pf, "demo.M", "b").value_type_name.as_deref(), Some("demo.M.E"));
        assert_eq!(field(&pf, "demo.M", "c").value_type_name.as_deref(), Some("demo.Later"));
        assert_eq!(field(&pf, "demo.M", "d").value_type_name.as_deref(), Some("int64"));
        assert_eq!(field(&pf, "demo.M", "b").key_type_name.as_deref(), Some("int32"));
    }

    #[test]
    fn a_file_without_a_package_has_plain_names() {
        let pf = parse("syntax = \"proto3\"; message A { B b = 1; message N {} N n = 2; } message B {}");
        assert_eq!(field(&pf, "A", "b").message_type_name.as_deref(), Some("B"));
        assert_eq!(field(&pf, "A", "n").message_type_name.as_deref(), Some("A.N"));
    }

    // -- services -----------------------------------------------------------

    #[test]
    fn rpcs_resolve_their_types_and_record_streaming() {
        let pf = parse(
            "syntax = \"proto3\"; package demo;
             message Req {} message Resp {} message Outer { message In {} }
             service S {
                 rpc Unary (Req) returns (Resp);
                 rpc ClientS (stream Req) returns (Resp);
                 rpc ServerS (Req) returns (stream Resp);
                 rpc Both (stream Req) returns (stream Resp);
                 rpc Nested (Outer.In) returns (.demo.Resp);
                 rpc Qual (demo.Req) returns (demo.Outer.In) {}
                 rpc Opts (Req) returns (Resp) { option deprecated = true; ; }
             }",
        );
        let s = pf.service("demo.S").unwrap();
        let r = |n: &str| s.rpc(n).unwrap_or_else(|| panic!("no rpc {n}"));
        assert_eq!((r("Unary").client_streaming, r("Unary").server_streaming), (false, false));
        assert_eq!((r("ClientS").client_streaming, r("ClientS").server_streaming), (true, false));
        assert_eq!((r("ServerS").client_streaming, r("ServerS").server_streaming), (false, true));
        assert_eq!((r("Both").client_streaming, r("Both").server_streaming), (true, true));
        assert_eq!(r("Unary").input_type_name, "demo.Req");
        assert_eq!(r("Nested").input_type_name, "demo.Outer.In");
        assert_eq!(r("Nested").output_type_name, "demo.Resp");
        assert_eq!((r("Qual").input_type_name.as_str(), r("Qual").output_type_name.as_str()), ("demo.Req", "demo.Outer.In"));
        assert!(pf.get_rpc_by_path("/demo.S/Both").is_some());
        assert!(pf.get_rpc_by_path("/demo.S/Missing").is_none());
        assert!(pf.get_rpc_by_path("demo.S/Both").is_none());
        assert!(pf.get_rpc_by_path("/demo.S/").is_none());
    }

    #[test]
    fn well_known_types_are_available_without_their_import() {
        let pf = parse(
            "syntax = \"proto3\"; package demo; import \"google/protobuf/empty.proto\"; import \"google/protobuf/timestamp.proto\";
             message Ev { google.protobuf.Timestamp at = 1; google.protobuf.Duration d = 2; google.protobuf.StringValue name = 3; }
             service S { rpc Ping (google.protobuf.Empty) returns (google.protobuf.Empty); rpc Get (google.protobuf.Empty) returns (Ev); }",
        );
        assert!(pf.message("google.protobuf.Empty").unwrap().fields.is_empty());
        let ts = pf.message("google.protobuf.Timestamp").unwrap();
        assert_eq!(ts.field_by_name("seconds").unwrap().field_type, FieldType::Int64);
        assert_eq!(ts.field_by_name("nanos").unwrap().field_type, FieldType::Int32);
        assert_eq!(pf.message("google.protobuf.StringValue").unwrap().field_by_name("value").unwrap().field_type, FieldType::String);
        assert_eq!(field(&pf, "demo.Ev", "at").message_type_name.as_deref(), Some("google.protobuf.Timestamp"));
        assert_eq!(pf.get_rpc_by_path("/demo.S/Ping").unwrap().input_type_name, "google.protobuf.Empty");
    }

    #[test]
    fn only_the_well_known_types_that_are_used_are_added() {
        let pf = parse("syntax = \"proto3\"; package demo; message M { google.protobuf.Duration d = 1; }");
        assert!(pf.message("google.protobuf.Duration").is_some());
        assert!(pf.message("google.protobuf.Empty").is_none());
        assert!(pf.message("demo.M").is_some());
    }

    #[test]
    fn struct_value_and_list_value_come_as_a_set_with_their_null_enum() {
        let pf = parse("syntax = \"proto3\"; package demo; message M { google.protobuf.Struct s = 1; }");
        let st = pf.message("google.protobuf.Struct").unwrap();
        let fields = st.field_by_name("fields").unwrap();
        assert_eq!(fields.field_type, FieldType::Map);
        assert_eq!(fields.key_type_name.as_deref(), Some("string"));
        assert_eq!(fields.value_type_name.as_deref(), Some("google.protobuf.Value"));
        let v = pf.message("google.protobuf.Value").unwrap();
        let kinds: Vec<(&str, FieldType, i32)> =
            v.fields.iter().map(|f| (f.name.as_str(), f.field_type, f.number)).collect();
        assert_eq!(
            kinds,
            [
                ("null_value", FieldType::Enum, 1),
                ("number_value", FieldType::Double, 2),
                ("string_value", FieldType::String, 3),
                ("bool_value", FieldType::Bool, 4),
                ("struct_value", FieldType::Message, 5),
                ("list_value", FieldType::Message, 6),
            ]
        );
        assert_eq!(v.field_by_name("struct_value").unwrap().message_type_name.as_deref(), Some("google.protobuf.Struct"));
        assert_eq!(v.field_by_name("null_value").unwrap().enum_type_name.as_deref(), Some("google.protobuf.NullValue"));
        let list = pf.message("google.protobuf.ListValue").unwrap().field_by_name("values").unwrap();
        assert!(list.repeated && list.message_type_name.as_deref() == Some("google.protobuf.Value"));
        assert_eq!(pf.enum_type("google.protobuf.NullValue").unwrap().value_name(0), Some("NULL_VALUE"));
        assert_eq!(field(&pf, "demo.M", "s").message_type_name.as_deref(), Some("google.protobuf.Struct"));
    }

    #[test]
    fn any_one_of_the_three_brings_the_others_it_refers_to() {
        for used in ["Value", "ListValue", "Struct"] {
            let pf = parse(&format!("syntax = \"proto3\"; package demo; message M {{ google.protobuf.{used} x = 1; }}"));
            for name in ["Struct", "Value", "ListValue"] {
                assert!(pf.message(&format!("google.protobuf.{name}")).is_some(), "{used} should bring {name}");
            }
            assert!(pf.enum_type("google.protobuf.NullValue").is_some());
        }
        let none = parse("syntax = \"proto3\"; package demo; message M { int32 x = 1; }");
        assert!(none.message("google.protobuf.Struct").is_none() && none.enum_type("google.protobuf.NullValue").is_none());
    }

    #[test]
    fn null_value_can_be_used_on_its_own() {
        let pf = parse("syntax = \"proto3\"; package demo; message M { google.protobuf.NullValue n = 1; }");
        let f = field(&pf, "demo.M", "n");
        assert_eq!(f.field_type, FieldType::Enum);
        assert_eq!(f.enum_type_name.as_deref(), Some("google.protobuf.NullValue"));
        assert!(pf.enum_type("google.protobuf.NullValue").is_some());
        assert!(pf.message("google.protobuf.Value").is_none(), "only the enum was asked for");
    }

    #[test]
    fn a_stray_token_in_a_service_is_an_error() {
        assert!(refused("syntax = \"proto3\"; service S { bogus; }").contains("line"));
        assert!(refused("syntax = \"proto3\"; service S { rpc A (X) returns (Y) }").contains("line"));
    }

    // -- options -------------------------------------------------------------

    #[test]
    fn a_field_may_have_several_options() {
        let pf = parse("syntax = \"proto3\"; message M { int32 a = 1 [deprecated = true, packed = false]; string b = 2 [ json_name = \"bee\" , deprecated = true ]; }");
        assert!(pf.message("M").unwrap().field_by_name("a").is_some());
    }

    #[test]
    fn json_name_overrides_the_default_json_key() {
        let pf = parse("syntax = \"proto3\"; message M { string first_name = 1 [json_name = \"givenName\"]; string last_name = 2; }");
        let m = pf.message("M").unwrap();
        assert_eq!(m.field_by_json_key("givenName").unwrap().name, "first_name");
        assert_eq!(m.field_by_json_key("first_name").unwrap().name, "first_name", "the proto name is accepted too");
        assert!(m.field_by_json_key("firstName").is_none(), "the default is replaced, not added to");
        assert_eq!(m.field_by_json_key("lastName").unwrap().name, "last_name");
        assert_eq!(m.field_by_name("first_name").unwrap().json_key(), "givenName");
        assert_eq!(m.field_by_name("last_name").unwrap().json_key(), "lastName");
    }

    #[test]
    fn custom_options_of_every_form_are_skipped() {
        parse(
            "syntax = \"proto3\"; package demo;
             import \"google/api/annotations.proto\";
             option java_package = \"com.example\";
             option optimize_for = SPEED;
             option (my.file_opt) = { a: 1 b: \"s\" nested { c: [1, 2] } };
             option (my.flag) = true;
             message M {
                 option (my.msg_opt) = \"x\";
                 option deprecated = true;
                 string s = 1 [(validate.rules).string.min_len = 1, (a.b) = 1.5e3, (c) = -inf, (d) = { x: 1 }];
                 int32 n = 2 [(my.opt) = -5];
             }
             enum E { option allow_alias = true; A = 0 [(my.v) = \"a\"]; B = 0; }
             service S {
                 option (my.svc) = 1;
                 rpc Get (M) returns (M) {
                     option (google.api.http) = { get: \"/v1/m/{id}\" additional_bindings { post: \"/v1/m\" body: \"*\" } };
                     option idempotency_level = NO_SIDE_EFFECTS;
                 }
             }",
        );
    }

    #[test]
    fn an_unbalanced_aggregate_option_is_an_error() {
        refused("syntax = \"proto3\"; option (x) = { a: 1 ;");
        refused("syntax = \"proto3\"; message M { string s = 1 [(x) = { a: 1 ]; }");
    }

    #[test]
    fn braces_inside_an_option_string_do_not_confuse_the_skipping() {
        parse("syntax = \"proto3\"; option (x) = { a: \"}\" b: \"{\" }; message M {}");
    }

    // -- numbers -------------------------------------------------------------

    #[test]
    fn field_numbers_are_checked() {
        for ok in ["1", "15", "16", "18999", "20000", "536870911"] {
            parse(&format!("syntax = \"proto3\"; message M {{ int32 a = {ok}; }}"));
        }
        for bad in ["0", "-1", "536870912", "4294967297", "19000", "19999", "99999999999999999999"] {
            refused(&format!("syntax = \"proto3\"; message M {{ int32 a = {bad}; }}"));
        }
    }

    #[test]
    fn a_duplicate_field_number_or_name_is_an_error() {
        assert!(refused("syntax = \"proto3\"; message M { int32 a = 1; int32 b = 1; }").contains("Duplicate field number"));
        assert!(refused("syntax = \"proto3\"; message M { int32 a = 1; string a = 2; }").to_lowercase().contains("duplicate"));
        refused("syntax = \"proto3\"; message M { oneof o { int32 a = 1; string b = 1; } }");
    }

    #[test]
    fn enum_values_are_i32() {
        let pf = parse("syntax = \"proto3\"; enum E { Z = 0; NEG = -5; MAX = 2147483647; MIN = -2147483648; }");
        let e = pf.enum_type("E").unwrap();
        assert_eq!((e.value_number("NEG"), e.value_number("MAX"), e.value_number("MIN")), (Some(-5), Some(i32::MAX), Some(i32::MIN)));
        assert_eq!(e.value_name(-5), Some("NEG"));
        refused("syntax = \"proto3\"; enum E { Z = 0; BIG = 2147483648; }");
        refused("syntax = \"proto3\"; enum E { Z = 0; BIG = 4294967297; }");
    }

    #[test]
    fn two_names_for_one_enum_number_are_allowed_with_allow_alias() {
        let pf = parse("syntax = \"proto3\"; enum E { option allow_alias = true; A = 0; B = 0; C = 1; }");
        let e = pf.enum_type("E").unwrap();
        assert_eq!((e.value_number("A"), e.value_number("B"), e.value_number("C")), (Some(0), Some(0), Some(1)));
    }

    // -- duplicates ----------------------------------------------------------

    #[test]
    fn declaring_a_name_twice_is_an_error() {
        refused("syntax = \"proto3\"; package d; message A {} message A {}");
        refused("syntax = \"proto3\"; package d; enum E { Z = 0; } enum E { Z = 0; }");
        refused("syntax = \"proto3\"; package d; service S {} service S {}");
        refused("syntax = \"proto3\"; package d; message A { message N {} message N {} }");
        refused("syntax = \"proto3\"; package d; message A {} enum A { Z = 0; }");
    }

    // -- the file as a whole -------------------------------------------------

    #[test]
    fn the_syntax_and_package_are_recorded() {
        let pf = parse("syntax = \"proto3\"; package a.b.c; message M {}");
        assert_eq!((pf.syntax.as_str(), pf.package_name.as_str()), ("proto3", "a.b.c"));
        assert!(pf.message("a.b.c.M").is_some());
        assert_eq!(parse("syntax = 'proto2'; message M {}").syntax, "proto2");
        assert_eq!(parse("message M {}").syntax, "proto3", "proto3 when not stated");
    }

    #[test]
    fn unsupported_or_invalid_syntax_is_refused() {
        refused("syntax = \"proto4\"; message M {}");
        refused("syntax = proto3; message M {}");
        refused("edition = \"2023\"; message M {}");
    }

    #[test]
    fn comments_may_go_anywhere_whitespace_may() {
        parse(
            "// leading\n/* block */ syntax /* c */ = /* c */ \"proto3\" /* c */ ; // t
             package // c
             demo;
             /* multi
                line */ message /* c */ M /* c */ { // x
                 int32 /* t */ a /* n */ = /* e */ 1 /* o */ ; /* trailing */
             } // end",
        );
    }

    #[test]
    fn errors_name_the_line() {
        let e = refused("syntax = \"proto3\";\n\n\nmessage M {\n  int32 a = ;\n}\n");
        assert!(e.contains("line 5"), "{e}");
        let e = refused("syntax = \"proto3\";\r\nmessage M {\r\n  bogus\r\n}\r\n");
        assert!(e.contains("line "), "{e}");
    }

    #[test]
    fn unterminated_constructs_are_errors_not_silently_accepted() {
        refused("syntax = \"proto3\"; import \"unterminated; message M {}");
        refused("syntax = \"proto3\"; /* never closed message M {}");
        refused("syntax = \"proto3\"; message M { int32 a = 1;");
        refused("syntax = \"proto3\"; message M { oneof o { int32 a = 1;");
        refused("syntax = \"proto3\"; enum E { Z = 0;");
        refused("syntax = \"proto3\"; service S { rpc A (X) returns (Y);");
        refused("syntax = \"proto3\"; message M { reserved 1, 2");
        refused("syntax = \"proto3\"; message M { reserved \"a\"");
    }

    #[test]
    fn string_escapes_in_option_values() {
        parse("syntax = \"proto3\"; option (x) = \"a\\\"b\\\\c\\n\"; option y = 'it\\'s';");
    }

    #[test]
    fn reserved_forms() {
        let pf = parse(
            "syntax = \"proto3\"; message M { reserved 2, 15, 9 to 11; reserved 40 to max; reserved \"foo\", \"bar\"; int32 a = 1; int32 b = 3; }",
        );
        assert!(pf.message("M").unwrap().field_by_number(3).is_some());
        // a reserved number cannot be used
        refused("syntax = \"proto3\"; message M { reserved 2; int32 a = 2; }");
        refused("syntax = \"proto3\"; message M { reserved 9 to 11; int32 a = 10; }");
        refused("syntax = \"proto3\"; message M { reserved \"a\"; int32 a = 1; }");
    }

    #[test]
    fn oneof_fields_belong_to_the_message() {
        let pf = parse("syntax = \"proto3\"; message M { oneof choice { option (x) = 1; string a = 1; int32 b = 2; } optional string c = 3; repeated int32 d = 4; }");
        let m = pf.message("M").unwrap();
        assert_eq!(m.fields.len(), 4);
        assert!(m.field_by_name("c").unwrap().optional && m.field_by_name("d").unwrap().repeated);
        assert!(!m.field_by_name("a").unwrap().optional);
    }

    #[test]
    fn identifiers_may_be_non_ascii_letters() {
        let pf = parse("syntax = \"proto3\"; message Café { string nom = 1; }");
        assert!(pf.message("Café").is_some());
    }

    #[test]
    fn the_source_may_arrive_in_pieces_even_in_the_middle_of_a_character() {
        let src = "syntax = \"proto3\"; // café ☃\nmessage Café { string nom = 1; }\n";
        for chunk in [1usize, 2, 3, 7] {
            let mut p = ProtoFileParser::new();
            for part in src.as_bytes().chunks(chunk) {
                p.receive(part);
            }
            let pf = p.close().unwrap_or_else(|e| panic!("chunk {chunk}: {}", e.message()));
            assert!(pf.message("Café").is_some(), "chunk {chunk}");
        }
    }

    #[test]
    fn an_empty_file_and_stray_semicolons() {
        let pf = parse("");
        assert!(pf.messages.is_empty());
        parse(";;; syntax = \"proto3\"; ; message M {}; ;");
        parse("/* only a comment */");
    }
}

// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-based parser for `.proto` files (proto3 language).
//!
//! Faithful port of Gumdrop `ProtoFileParser`. Limitations preserved:
//! - `import` statements are skipped (path consumed, not resolved)
//! - `syntax` is validated but not stored on the built [`ProtoFile`]
//! - nested enums are not registered in the enum-name set used for field typing
//! - options / reserved are parsed and discarded

use std::collections::HashSet;

use super::{
    EnumDescriptor, FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ProtoParseError,
    RpcDescriptor, ServiceDescriptor,
};

/// Push-based parser for `.proto` files.
pub struct ProtoFileParser {
    input: String,
    pos: usize,
    line: i32,
    column: i32,
    closed: bool,
    enum_full_names: HashSet<String>,
}

impl Default for ProtoFileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoFileParser {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            pos: 0,
            line: 1,
            column: 1,
            closed: false,
            enum_full_names: HashSet::new(),
        }
    }

    /// Pushes bytes into the parser (UTF-8).
    pub fn receive(&mut self, data: &[u8]) {
        if self.closed {
            panic!("Parser already closed");
        }
        self.input
            .push_str(&String::from_utf8_lossy(data));
    }

    /// Parses the accumulated input and returns the Proto model.
    pub fn close(mut self) -> Result<ProtoFile, ProtoParseError> {
        if self.closed {
            panic!("Parser already closed");
        }
        self.closed = true;
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

        let mut file_builder = ProtoFile::builder();
        let mut pkg = String::new();
        self.enum_full_names.clear();

        self.skip_whitespace_and_comments()?;

        while self.pos < self.input.len() {
            if self.peek() == Some(';') {
                self.consume()?;
                self.skip_whitespace_and_comments()?;
                continue;
            }

            let tok = match self.next_identifier()? {
                Some(t) => t,
                None => break,
            };

            match tok.as_str() {
                "syntax" => self.parse_syntax()?,
                "package" => {
                    pkg = self.parse_package()?;
                    file_builder = file_builder.package_name(pkg.clone());
                }
                "import" => self.parse_import()?,
                "option" => self.parse_option()?,
                "message" => {
                    let msg = self.parse_message(&pkg)?;
                    file_builder = file_builder.add_message(msg);
                }
                "enum" => {
                    let enm = self.parse_enum(&pkg)?;
                    self.enum_full_names.insert(enm.full_name.clone());
                    file_builder = file_builder.add_enum(enm);
                }
                "service" => {
                    let svc = self.parse_service(&pkg)?;
                    file_builder = file_builder.add_service(svc);
                }
                _ => {
                    let ch = self.peek().map(|c| c.to_string()).unwrap_or_default();
                    return Err(self.parse_error_fmt(
                        &format!("Unexpected character '{ch}' at line {}", self.line),
                        &[],
                    ));
                }
            }

            self.skip_whitespace_and_comments()?;
        }

        Ok(file_builder.build())
    }

    fn parse_syntax(&mut self) -> Result<(), ProtoParseError> {
        self.expect('=')?;
        let val = self.next_string()?;
        if val.as_deref() != Some("proto3") && val.as_deref() != Some("proto2") {
            return Err(self.parse_error("Invalid syntax declaration"));
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
        // Gumdrop limitation: imports are skipped.
        let _ = self.next_string()?;
        self.expect(';')?;
        Ok(())
    }

    fn parse_option(&mut self) -> Result<(), ProtoParseError> {
        let _ = self.next_full_ident()?;
        self.expect('=')?;
        self.parse_constant()?;
        self.expect(';')?;
        Ok(())
    }

    fn parse_constant(&mut self) -> Result<(), ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        match self.peek() {
            Some('"') | Some('\'') => {
                let _ = self.next_string()?;
                return Ok(());
            }
            Some('-') | Some('+') => {
                let _ = self.next_number()?;
                return Ok(());
            }
            Some(c) if c.is_ascii_digit() => {
                let _ = self.next_number()?;
                return Ok(());
            }
            _ => {}
        }
        if let Some(ident) = self.next_full_ident()? {
            let _ = ident; // true / false / ident — discarded like Gumdrop
            return Ok(());
        }
        Err(self.parse_error("Expected string"))
    }

    fn parse_message(&mut self, pkg: &str) -> Result<MessageDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = if pkg.is_empty() {
            name.clone()
        } else {
            format!("{pkg}.{name}")
        };
        self.expect('{')?;

        let mut msg_builder = MessageDescriptor::builder()
            .name(name)
            .full_name(full_name.clone());

        let mut field_numbers: HashSet<i32> = HashSet::new();

        self.skip_whitespace_and_comments()?;
        while self.pos < self.input.len() && self.peek() != Some('}') {
            if self.peek() == Some(';') {
                self.consume()?;
                self.skip_whitespace_and_comments()?;
                continue;
            }

            let tok = match self.next_identifier()? {
                Some(t) => t,
                None => break,
            };

            match tok.as_str() {
                "option" => self.parse_option()?,
                "reserved" => self.parse_reserved()?,
                "message" => {
                    let nested = self.parse_message(&full_name)?;
                    msg_builder = msg_builder.add_nested_message(nested);
                }
                "enum" => {
                    // Gumdrop limitation: nested enums are not added to enum_full_names.
                    let nested_enum = self.parse_enum(&full_name)?;
                    msg_builder = msg_builder.add_nested_enum(nested_enum);
                }
                "oneof" => {
                    msg_builder =
                        self.parse_oneof(msg_builder, &full_name, &mut field_numbers)?;
                }
                "map" => {
                    if let Some(map_field) =
                        self.parse_map_field(&full_name, &mut field_numbers)?
                    {
                        msg_builder = msg_builder.add_field(map_field);
                    }
                }
                "repeated" | "optional" => {
                    if let Some(opt_field) =
                        self.parse_field(Some(&tok), &full_name, &mut field_numbers, None)?
                    {
                        msg_builder = msg_builder.add_field(opt_field);
                    }
                }
                _ => {
                    if let Some(field) =
                        self.parse_field(None, &full_name, &mut field_numbers, Some(&tok))?
                    {
                        msg_builder = msg_builder.add_field(field);
                    }
                }
            }
            self.skip_whitespace_and_comments()?;
        }

        self.expect('}')?;
        Ok(msg_builder.build())
    }

    fn parse_reserved(&mut self) -> Result<(), ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        while self.peek() != Some(';') {
            if matches!(self.peek(), Some('"') | Some('\'')) {
                let _ = self.next_string()?;
            } else {
                let _ = self.next_number()?;
                // "to" range: reserved 1 to 10;
                if self.peek() == Some('t') {
                    let _ = self.next_identifier()?;
                    let _ = self.next_identifier()?;
                }
            }
            self.skip_whitespace_and_comments()?;
            if self.peek() == Some(',') {
                self.consume()?;
                self.skip_whitespace_and_comments()?;
            }
        }
        self.expect(';')?;
        Ok(())
    }

    fn parse_oneof(
        &mut self,
        mut msg_builder: MessageDescriptorBuilderOwned,
        parent_full_name: &str,
        field_numbers: &mut HashSet<i32>,
    ) -> Result<MessageDescriptorBuilderOwned, ProtoParseError> {
        let _oneof_name = self.next_identifier()?;
        self.expect('{')?;
        self.skip_whitespace_and_comments()?;
        while self.peek() != Some('}') {
            if let Some(f) = self.parse_field(None, parent_full_name, field_numbers, None)? {
                msg_builder = msg_builder.add_field(f);
            }
            self.skip_whitespace_and_comments()?;
        }
        self.expect('}')?;
        Ok(msg_builder)
    }

    fn parse_map_field(
        &mut self,
        parent_full_name: &str,
        field_numbers: &mut HashSet<i32>,
    ) -> Result<Option<FieldDescriptor>, ProtoParseError> {
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
        let num = self.next_int()?;
        if field_numbers.contains(&num) {
            return Err(self.parse_error_fmt(
                &format!("Duplicate field number {num} in message {parent_full_name}"),
                &[],
            ));
        }
        field_numbers.insert(num);
        self.parse_field_options()?;
        self.expect(';')?;

        // Gumdrop computes key/value FieldTypes then discards them.
        let _key_ft = self.scalar_type_from_name(&key_type)?;
        let _value_ft = if value_type.starts_with('.')
            || value_type
                .chars()
                .next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
        {
            FieldType::Message
        } else {
            self.scalar_type_from_name(&value_type)?
        };

        Ok(Some(
            FieldDescriptor::builder()
                .number(num)
                .name(name)
                .field_type(FieldType::Map)
                .key_type_name(key_type)
                .value_type_name(value_type)
                .build(),
        ))
    }

    fn parse_field(
        &mut self,
        modifier: Option<&str>,
        parent_full_name: &str,
        field_numbers: &mut HashSet<i32>,
        type_override: Option<&str>,
    ) -> Result<Option<FieldDescriptor>, ProtoParseError> {
        let repeated = modifier == Some("repeated");
        let optional = modifier == Some("optional");

        let type_name = if let Some(t) = type_override {
            t.to_string()
        } else {
            self.next_type_name()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?
        };
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('=')?;
        let num = self.next_int()?;
        if field_numbers.contains(&num) {
            return Err(self.parse_error_fmt(
                &format!("Duplicate field number {num} in message {parent_full_name}"),
                &[],
            ));
        }
        field_numbers.insert(num);
        self.parse_field_options()?;
        self.expect(';')?;

        let (field_type, message_type_name, enum_type_name) = if is_scalar_type(&type_name) {
            (
                self.scalar_type_from_name(&type_name)?,
                None,
                None,
            )
        } else {
            let full_type_name = if type_name.starts_with('.') {
                type_name[1..].to_string()
            } else if parent_full_name.is_empty() {
                type_name.clone()
            } else {
                resolve_type(parent_full_name, &type_name)
            };
            if self.enum_full_names.contains(&full_type_name) {
                (FieldType::Enum, None, Some(full_type_name))
            } else {
                let ft = if type_name == "map" {
                    FieldType::Map
                } else {
                    FieldType::Message
                };
                let msg = if ft == FieldType::Message {
                    Some(full_type_name)
                } else {
                    None
                };
                (ft, msg, None)
            }
        };

        let mut b = FieldDescriptor::builder()
            .number(num)
            .name(name)
            .field_type(field_type)
            .repeated(repeated)
            .optional(optional);
        if let Some(m) = message_type_name {
            b = b.message_type_name(m);
        }
        if let Some(e) = enum_type_name {
            b = b.enum_type_name(e);
        }
        Ok(Some(b.build()))
    }

    fn parse_field_options(&mut self) -> Result<(), ProtoParseError> {
        self.skip_whitespace_and_comments()?;
        if self.peek() == Some('[') {
            self.consume()?;
            // Faithful to Gumdrop: do { ... } while (peek == ',');
            // (comma is not consumed — multi-option fields are unused in practice)
            loop {
                let _ = self.next_full_ident()?;
                self.expect('=')?;
                self.parse_constant()?;
                self.skip_whitespace_and_comments()?;
                if self.peek() != Some(',') {
                    break;
                }
            }
            self.expect(']')?;
        }
        Ok(())
    }

    fn parse_enum(&mut self, pkg: &str) -> Result<EnumDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = if pkg.is_empty() {
            name.clone()
        } else {
            format!("{pkg}.{name}")
        };
        self.expect('{')?;

        let mut enum_builder = EnumDescriptor::builder()
            .name(name)
            .full_name(full_name);

        self.skip_whitespace_and_comments()?;
        while self.pos < self.input.len() && self.peek() != Some('}') {
            if self.peek() == Some(';') {
                self.consume()?;
                self.skip_whitespace_and_comments()?;
                continue;
            }

            let tok = match self.next_identifier()? {
                Some(t) => t,
                None => break,
            };

            if tok == "option" || tok == "reserved" {
                if tok == "option" {
                    self.parse_option()?;
                } else {
                    self.parse_reserved()?;
                }
            } else {
                let value_name = tok;
                self.expect('=')?;
                let num = self.next_int()?;
                self.parse_field_options()?;
                self.expect(';')?;
                enum_builder = enum_builder.add_value(num, value_name);
            }
            self.skip_whitespace_and_comments()?;
        }

        self.expect('}')?;
        Ok(enum_builder.build())
    }

    fn parse_service(&mut self, pkg: &str) -> Result<ServiceDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        let full_name = if pkg.is_empty() {
            name.clone()
        } else {
            format!("{pkg}.{name}")
        };
        self.expect('{')?;

        let mut svc_builder = ServiceDescriptor::builder()
            .name(name)
            .full_name(full_name);

        self.skip_whitespace_and_comments()?;
        while self.pos < self.input.len() && self.peek() != Some('}') {
            if self.peek() == Some(';') {
                self.consume()?;
                self.skip_whitespace_and_comments()?;
                continue;
            }

            let tok = match self.next_identifier()? {
                Some(t) => t,
                None => break,
            };

            if tok == "option" {
                self.parse_option()?;
            } else if tok == "rpc" {
                let rpc = self.parse_rpc(pkg)?;
                svc_builder = svc_builder.add_rpc(rpc);
            }
            self.skip_whitespace_and_comments()?;
        }

        self.expect('}')?;
        Ok(svc_builder.build())
    }

    fn parse_rpc(&mut self, pkg: &str) -> Result<RpcDescriptor, ProtoParseError> {
        let name = self
            .next_identifier()?
            .ok_or_else(|| self.parse_error("Expected identifier"))?;
        self.expect('(')?;
        let tok = self.next_identifier()?;
        let client_streaming = tok.as_deref() == Some("stream");
        let mut input_type = if client_streaming {
            self.next_type_name()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?
        } else if let Some(t) = tok {
            t
        } else {
            self.next_type_name()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?
        };
        if !client_streaming && self.peek() == Some('.') {
            self.consume()?;
            let rest = self
                .next_full_ident()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?;
            input_type = format!("{input_type}.{rest}");
        }
        self.expect(')')?;
        let returns = self.next_identifier()?;
        if returns.as_deref() != Some("returns") {
            return Err(self.parse_error("Invalid rpc definition"));
        }
        self.expect('(')?;
        let tok = self.next_identifier()?;
        let server_streaming = tok.as_deref() == Some("stream");
        let mut output_type = if server_streaming {
            self.next_type_name()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?
        } else if let Some(t) = tok {
            t
        } else {
            self.next_type_name()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?
        };
        if !server_streaming && self.peek() == Some('.') {
            self.consume()?;
            let rest = self
                .next_full_ident()?
                .ok_or_else(|| self.parse_error("Expected identifier"))?;
            output_type = format!("{output_type}.{rest}");
        }
        self.expect(')')?;
        if self.peek() == Some('{') {
            self.expect('{')?;
            while self.peek() != Some('}') {
                self.parse_option()?;
            }
            self.expect('}')?;
        } else {
            self.expect(';')?;
        }

        let in_full = if input_type.starts_with('.') {
            input_type[1..].to_string()
        } else if pkg.is_empty() {
            input_type
        } else {
            format!("{pkg}.{input_type}")
        };
        let out_full = if output_type.starts_with('.') {
            output_type[1..].to_string()
        } else if pkg.is_empty() {
            output_type
        } else {
            format!("{pkg}.{output_type}")
        };

        Ok(RpcDescriptor::builder()
            .name(name)
            .input_type_name(in_full)
            .output_type_name(out_full)
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
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.consume()?;
            } else if c == '/' && self.pos + 1 < self.input.len() {
                let next = self.input[self.pos + 1..].chars().next().unwrap();
                if next == '/' {
                    self.pos += 2;
                    while self.pos < self.input.len()
                        && self.input[self.pos..].chars().next() != Some('\n')
                    {
                        let ch = self.input[self.pos..].chars().next().unwrap();
                        self.pos += ch.len_utf8();
                    }
                    if self.pos < self.input.len() {
                        self.pos += 1; // '\n'
                    }
                    self.line += 1;
                    self.column = 1;
                } else if next == '*' {
                    self.pos += 2;
                    while self.pos + 1 < self.input.len() {
                        let ch = self.input[self.pos..].chars().next().unwrap();
                        if ch == '*' {
                            let n2 = self.input[self.pos + 1..].chars().next().unwrap();
                            if n2 == '/' {
                                self.pos += 2;
                                break;
                            }
                        }
                        if ch == '\n' {
                            self.line += 1;
                        }
                        self.pos += ch.len_utf8();
                    }
                } else {
                    break;
                }
            } else {
                break;
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
        let mut sb = String::new();
        let part = match self.next_identifier()? {
            Some(p) => p,
            None => return Ok(None),
        };
        sb.push_str(&part);
        self.skip_whitespace_and_comments()?;
        while self.pos < self.input.len() && self.peek() == Some('.') {
            self.consume()?;
            match self.next_identifier()? {
                Some(p) => {
                    sb.push('.');
                    sb.push_str(&p);
                }
                None => break,
            }
            self.skip_whitespace_and_comments()?;
        }
        Ok(Some(sb))
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
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c == quote {
                self.pos += c.len_utf8();
                self.column += 1;
                break;
            }
            if c == '\\' {
                self.consume()?;
                if self.pos >= self.input.len() {
                    return Err(self.parse_error("Unexpected end of file"));
                }
                let esc = self.input[self.pos..].chars().next().unwrap();
                match esc {
                    'n' => sb.push('\n'),
                    't' => sb.push('\t'),
                    'r' => sb.push('\r'),
                    '\\' => sb.push('\\'),
                    '\'' => sb.push('\''),
                    '"' => sb.push('"'),
                    other => sb.push(other),
                }
                self.consume()?;
            } else {
                sb.push(c);
                self.consume()?;
            }
        }
        Ok(Some(sb))
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

    fn next_int(&mut self) -> Result<i32, ProtoParseError> {
        Ok(self.next_number()? as i32)
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
            _ => Err(self.parse_error_fmt(&format!("Unknown type: {name}"), &[])),
        }
    }

    fn parse_error(&self, msg: &str) -> ProtoParseError {
        ProtoParseError::new(format!("{msg} (line {})", self.line))
    }

    fn parse_error_fmt(&self, msg: &str, _args: &[&str]) -> ProtoParseError {
        ProtoParseError::new(format!("{msg} (line {})", self.line))
    }
}

type MessageDescriptorBuilderOwned = super::message_descriptor::MessageDescriptorBuilder;

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

fn resolve_type(parent_full_name: &str, type_name: &str) -> String {
    let parent_pkg = match parent_full_name.rfind('.') {
        Some(dot) => &parent_full_name[..dot],
        None => "",
    };
    if parent_pkg.is_empty() {
        type_name.to_string()
    } else {
        format!("{parent_pkg}.{type_name}")
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
}

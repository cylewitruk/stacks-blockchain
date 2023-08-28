use std::fmt::Display;

use stacks_common::util::hash;

use super::error::LexerError;
use crate::vm::{representations::Span, types::UTF8Data};

#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    Eof,
    Whitespace,
    Lparen,
    Rparen,
    Lbrace,
    Rbrace,
    Colon,
    Comma,
    Dot,
    Int(String),
    Uint(String),
    Int8(String),
    UInt8(String),
    Int16(String),
    UInt16(String),
    Int32(String),
    UInt32(String),
    Int64(String),
    UInt64(String),
    Int128(String),
    UInt128(String),
    Int256(String),
    UInt256(String),
    AsciiString(String),
    Utf8String(String),
    Bytes(String),
    Principal(String),
    Ident(String),
    TraitIdent(String),
    Plus,
    Minus,
    Multiply,
    Divide,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Comment(String),
    Placeholder(String), // used to continue parsing after errors
}

#[derive(Clone, Debug)]
pub struct PlacedToken {
    pub span: Span,
    pub token: Token,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Token::*;
        match self {
            Eof => write!(f, "EOF"),
            Whitespace => write!(f, "whitespace"),
            Lparen => write!(f, "("),
            Rparen => write!(f, ")"),
            Lbrace => write!(f, "{{"),
            Rbrace => write!(f, "}}"),
            Colon => write!(f, ":"),
            Comma => write!(f, ","),
            Dot => write!(f, "."),
            Int(_) => write!(f, "int"),
            Uint(_) => write!(f, "uint"),
            Int8(_) => write!(f, "i8"),
            UInt8(_) => write!(f, "u8"),
            Int16(_) => write!(f, "i16"),
            UInt16(_) => write!(f, "u16"),
            Int32(_) => write!(f, "i32"),
            UInt32(_) => write!(f, "u32"),
            Int64(_) => write!(f, "i64"),
            UInt64(_) => write!(f, "u64"),
            Int128(_) => write!(f, "i128"),
            UInt128(_) => write!(f, "u128"),
            Int256(_) => write!(f, "i256"),
            UInt256(_) => write!(f, "u256"),
            AsciiString(_) => write!(f, "string-ascii"),
            Utf8String(_) => write!(f, "string-utf8"),
            Bytes(_) => write!(f, "bytes"),
            Principal(_) => write!(f, "principal"),
            Ident(_) => write!(f, "identifier"),
            TraitIdent(_) => write!(f, "trait-identifier"),
            Plus => write!(f, "+"),
            Minus => write!(f, "-"),
            Multiply => write!(f, "*"),
            Divide => write!(f, "/"),
            Less => write!(f, "<"),
            LessEqual => write!(f, "<="),
            Greater => write!(f, ">"),
            GreaterEqual => write!(f, ">="),
            Comment(_) => write!(f, "comment"),
            Placeholder(_) => write!(f, "placeholder"),
        }
    }
}

impl Token {
    pub fn reproduce(&self) -> String {
        use self::Token::*;
        match self {
            Eof => "".to_string(),
            Whitespace => " ".to_string(),
            Lparen => "(".to_string(),
            Rparen => ")".to_string(),
            Lbrace => "{{".to_string(),
            Rbrace => "}}".to_string(),
            Colon => ":".to_string(),
            Comma => ",".to_string(),
            Dot => ".".to_string(),
            Int(s) => format!("{}i128", s),
            Uint(s) => format!("{}u128", s),
            Int8(s) => format!("{}i8", s),
            UInt8(s) => format!("{}u8", s),
            Int16(s) => format!("{}i16", s),
            UInt16(s) => format!("{}u16", s),
            Int32(s) => format!("{}i32", s),
            UInt32(s) => format!("{}u32", s),
            Int64(s) => format!("{}i64", s),
            UInt64(s) => format!("{}u64", s),
            Int128(s) => format!("{}i128", s),
            UInt128(s) => format!("{}u128", s),
            Int256(s) => format!("{}i256", s),
            UInt256(s) => format!("{}u256", s),
            AsciiString(s) => format!("\"{}\"", s),
            Utf8String(s) => s.to_string(),
            Bytes(s) => format!("0x{}", s),
            Principal(s) => format!("'{}", s),
            Ident(s) => s.to_string(),
            TraitIdent(s) => format!("<{}>", s),
            Plus => "+".to_string(),
            Minus => "-".to_string(),
            Multiply => "*".to_string(),
            Divide => "/".to_string(),
            Less => "<".to_string(),
            LessEqual => "<=".to_string(),
            Greater => ">".to_string(),
            GreaterEqual => ">=".to_string(),
            Comment(c) => format!(";; {}", c),
            Placeholder(s) => s.to_string(),
        }
    }
}

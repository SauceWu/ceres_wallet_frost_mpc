use std::fmt;

#[derive(Debug)]
pub enum FrostMpcError {
    Protocol(String),
    InvalidInput(String),
    Serialization(String),
}

impl fmt::Display for FrostMpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(msg) => write!(f, "FROST protocol error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization: {msg}"),
        }
    }
}

impl std::error::Error for FrostMpcError {}

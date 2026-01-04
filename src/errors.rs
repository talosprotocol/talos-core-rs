//! Error types for Talos Protocol.

use std::fmt;
use thiserror::Error;

/// Talos error codes matching ERROR_TAXONOMY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TalosErrorCode {
    Denied,
    InvalidCapability,
    ProtocolMismatch,
    FrameInvalid,
    CryptoError,
    InvalidInput,
    TransportTimeout,
    TransportError,
}

impl fmt::Display for TalosErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TalosErrorCode {
    /// Get the string code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Denied => "TALOS_DENIED",
            Self::InvalidCapability => "TALOS_INVALID_CAPABILITY",
            Self::ProtocolMismatch => "TALOS_PROTOCOL_MISMATCH",
            Self::FrameInvalid => "TALOS_FRAME_INVALID",
            Self::CryptoError => "TALOS_CRYPTO_ERROR",
            Self::InvalidInput => "TALOS_INVALID_INPUT",
            Self::TransportTimeout => "TALOS_TRANSPORT_TIMEOUT",
            Self::TransportError => "TALOS_TRANSPORT_ERROR",
        }
    }
}

/// Talos error type.
#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct TalosError {
    code: TalosErrorCode,
    message: String,
}

impl TalosError {
    /// Create a new error.
    pub fn new(code: TalosErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Get the error code.
    pub fn code(&self) -> TalosErrorCode {
        self.code
    }

    /// Get the error code string.
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

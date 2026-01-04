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
pub enum TalosError {
    #[error("TALOS_DENIED: {0}")]
    Denied(String),
    #[error("TALOS_INVALID_CAPABILITY: {0}")]
    InvalidCapability(String),
    #[error("TALOS_PROTOCOL_MISMATCH: {0}")]
    ProtocolMismatch(String),
    #[error("TALOS_FRAME_INVALID: {0}")]
    FrameInvalid(String),
    #[error("TALOS_CRYPTO_ERROR: {0}")]
    CryptoError(String),
    #[error("TALOS_INVALID_INPUT: {0}")]
    InvalidInput(String),
    #[error("TALOS_TRANSPORT_TIMEOUT: {0}")]
    TransportTimeout(String),
    #[error("TALOS_TRANSPORT_ERROR: {0}")]
    TransportError(String),
    #[error("TALOS_RATCHET_ERROR: {0}")]
    RatchetError(String),
}

pub type TalosResult<T> = Result<T, TalosError>;

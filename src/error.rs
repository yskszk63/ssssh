use std::error::Error;
use std::io;

use bytes::BytesMut;
use thiserror::Error;

use crate::msg::disconnect::ReasonCode;
use crate::pack::UnpackError;

#[derive(Debug, Error)]
pub enum SshError {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("invalid version string: {0:?}")]
    InvalidVersion(String),

    #[error("unexpected eof {0:?}")]
    VersionUnexpectedEof(BytesMut),

    #[error("too long version identifier")]
    VersionTooLong,

    #[error(transparent)]
    UnpackError(#[from] UnpackError),

    #[error("too large packet length {0}")]
    TooLargePacket(usize),

    #[error("not matched {0:?}")]
    NegotiateNotMatched(String),

    #[error("unknown algorithm {0}")]
    UnknownAlgorithm(String),

    #[error("compression error: {0}")]
    CompressionError(#[source] Box<dyn Error + Send + Sync + 'static>),

    #[error("encrypt error: {0}")]
    EncryptError(#[source] Box<dyn Error + Send + Sync + 'static>),

    #[error("mac error: {0}")]
    MacError(#[source] Box<dyn Error + Send + Sync + 'static>),

    #[error("unexpected msg {0:}")]
    KexUnexpectedMsg(String),

    #[error("unexpected eof")]
    KexUnexpectedEof,

    #[error("kex error: {0}")]
    KexError(#[source] Box<dyn Error + Send + Sync + 'static>),

    #[error("unexpected error {0}")]
    UnexpectedMsg(String),

    #[error("no packet received.")]
    NoPacketReceived,

    #[error(transparent)]
    ChannelError(#[from] futures::channel::mpsc::SendError),

    #[error("handler error: {0}")]
    HandlerError(#[source] Box<dyn Error + Send + Sync + 'static>),

    #[error(transparent)]
    Any(Box<dyn Error + Send + Sync + 'static>),
}

impl SshError {
    pub(crate) fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::IoError(..) => Some(ReasonCode::ProtocolError),
            Self::InvalidVersion(..) => None,
            Self::VersionUnexpectedEof(..) => None,
            Self::VersionTooLong => None,
            Self::UnpackError(..) => Some(ReasonCode::ProtocolError),
            Self::TooLargePacket(..) => Some(ReasonCode::ProtocolError),
            Self::NegotiateNotMatched(..) => Some(ReasonCode::KeyExchangeFailed),
            Self::UnknownAlgorithm(..) => Some(ReasonCode::ProtocolError),
            Self::CompressionError(..) => Some(ReasonCode::CompressionError),
            Self::EncryptError(..) => Some(ReasonCode::ProtocolError),
            Self::MacError(..) => Some(ReasonCode::MacError),
            Self::KexUnexpectedMsg(..) => Some(ReasonCode::KeyExchangeFailed),
            Self::KexUnexpectedEof => Some(ReasonCode::KeyExchangeFailed),
            Self::KexError(..) => Some(ReasonCode::KeyExchangeFailed),
            Self::UnexpectedMsg(..) => Some(ReasonCode::ProtocolError),
            Self::NoPacketReceived => Some(ReasonCode::ProtocolError),
            Self::ChannelError(..) => Some(ReasonCode::ServiceNotAvailable),
            Self::HandlerError(..) => Some(ReasonCode::ByApplication),
            Self::Any(..) => None,
        }
    }

    pub(crate) fn encrypt_error<E>(err: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::EncryptError(Box::new(err))
    }

    pub(crate) fn mac_error<E>(err: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::MacError(Box::new(err))
    }

    pub(crate) fn kex_error<E>(err: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::KexError(Box::new(err))
    }

    pub(crate) fn any<E>(err: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Any(Box::new(err))
    }
}

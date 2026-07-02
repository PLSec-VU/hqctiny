use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSignature,
    TimestampTooOld,
    TimestampNotIncreasing,
    SessionExpired,
    InvalidCookie,
    InvalidCookieLength,
    SerializationError,
    EncryptionError,
    DecryptionError,
    UnexpectedResponse,
    InvalidThetaLength,
    InvalidPointIndex,
    InvalidStateTransition,
    InterpolationFailed,
    MacVerificationFailed,
    DecodingFailed,
    MerkleVerificationFailed,
    InvalidWitness,
    NetworkError(String),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

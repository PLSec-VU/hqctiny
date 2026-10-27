use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SessionExpired,
    InvalidCookie,
    InvalidCookieLength,
    SerializationError,
    EncryptionError,
    DecryptionError,
    InvalidResidueIndex,
    ReplayedRequest,
    DecodingFailed,
    KeyConfirmationFailed,
    ServerAuthenticationFailed,
    InvalidAuthKey,
    InsufficientPuzzleDifficulty,
    StalePuzzle,
    InvalidPuzzleMac,
    InvalidPuzzleSolution,
    PuzzleTooHard,
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

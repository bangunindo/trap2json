use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AuthenticationError,
    AuthenticationFailure,
    NotInTimeWindowError,
    CipherDESUnpadError,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationError => write!(f, "incorrect authentication parameter length"),
            Self::AuthenticationFailure => write!(f, "auth doesn't match"),
            Self::NotInTimeWindowError => write!(f, "engine time/boot is not incremented"),
            Self::CipherDESUnpadError => write!(f, "des cipher text is not zero padded"),
        }
    }
}

impl std::error::Error for Error {}

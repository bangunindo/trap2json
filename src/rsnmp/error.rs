use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AuthenticationError,
    AuthenticationFailure,
    NotInTimeWindowError,
    CipherDESUnpadError,
    ASNDecodeError,
    ASNEncodeError,
    USMParamDecodeError,
    USMParamEncodeError,
    UnknownSNMPVersion,
    InvalidV3Flags,
    InvalidSecurityLevel,
    DecryptionFailure,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationError => write!(f, "incorrect authentication parameter length"),
            Self::AuthenticationFailure => write!(f, "auth doesn't match"),
            Self::NotInTimeWindowError => write!(f, "engine time/boot is not monotonically incremented"),
            Self::CipherDESUnpadError => write!(f, "des cipher text is not zero padded"),
            Self::ASNDecodeError => write!(f, "failed decoding packet"),
            Self::ASNEncodeError => write!(f, "failed encoding packet"),
            Self::UnknownSNMPVersion => write!(f, "unknown snmp version"),
            Self::InvalidV3Flags => write!(f, "snmp v3 flag header doesn't exists"),
            Self::InvalidSecurityLevel => write!(f, "incoming packet doesn't match minimum security level"),
            Self::USMParamDecodeError => write!(f, "failed decoding usm parameters"),
            Self::USMParamEncodeError => write!(f, "failed encoding usm parameters"),
            Self::DecryptionFailure => write!(f, "failed decrypting payload"),
        }
    }
}

impl std::error::Error for Error {}

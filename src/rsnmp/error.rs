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

impl Error {
    pub const ERROR_STATUS_NO_ERROR: u32 = 0;
    pub const ERROR_STATUS_TOO_BIG: u32 = 1;
    pub const ERROR_STATUS_NO_SUCH_NAME: u32 = 2;
    pub const ERROR_STATUS_BAD_VALUE: u32 = 3;
    pub const ERROR_STATUS_READ_ONLY: u32 = 4;
    pub const ERROR_STATUS_GEN_ERR: u32 = 5;
    pub const ERROR_STATUS_NO_ACCESS: u32 = 6;
    pub const ERROR_STATUS_WRONG_TYPE: u32 = 7;
    pub const ERROR_STATUS_WRONG_LENGTH: u32 = 8;
    pub const ERROR_STATUS_WRONG_ENCODING: u32 = 9;
    pub const ERROR_STATUS_WRONG_VALUE: u32 = 10;
    pub const ERROR_STATUS_NO_CREATION: u32 = 11;
    pub const ERROR_STATUS_INCONSISTENT_VALUE: u32 = 12;
    pub const ERROR_STATUS_RESOURCE_UNAVAILABLE: u32 = 13;
    pub const ERROR_STATUS_COMMIT_FAILED: u32 = 14;
    pub const ERROR_STATUS_UNDO_FAILED: u32 = 15;
    pub const ERROR_STATUS_AUTHORIZATION_ERROR: u32 = 16;
    pub const ERROR_STATUS_NOT_WRITABLE: u32 = 17;
    pub const ERROR_STATUS_INCONSISTENT_NAME: u32 = 18;
    pub const ERROR_STATUS_MAX_RETRIES_EXCEEDED: u32 = 19;
    pub const ERROR_STATUS_OID_OR_SYNTAX_NOT_IN_LOCAL_MIB: u32 = 20;
    pub const ERROR_STATUS_PORT_NOT_CONNECTED: u32 = 21;
    pub const ERROR_STATUS_PORT_INCOMPATIBLE: u32 = 22;
    pub const ERROR_STATUS_PORT_INVALID: u32 = 23;
    pub const ERROR_STATUS_NO_SUCH_INSTANCE_AT_THIS_OID: u32 = 24;
    pub const ERROR_STATUS_NO_SUCH_OBJECT_AT_THIS_OID: u32 = 25;
    pub const ERROR_STATUS_UNKNOWN_SNMP_VERSION: u32 = 26;
    pub const ERROR_STATUS_UNKNOWN_SNMP_SECURITY_MODEL: u32 = 27;
    pub const ERROR_STATUS_INVALID_SECURITY_FLAGS: u32 = 28;
    pub const ERROR_STATUS_CANNOT_PARSE_INCOMING_SNMP_PACKET: u32 = 29;
    pub const ERROR_STATUS_CANNOT_ENCODE_OUTGOING_SNMP_PACKET: u32 = 30;
    pub const ERROR_STATUS_UNSUPPORTED_SECURITY_LEVEL: u32 = 31;
    pub const ERROR_STATUS_MESSAGE_NOT_IN_TIME_WINDOW: u32 = 32;
    pub const ERROR_STATUS_UNKNOWN_USERNAME: u32 = 33;
    pub const ERROR_STATUS_UNKNOWN_ENGINEID: u32 = 34;
    pub const ERROR_STATUS_AUTHENTICATION_FAILED: u32 = 35;
    pub const ERROR_STATUS_DECRYPTION_FAILED: u32 = 36;
    pub const ERROR_STATUS_ENCRYPTION_FAILED: u32 = 37;
    pub const ERROR_STATUS_MESSAGE_PARAMETERS_DONT_MATCH: u32 = 38;
    pub const ERROR_STATUS_UNEXPECTED_PDU_TYPE: u32 = 39;
    pub const ERROR_STATUS_REQUESTID_IN_RESPONSE_DOES_NOT_MATCH_REQUEST: u32 = 40;
    pub const ERROR_STATUS_UNEXPECTED_INTERNAL_ERROR_IN_SNMPDRIVER: u32 = 41;
    pub const ERROR_STATUS_NO_HANDLER_WAS_AVAILABLE_TO_PROCESS_PDU: u32 = 42;
    pub const ERROR_STATUS_ERROR_ADDING_USER_CREDENTIALS: u32 = 43;

    pub fn code(&self) -> u32 {
        match self {
            Self::AuthenticationError => Self::ERROR_STATUS_AUTHENTICATION_FAILED,
            Self::AuthenticationFailure => Self::ERROR_STATUS_AUTHENTICATION_FAILED,
            Self::NotInTimeWindowError => Self::ERROR_STATUS_MESSAGE_NOT_IN_TIME_WINDOW,
            Self::CipherDESUnpadError => Self::ERROR_STATUS_DECRYPTION_FAILED,
        }
    }
}
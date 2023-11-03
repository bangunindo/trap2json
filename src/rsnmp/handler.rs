use rasn_snmp::{v1, v2, v2c, v3};
use rasn::{
    types::{Integer, OctetString},
    AsnType,
    Decode,
    Encode,
    ber::{decode, encode},
    Codec,
};
use super::{
    error::Error,
    auth,
    cipher,
};

#[derive(Clone, Debug)]
pub struct V1Message {
    pub message: v1::Message<v1::Pdus>,
}

#[derive(Clone, Debug)]
pub struct V2Message {
    pub message: v2c::Message<v2::Pdus>,
    pub response: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum SecurityParameters {
    USM(v3::USMSecurityParameters)
}

#[derive(Clone, Debug)]
pub struct V3Message {
    pub message: v3::Message,
    pub response: Option<Vec<u8>>,
    pub security_parameters: SecurityParameters,
}

pub const AUTH_FLAG: u8 = 0x01;
pub const PRIV_FLAG: u8 = 0x02;

impl V3Message {
    pub fn process(
        &mut self,
        minimum_security_level: u8,
        auth_type: Option<auth::AuthType>,
        auth_passphrase: Option<&String>,
        privacy_protocol: Option<cipher::CipherType>,
        privacy_passphrase: Option<&String>,
        skip_timeliness_checks: bool,
    ) -> Result<(), Error> {
        let flags = self.message.global_data.flags
            .get(0)
            .ok_or(Error::InvalidV3Flags)?;
        // let expecting_response = flags >> 2 != 0;
        let security_level = flags << 6 >> 6;
        if security_level < minimum_security_level ||
            (security_level & PRIV_FLAG != 0 && security_level & AUTH_FLAG == 0) {
            return Err(Error::InvalidSecurityLevel);
        }
        if let (
            true,
            SecurityParameters::USM(usm),
            Some(auth_type),
            Some(auth_passphrase),
        ) = (
            security_level & AUTH_FLAG != 0,
            &self.security_parameters,
            auth_type,
            auth_passphrase,
        ) {
            let mut m = self.message.clone();
            m.encode_security_parameters(
                Codec::Ber,
                &v3::USMSecurityParameters {
                    authoritative_engine_id: usm.authoritative_engine_id.clone(),
                    authoritative_engine_boots: usm.authoritative_engine_boots.clone(),
                    authoritative_engine_time: usm.authoritative_engine_time.clone(),
                    user_name: usm.user_name.clone(),
                    authentication_parameters: OctetString::from(vec![0u8; usm.authentication_parameters.len()]),
                    privacy_parameters: usm.privacy_parameters.clone(),
                },
            ).map_err(|_| Error::USMParamEncodeError)?;
            let payload = encode(&m)
                .map_err(|_| Error::ASNEncodeError)?;
            auth_type.integrity_check(
                &payload,
                auth_passphrase.as_bytes(),
                &usm.authoritative_engine_id,
                &usm.authentication_parameters,
            )?;
            if !skip_timeliness_checks {
                auth_type.timeliness_check(
                    usm.authoritative_engine_boots.to_u32_digits().1[0],
                    usm.authoritative_engine_time.to_u32_digits().1[0] as u64,
                    &usm.authoritative_engine_id,
                )?;
            }
        } else if security_level & AUTH_FLAG != 0 {
            return Err(Error::AuthenticationFailure);
        }
        if let (
            true,
            v3::ScopedPduData::EncryptedPdu(payload),
            SecurityParameters::USM(usm),
            Some(auth_type),
            Some(privacy_protocol),
            Some(privacy_passphrase),
        ) = (
            security_level & PRIV_FLAG != 0,
            &self.message.scoped_data,
            &self.security_parameters,
            auth_type,
            privacy_protocol,
            privacy_passphrase,
        ) {
            let mut payload = payload.clone().to_vec();
            privacy_protocol.decrypt(
                auth_type,
                &mut payload,
                privacy_passphrase.as_bytes(),
                usm.authoritative_engine_boots.to_u32_digits().1[0],
                usm.authoritative_engine_time.to_u32_digits().1[0],
                &usm.authoritative_engine_id,
                &usm.privacy_parameters,
            )?;
            let pdu = decode::<v3::ScopedPdu>(&payload)
                .map_err(|_| Error::DecryptionFailure)?;
            self.message.scoped_data = v3::ScopedPduData::CleartextPdu(pdu);
        } else if security_level & PRIV_FLAG != 0 {
            return Err(Error::DecryptionFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    V1(V1Message),
    V2C(V2Message),
    V3(V3Message),
}

#[derive(AsnType, Debug, Decode, Encode, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
struct SnmpVersion {
    version: Integer,
}

fn decode_v1_message(data: &[u8]) -> Result<Message, Error> {
    let m: v1::Message<v1::Pdus> = decode(&data).map_err(|_| Error::ASNDecodeError)?;
    Ok(
        Message::V1(
            V1Message {
                message: m,
            }
        )
    )
}

fn decode_v2_message(data: &[u8]) -> Result<Message, Error> {
    let m: v2c::Message<v2::Pdus> = decode(&data).map_err(|_| Error::ASNDecodeError)?;
    let mut r = None;
    if let v2::Pdus::InformRequest(ref req) = m.data {
        let mut m = m.clone();
        let mut req = req.0.clone();
        req.error_index = 0;
        req.error_status = v2::Pdu::ERROR_STATUS_NO_ERROR;
        m.data = v2::Pdus::Response(v2::Response(req));
        let data = encode(&m).map_err(|_| Error::ASNEncodeError)?;
        r = Some(data);
    }
    Ok(
        Message::V2C(
            V2Message {
                message: m,
                response: r,
            }
        )
    )
}

fn decode_v3_message(data: &[u8]) -> Result<Message, Error> {
    let m: v3::Message = decode(&data).map_err(|_| Error::ASNDecodeError)?;
    let usm_security_model = m.decode_security_parameters::<v3::USMSecurityParameters>(Codec::Ber)
        .map_err(|_| Error::USMParamDecodeError)?;
    Ok(
        Message::V3(
            V3Message {
                message: m,
                response: None,
                security_parameters: SecurityParameters::USM(usm_security_model),
            }
        )
    )
}

pub fn decode_message(data: &[u8]) -> Result<Message, Error> {
    let r = decode::<SnmpVersion>(data)
        .map_err(|_| Error::ASNDecodeError)?;
    match r.version.to_u32_digits().1[0] {
        0 => decode_v1_message(data),
        1 => decode_v2_message(data),
        3 => decode_v3_message(data),
        _ => Err(Error::UnknownSNMPVersion),
    }
}

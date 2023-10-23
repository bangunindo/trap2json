use serde_enum_str::Deserialize_enum_str;
use std::fmt::Formatter;
use rasn_snmp::v3;
use cfb_mode::Decryptor;
use aes::cipher::{AsyncStreamCipher, IvSizeUser, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use rasn::ber::decode;
use sha1::Digest;

const ONE_MEGABYTE: usize = 1_048_576;
const PASSWD_BUF_LEN: usize = 64;

#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
pub enum PrivacyCipher {
    DES,
    #[serde(rename = "AES-128", alias = "AES")]
    AES128,
    #[serde(rename = "AES-192")]
    AES192,
    #[serde(rename = "AES-256")]
    AES256,
    #[serde(rename = "AES-192C")]
    AES192C,
    #[serde(rename = "AES-256C")]
    AES256C,
}

impl std::fmt::Display for PrivacyCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivacyCipher::DES => write!(f, "DES"),
            PrivacyCipher::AES128 => write!(f, "AES-128"),
            PrivacyCipher::AES192 => write!(f, "AES-192"),
            PrivacyCipher::AES192C => write!(f, "AES-192C"),
            PrivacyCipher::AES256 => write!(f, "AES-256"),
            PrivacyCipher::AES256C => write!(f, "AES-256C"),
        }
    }
}

impl PrivacyCipher {
    fn key_bits(&self) -> usize {
        match self {
            PrivacyCipher::DES => 128,
            PrivacyCipher::AES128 => 128,
            PrivacyCipher::AES192 => 192,
            PrivacyCipher::AES192C => 192,
            PrivacyCipher::AES256 => 256,
            PrivacyCipher::AES256C => 256,
        }
    }

    fn key_len(&self) -> usize {
        self.key_bits() / 8
    }
}

#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
pub enum AuthHash {
    MD5,
    #[serde(rename = "SHA-128", alias = "SHA")]
    SHA128,
    #[serde(rename = "SHA-224")]
    SHA224,
    #[serde(rename = "SHA-256")]
    SHA256,
    #[serde(rename = "SHA-384")]
    SHA384,
    #[serde(rename = "SHA-512")]
    SHA512,
}

impl std::fmt::Display for AuthHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthHash::MD5 => write!(f, "MD5"),
            AuthHash::SHA128 => write!(f, "SHA-128"),
            AuthHash::SHA224 => write!(f, "SHA-224"),
            AuthHash::SHA256 => write!(f, "SHA-256"),
            AuthHash::SHA384 => write!(f, "SHA-384"),
            AuthHash::SHA512 => write!(f, "SHA-512"),
        }
    }
}

impl AuthHash {
    fn key_bits(&self) -> usize {
        match self {
            AuthHash::MD5 => 128,
            AuthHash::SHA128 => 128,
            AuthHash::SHA224 => 224,
            AuthHash::SHA256 => 256,
            AuthHash::SHA384 => 384,
            AuthHash::SHA512 => 512,
        }
    }

    fn key_len(&self) -> usize {
        self.key_bits() / 8
    }
}

fn aes_iv(
    iv_size: usize,
    security_parameter: &v3::USMSecurityParameters,
) -> Vec<u8> {
    let mut iv = Vec::with_capacity(iv_size);
    iv.extend_from_slice(&security_parameter.authoritative_engine_boots.to_u32_digits().1[0].to_be_bytes());
    iv.extend_from_slice(&security_parameter.authoritative_engine_time.to_u32_digits().1[0].to_be_bytes());
    iv.extend_from_slice(&security_parameter.privacy_parameters);

    iv
}

fn key_from_passwd_iter(
    hash: AuthHash,
    passwd: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    assert!(
        !passwd.is_empty(),
        "password for localized key cannot be empty"
    );

    let mut passwd_buf = vec![0; PASSWD_BUF_LEN];
    let mut passwd_index = 0;
    let passwd_len = passwd.len();
    let mut hashing_fn = sha1::Sha1::default();

    for _ in (0..ONE_MEGABYTE).step_by(PASSWD_BUF_LEN) {
        for byte in passwd_buf.iter_mut() {
            *byte = passwd[passwd_index % passwd_len];
            passwd_index += 1;
        }

        hashing_fn.update(&passwd_buf);
    }

    let key = hashing_fn.finalize_reset();
    passwd_buf.clear();
    passwd_buf.extend_from_slice(&key);
    passwd_buf.extend_from_slice(engine_id);
    passwd_buf.extend_from_slice(&key);

    hashing_fn.update(&passwd_buf);
    hashing_fn.finalize().to_vec()
}

fn key_from_passwd_reeder(
    hash: AuthHash,
    cipher: PrivacyCipher,
    passwd: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    assert!(
        !passwd.is_empty(),
        "password for localized key cannot be empty"
    );

    let mut key = Vec::with_capacity(cipher.key_len());
    let mut prev_res = Vec::with_capacity(hash.key_len());
    while key.len() < cipher.key_len() {
        if prev_res.is_empty() {
            prev_res = key_from_passwd_iter(hash, passwd, engine_id);
        } else {
            prev_res = key_from_passwd_iter(hash, prev_res.as_slice(), engine_id);
        }
        key.extend_from_slice(prev_res.as_slice());
    }
    key[..cipher.key_len()].to_vec()
}

fn key_from_passwd_blumenthal(
    hash: AuthHash,
    cipher: PrivacyCipher,
    passwd: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    assert!(
        !passwd.is_empty(),
        "password for localized key cannot be empty"
    );

    let mut key = Vec::with_capacity(cipher.key_len());
    let mut prev_res = Vec::with_capacity(hash.key_len());
    while key.len() < cipher.key_len() {
        if prev_res.is_empty() {
            prev_res = key_from_passwd_iter(hash, passwd, engine_id);
        } else {
            let mut hashing_fn = sha1::Sha1::default();
            hashing_fn.update(prev_res);
            prev_res = hashing_fn.finalize().to_vec();
        }
        key.extend_from_slice(prev_res.as_slice());
    }
    key[..cipher.key_len()].to_vec()
}

pub fn decrypt(
    payload: &[u8],
    cipher: PrivacyCipher,
    hash: AuthHash,
    password: &[u8],
    security_parameter: &v3::USMSecurityParameters,
) -> Result<v3::ScopedPdu, anyhow::Error> {
    let mut payload = payload.to_vec().clone();
    let key;
    match cipher {
        PrivacyCipher::DES |
        PrivacyCipher::AES128 |
        PrivacyCipher::AES192C |
        PrivacyCipher::AES256C => {
            key = key_from_passwd_reeder(
                hash,
                cipher,
                password,
                &security_parameter.authoritative_engine_id,
            );
        }
        PrivacyCipher::AES192 | PrivacyCipher::AES256 => {
            key = key_from_passwd_blumenthal(
                hash,
                cipher,
                password,
                &security_parameter.authoritative_engine_id,
            );
        }
    }
    match cipher {
        PrivacyCipher::DES => {}
        PrivacyCipher::AES128 => {
            let decryptor: Decryptor<Aes128> = Decryptor::new_from_slices(
                &key,
                &aes_iv(
                    <Decryptor<Aes128> as IvSizeUser>::iv_size(),
                    security_parameter,
                ),
            ).map_err(|_| anyhow::Error::msg("decrypt error"))?;
            decryptor.decrypt(&mut payload);
        }
        PrivacyCipher::AES192 | PrivacyCipher::AES192C => {
            let decryptor: Decryptor<Aes192> = Decryptor::new_from_slices(
                &key,
                &aes_iv(
                    <Decryptor<Aes192> as IvSizeUser>::iv_size(),
                    security_parameter,
                ),
            ).map_err(|_| anyhow::Error::msg("decrypt error"))?;
            decryptor.decrypt(&mut payload);
        }
        PrivacyCipher::AES256 | PrivacyCipher::AES256C => {
            let decryptor: Decryptor<Aes256> = Decryptor::new_from_slices(
                &key,
                &aes_iv(
                    <Decryptor<Aes256> as IvSizeUser>::iv_size(),
                    security_parameter,
                ),
            ).map_err(|_| anyhow::Error::msg("decrypt error"))?;
            decryptor.decrypt(&mut payload);
        }
    }
    if let Ok(pdu) = decode::<v3::ScopedPdu>(&payload) {
        Ok(pdu)
    } else {
        Err(anyhow::Error::msg("decode error"))
    }
}

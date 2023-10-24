use serde_enum_str::Deserialize_enum_str;
use std::fmt::Formatter;
use cfb_mode::Decryptor as cfbDecryptor;
use cbc::Decryptor as cbcDecryptor;
use aes::cipher::{AsyncStreamCipher, IvSizeUser, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::BlockDecryptMut;
use cbc::cipher::block_padding::ZeroPadding;
use des::{Des, TdesEde3};
use super::auth::AuthType;

pub enum KeyExtension {
    Reeder,
    Blumenthal,
}

#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
pub enum CipherType {
    DES,
    #[serde(alias = "3DES")]
    TDES,
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

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DES => write!(f, "DES"),
            Self::TDES => write!(f, "3DES"),
            Self::AES128 => write!(f, "AES-128"),
            Self::AES192 => write!(f, "AES-192"),
            Self::AES192C => write!(f, "AES-192C"),
            Self::AES256 => write!(f, "AES-256"),
            Self::AES256C => write!(f, "AES-256C"),
        }
    }
}

impl CipherType {
    pub fn key_bits(&self) -> usize {
        match self {
            Self::DES => 128,
            Self::TDES => 168,
            Self::AES128 => 128,
            Self::AES192 => 192,
            Self::AES192C => 192,
            Self::AES256 => 256,
            Self::AES256C => 256,
        }
    }

    pub fn key_len(&self) -> usize {
        self.key_bits() / 8
    }

    pub fn key_extension(&self) -> KeyExtension {
        match self {
            Self::DES |
            Self::TDES |
            Self::AES128 |
            Self::AES192C |
            Self::AES256C => KeyExtension::Reeder,
            Self::AES192 |
            Self::AES256 => KeyExtension::Blumenthal,
        }
    }

    fn aes_iv<T: IvSizeUser>(
        &self,
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> Vec<u8> {
        let mut iv = Vec::with_capacity(T::iv_size());
        iv.extend_from_slice(&engine_boots.to_be_bytes());
        iv.extend_from_slice(&engine_time.to_be_bytes());
        iv.extend_from_slice(priv_params);
        iv
    }

    pub fn decrypt(
        &self,
        auth: AuthType,
        payload: &mut [u8],
        password: &[u8],
        engine_boots: u32,
        engine_time: u32,
        engine_id: &[u8],
        priv_params: &[u8],
    ) -> Result<(), anyhow::Error> {
        let key = auth.gen_key(
            password,
            engine_id,
            self.key_extension(),
            self.key_len(),
        );
        match self {
            Self::DES => {
                let des_key_len = 8;
                let (des_key, pre_iv) = key.split_at(des_key_len);
                let iv: Vec<_> = priv_params
                    .iter()
                    .zip(pre_iv.iter())
                    .map(|(salt, pre_iv)| salt ^ pre_iv)
                    .collect();
                let decryptor: cbcDecryptor<Des> = cbcDecryptor::new_from_slices(
                    des_key,
                    &iv,
                ).map_err(|_| anyhow::Error::msg("decrypt length error"))?;
                decryptor.decrypt_padded_mut::<ZeroPadding>(payload)
                    .map_err(|_| anyhow::Error::msg("decrypt padding error"))?;
            }
            Self::TDES => {}
            Self::AES128 => {
                let iv = self.aes_iv::<cfbDecryptor<Aes128>>(
                    engine_boots,
                    engine_time,
                    priv_params,
                );
                let decryptor: cfbDecryptor<Aes128> = cfbDecryptor::new_from_slices(
                    &key,
                    &iv,
                ).map_err(|_| anyhow::Error::msg("decrypt length error"))?;
                decryptor.decrypt(payload);
            }
            Self::AES192 | Self::AES192C => {
                let iv = self.aes_iv::<cfbDecryptor<Aes192>>(
                    engine_boots,
                    engine_time,
                    priv_params,
                );
                let decryptor: cfbDecryptor<Aes192> = cfbDecryptor::new_from_slices(
                    &key,
                    &iv,
                ).map_err(|_| anyhow::Error::msg("decrypt length error"))?;
                decryptor.decrypt(payload);
            }
            Self::AES256 | Self::AES256C => {
                let iv = self.aes_iv::<cfbDecryptor<Aes256>>(
                    engine_boots,
                    engine_time,
                    priv_params,
                );
                let decryptor: cfbDecryptor<Aes256> = cfbDecryptor::new_from_slices(
                    &key,
                    &iv,
                ).map_err(|_| anyhow::Error::msg("decrypt length error"))?;
                decryptor.decrypt(payload);
            }
        }
        Ok(())
    }
}


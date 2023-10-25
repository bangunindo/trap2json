use serde_enum_str::Deserialize_enum_str;
use std::fmt::Formatter;
use std::time::{Duration, SystemTime};
use sha1::digest::DynDigest;
use hmac::{Mac, Hmac};
use lazy_static::lazy_static;
use super::{
    cipher::KeyExtension,
    error::Error,
    cache::{AuthKey, LocalEngine, AUTH_KEY_CACHE, AUTH_ENGINE_CACHE},
};

const ONE_MEGABYTE: usize = 1_048_576;
const PASSWD_BUF_LEN: usize = 64;
const TIME_WINDOW: Duration = Duration::from_secs(150);
const ENGINE_BOOTS_MAX: u32 = 2_147_483_647;
const ENGINE_TIME_MAX: u32 = 2_147_483_647;

lazy_static!(
    static ref FIRST_BOOT: SystemTime = SystemTime::now();
);

#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
pub enum AuthType {
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

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA128 => write!(f, "SHA-128"),
            Self::SHA224 => write!(f, "SHA-224"),
            Self::SHA256 => write!(f, "SHA-256"),
            Self::SHA384 => write!(f, "SHA-384"),
            Self::SHA512 => write!(f, "SHA-512"),
        }
    }
}


impl AuthType {
    fn key_bits(&self) -> usize {
        match self {
            Self::MD5 => 128,
            Self::SHA128 => 128,
            Self::SHA224 => 224,
            Self::SHA256 => 256,
            Self::SHA384 => 384,
            Self::SHA512 => 512,
        }
    }

    fn hmac_key_bits(&self) -> usize {
        match self {
            Self::MD5 => 96,
            Self::SHA128 => 96,
            Self::SHA224 => 128,
            Self::SHA256 => 192,
            Self::SHA384 => 256,
            Self::SHA512 => 384,
        }
    }

    fn key_len(&self) -> usize {
        self.key_bits() / 8
    }

    fn hmac_key_len(&self) -> usize {
        self.hmac_key_bits() / 8
    }

    fn hasher(&self) -> Box<dyn DynDigest> {
        match self {
            Self::MD5 => Box::new(md5::Md5::default()),
            Self::SHA128 => Box::new(sha1::Sha1::default()),
            Self::SHA224 => Box::new(sha2::Sha224::default()),
            Self::SHA256 => Box::new(sha2::Sha256::default()),
            Self::SHA384 => Box::new(sha2::Sha384::default()),
            Self::SHA512 => Box::new(sha2::Sha512::default()),
        }
    }

    fn hmac_hasher(&self, key: &[u8]) -> Box<dyn DynDigest> {
        match self {
            Self::MD5 => Box::new(Hmac::<md5::Md5>::new_from_slice(key).unwrap()),
            Self::SHA128 => Box::new(Hmac::<sha1::Sha1>::new_from_slice(key).unwrap()),
            Self::SHA224 => Box::new(Hmac::<sha2::Sha224>::new_from_slice(key).unwrap()),
            Self::SHA256 => Box::new(Hmac::<sha2::Sha256>::new_from_slice(key).unwrap()),
            Self::SHA384 => Box::new(Hmac::<sha2::Sha384>::new_from_slice(key).unwrap()),
            Self::SHA512 => Box::new(Hmac::<sha2::Sha512>::new_from_slice(key).unwrap()),
        }
    }

    fn gen_key_iter(
        &self,
        password: &[u8],
        engine_id: &[u8],
    ) -> Vec<u8> {
        let auth_key = AuthKey {
            password: password.to_vec(),
            engine_id: engine_id.to_vec(),
        };
        let cache_res = AUTH_KEY_CACHE.get(&auth_key);
        if let Some(res) = cache_res {
            return res;
        }

        let mut passwd_buf = vec![0; PASSWD_BUF_LEN];
        let mut passwd_index = 0;
        let passwd_len = password.len();
        let mut hasher = self.hasher();

        for _ in (0..ONE_MEGABYTE).step_by(PASSWD_BUF_LEN) {
            for byte in passwd_buf.iter_mut() {
                *byte = password[passwd_index % passwd_len];
                passwd_index += 1;
            }

            hasher.update(&passwd_buf);
        }

        let key = hasher.finalize_reset();
        passwd_buf.clear();
        passwd_buf.extend_from_slice(&key);
        passwd_buf.extend_from_slice(engine_id);
        passwd_buf.extend_from_slice(&key);

        hasher.update(&passwd_buf);
        let res = hasher.finalize().to_vec();
        AUTH_KEY_CACHE.insert(auth_key, res.clone());
        res
    }

    pub fn gen_key(
        &self,
        password: &[u8],
        engine_id: &[u8],
        key_extension: KeyExtension,
        key_len: usize,
    ) -> Vec<u8> {
        assert!(
            !password.is_empty(),
            "password for localized key cannot be empty"
        );

        let mut key = Vec::with_capacity(key_len);
        let mut prev_res = Vec::with_capacity(self.key_len());
        while key.len() < key_len {
            if prev_res.is_empty() {
                prev_res = self.gen_key_iter(password, engine_id);
            } else {
                match key_extension {
                    KeyExtension::Reeder => {
                        prev_res = self.gen_key_iter(&prev_res, engine_id);
                    }
                    KeyExtension::Blumenthal => {
                        let mut hasher = self.hasher();
                        hasher.update(&prev_res);
                        prev_res = hasher.finalize().to_vec();
                    }
                }
            }
            key.extend_from_slice(&prev_res);
        }
        key[..key_len].to_vec()
    }

    pub fn timeliness_check(
        &self,
        engine_boots: u32,
        engine_time: u32,
        engine_id: &[u8],
    ) -> Result<(), Error> {
        if engine_boots >= ENGINE_BOOTS_MAX {
            return Err(Error::NotInTimeWindowError);
        }
        let local_engine = AUTH_ENGINE_CACHE.get(engine_id);
        if let Some(l) = local_engine {
            todo!();
        }
        let new_local_engine = LocalEngine{
            engine_boots,
            engine_time,
            last_access: SystemTime::now(),
        };
        AUTH_ENGINE_CACHE.insert(engine_id.to_vec(), new_local_engine);
        Ok(())
    }

    pub fn integrity_check(
        &self,
        payload: &[u8],
        password: &[u8],
        engine_id: &[u8],
        auth_params: &[u8],
    ) -> Result<(), Error> {
        if auth_params.len() != self.hmac_key_len() {
            return Err(Error::AuthenticationError);
        }
        let key = self.gen_key_iter(password, engine_id);
        let mut hasher = self.hmac_hasher(&key);
        hasher.update(payload);
        let hash_val = hasher.finalize();
        if hash_val[..self.hmac_key_len()] != *auth_params {
            return Err(Error::AuthenticationFailure);
        }
        Ok(())
    }
}

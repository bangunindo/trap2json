use serde_enum_str::Deserialize_enum_str;
use std::fmt::Formatter;
use sha1::digest::DynDigest;
use super::cipher::KeyExtension;

const ONE_MEGABYTE: usize = 1_048_576;
const PASSWD_BUF_LEN: usize = 64;

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
    pub fn key_bits(&self) -> usize {
        match self {
            Self::MD5 => 128,
            Self::SHA128 => 128,
            Self::SHA224 => 224,
            Self::SHA256 => 256,
            Self::SHA384 => 384,
            Self::SHA512 => 512,
        }
    }

    pub fn key_len(&self) -> usize {
        self.key_bits() / 8
    }

    pub fn hasher(&self) -> Box<dyn DynDigest> {
        match self {
            Self::MD5 => Box::new(md5::Md5::default()),
            Self::SHA128 => Box::new(sha1::Sha1::default()),
            Self::SHA224 => Box::new(sha2::Sha224::default()),
            Self::SHA256 => Box::new(sha2::Sha256::default()),
            Self::SHA384 => Box::new(sha2::Sha384::default()),
            Self::SHA512 => Box::new(sha2::Sha512::default()),
        }
    }

    fn gen_key_iter(
        &self,
        password: &[u8],
        engine_id: &[u8],
    ) -> Vec<u8> {
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
        hasher.finalize().to_vec()
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
}

use std::fmt::Formatter;
use serde::Deserialize;
use serde_enum_str::Deserialize_enum_str;
use clap::Parser;
use std::default::Default;
use crate::rsnmp::{auth, cipher};
use validator::Validate;
use std::io::BufReader;
use std::fs::File;


#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Console,
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Console
    }
}

#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[serde(rename = "error")]
    LvlError,
    #[serde(rename = "warn", alias = "warning")]
    LvlWarn,
    #[serde(rename = "info")]
    LvlInfo,
    #[serde(rename = "debug")]
    LvlDebug,
    #[serde(rename = "trace")]
    LvlTrace,
    #[serde(rename = "off")]
    LvlOff,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::LvlInfo
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::LvlError => write!(f, "error"),
            LogLevel::LvlWarn => write!(f, "warn"),
            LogLevel::LvlInfo => write!(f, "info"),
            LogLevel::LvlDebug => write!(f, "debug"),
            LogLevel::LvlTrace => write!(f, "trace"),
            LogLevel::LvlOff => write!(f, "off"),
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Logger {
    #[serde(default)]
    pub level: LogLevel,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            level: Default::default(),
            format: Default::default(),
        }
    }
}

#[derive(Deserialize, Validate, Clone, Debug)]
pub struct Community {
    #[validate(length(min = 1, max = 32))]
    pub name: String,
}

#[derive(Deserialize, Validate, Clone, Debug)]
pub struct User {
    #[validate(length(min = 1, max = 32))]
    pub username: String,
    #[serde(default = "bool::default")]
    pub no_auth: bool,
    #[serde(default = "bool::default")]
    pub require_privacy: bool,
    #[serde(with = "hex::serde")]
    pub engine_id: Vec<u8>,
    pub auth_type: Option<auth::AuthType>,
    #[validate(length(min = 8))]
    pub auth_passphrase: Option<String>,
    pub privacy_protocol: Option<cipher::CipherType>,
    #[validate(length(min = 8))]
    pub privacy_passphrase: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Auth {
    #[serde(default = "bool::default")]
    pub enable: bool,
    #[serde(default = "Vec::new")]
    pub community: Vec<Community>,
    #[serde(default = "Vec::new")]
    pub user: Vec<User>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            enable: false,
            community: vec![],
            user: vec![],
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct TrapdConfig {
    #[serde(default = "default_listening")]
    pub listening: Vec<String>,
    #[serde(default)]
    pub auth: Auth,
}

impl Default for TrapdConfig {
    fn default() -> Self {
        Self {
            listening: default_listening(),
            auth: Default::default(),
        }
    }
}

fn default_listening() -> Vec<String> {
    vec![
        "0.0.0.0:10162".to_string(),
        "[::]:10162".to_string(),
    ]
}

#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(default)]
    pub logger: Logger,
    #[serde(default = "default_num_cpus")]
    pub parse_workers: u64,
    #[serde(default)]
    pub snmptrapd: TrapdConfig,
}


fn default_num_cpus() -> u64 {
    num_cpus::get() as u64
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            logger: Default::default(),
            parse_workers: default_num_cpus(),
            snmptrapd: Default::default(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
}

impl Settings {
    pub fn new() -> Result<Self, anyhow::Error> {
        let args = Args::parse();
        match args.config {
            Some(cnf) => {
                let file = File::open(cnf)?;
                let reader = BufReader::new(file);
                let r = serde_yaml::from_reader(reader)?;
                Ok(r)
            },
            None => Ok(Default::default())
        }
    }
}
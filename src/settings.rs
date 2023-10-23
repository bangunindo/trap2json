use std::fmt::Formatter;
use serde::Deserialize;
use serde_enum_str::Deserialize_enum_str;
use config::{Config, ConfigError, Environment, File};
use clap::Parser;


#[derive(Deserialize_enum_str, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Console,
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

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Logger {
    pub level: LogLevel,
    pub format: LogFormat,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TrapdConfig {
    pub listening: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    pub logger: Logger,
    pub parse_workers: u64,
    pub snmptrapd: TrapdConfig,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let args = Args::parse();
        let mut s = Config::builder()
            .add_source(Environment::with_prefix("T2J"))
            .set_default("parse_workers", num_cpus::get() as u64)?
            .set_default("logger.level", "info")?
            .set_default("logger.format", "console")?
            .set_default("snmptrapd.listening", vec!["0.0.0.0:10162", "[::]:10162"])?;
        if let Some(cnf) = args.config {
            s = s.add_source(File::with_name(cnf.as_str()));
        }
        s.build()?.try_deserialize()
    }
}
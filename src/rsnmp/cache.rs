use std::time::{Duration, SystemTime};
use lazy_static::lazy_static;
use moka::sync::Cache;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct AuthKey {
    pub password: Vec<u8>,
    pub engine_id: Vec<u8>,
}

lazy_static!(
    pub static ref AUTH_KEY_CACHE: Cache<AuthKey, Vec<u8>> = Cache::builder()
    .max_capacity(10_000)
    .time_to_idle(Duration::from_secs(3600))
    .build();
);

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct LocalEngine {
    pub engine_boots: u32,
    pub engine_time: Duration,
    pub last_access: SystemTime,
}

lazy_static!(
    pub static ref AUTH_ENGINE_CACHE: Cache<Vec<u8>, LocalEngine> = Cache::builder()
    .max_capacity(10_000)
    .time_to_idle(Duration::from_secs(24*3600))
    .build();
);
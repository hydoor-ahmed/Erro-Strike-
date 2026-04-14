use serde::{Serialize, Deserialize};

pub mod tcp;
pub mod banner_grab;
pub mod dns_lookup;
pub mod stealth;
pub mod udp;

use std::net::IpAddr;
use std::time::Duration;

use crate::core::fingerprint::StackInfo;

#[derive(Clone)]
pub struct ScanConfig {
    pub target: IpAddr,
    pub timeout: Duration,
    pub threads: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service: String,
    pub banner: Option<String>,
    pub os_guess: Option<String>,
    pub stack_info: Option<StackInfo>,
}
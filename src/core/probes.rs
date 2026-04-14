use serde::Deserialize;
use std::fs;
use regex::Regex;
use lazy_static::lazy_static;

pub enum Probe {
    Tcp(String),
    Udp(Vec<u8>),
    Null
}

#[derive(Deserialize, Debug)]
pub struct ServiceSignature {
    pub name: String,
    pub pattern: String,
}

#[derive(Deserialize, Debug)]
pub struct SignatureDb {
    pub signatures: Vec<ServiceSignature>,
}

lazy_static! {
    static ref SIG_DB: SignatureDb = {
        let content = fs::read_to_string("signatures.toml")
            .expect("❌ Failed to read signatures.toml! Make sure the file exists.");
        toml::from_str(&content).expect("❌ Failed to parse signatures.toml!")
    };
}

pub fn get_probe_for_port(port: u16) -> Probe {
    match port {
        80 | 443 | 8080 => Probe::Tcp("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string()),
        21 => Probe::Null,
        110 | 143 => Probe::Tcp("CAPA\r\n".to_string()),
        53 => Probe::Udp(vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o', b'o',
            b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ]),
        _ => Probe::Tcp("\r\n\r\n".to_string())
    }
}

pub fn identify_service(port: u16, response: &str) -> String {
    for sig in &SIG_DB.signatures {
        if let Ok(re) = Regex::new(&sig.pattern) {
            if let Some(caps) = re.captures(response) {
                let version = caps.get(1).map_or("", |m| m.as_str());
                return format!("{} {}", sig.name, version).trim().to_string();
            }
        }
    }

    match port {
        22 => "SSH (Likely)".to_string(),
        80 | 8080 => "HTTP (Likely)".to_string(),
        443 => "HTTPS (Likely)".to_string(),
        21 => "FTP (Likely)".to_string(),
        53 => "DNS (Likely)".to_string(),
        3306 => "MySQL/MariaDB (Likely)".to_string(),
        _ => {
            if !response.is_empty() {
                response.chars().take(30).collect::<String>().replace("\n", " ").replace("\r", "")
            } else {
                "Unknown Service".to_string()
            }
        }
    }
}
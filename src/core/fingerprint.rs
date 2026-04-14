use lazy_static::lazy_static;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::{Packet, ip::IpNextHeaderProtocols};
use pnet::transport::{TransportChannelType, transport_channel};
use serde::{Deserialize, Serialize};
use std::{fs, net::Ipv4Addr};

#[derive(Deserialize, Debug, Clone)]
pub struct OsSignature {
    pub name: String,
    pub ttl: u8,
    pub window_sizes: Vec<u16>,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
}

#[derive(Deserialize, Debug)]
struct SignatureFile {
    signatures: Vec<OsSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StackInfo {
    pub ttl: u8,
    pub window_size: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
}

lazy_static! {
    static ref OS_DB: Vec<OsSignature> = {
        let content = fs::read_to_string("os_signatures.toml")
            .expect("❌ [CRITICAL] Failed to read os_signatures.toml");
        let file: SignatureFile = toml::from_str(&content)
            .expect("❌ [CRITICAL] Invalid TOML format in os_signatures.toml");
        file.signatures
    };
}

impl StackInfo {
    pub fn from_packet(ip_header: &pnet::packet::ipv4::Ipv4Packet, tcp_header: &TcpPacket) -> Self {
        let mut mss = None;
        let mut wscale = None;

        for option in tcp_header.get_options_iter() {
            match option.get_number().0 {
                2 => {
                    // * Maximum Segment Size
                    let p = option.payload();
                    if p.len() >= 2 {
                        mss = Some(u16::from_be_bytes([p[0], p[1]]));
                    }
                }
                3 => {
                    // * Window Scale
                    let p = option.payload();
                    if !p.is_empty() {
                        wscale = Some(p[0]);
                    }
                }
                _ => {}
            }
        }

        Self {
            ttl: ip_header.get_ttl(),
            window_size: tcp_header.get_window(),
            mss,
            wscale,
        }
    }

    pub fn guess_os(&self, banner: &str) -> String {
        let signatures = OS_DB.iter();
        let mut best_match = "Unknown OS/Hardened ❓".to_string();
        let mut highest_score = 0;

        for sig in signatures {
            let mut score = 0;

            if self.ttl <= sig.ttl && self.ttl >= sig.ttl.saturating_sub(20) {
                score += 40;
            }
            if sig.window_sizes.contains(&self.window_size) {
                score += 20;
            }
            if let (Some(i_mss), Some(s_mss)) = (self.mss, sig.mss) {
                if i_mss == s_mss {
                    score += 15;
                }
            }
            if let (Some(i_ws), Some(s_ws)) = (self.wscale, sig.wscale) {
                if i_ws == s_ws {
                    score += 10;
                }
            }

            score += self.calculate_synergy_bonus(banner, &sig.name);

            if score > highest_score {
                highest_score = score;
                best_match = format!("{} (Confidence: {}%)", sig.name, score.min(100));
            }
        }
        best_match
    }

    fn calculate_synergy_bonus(&self, banner: &str, os_name: &str) -> i32 {
        let mut bonus = 0;
        let banner_lower = banner.to_lowercase();
        let os_lower = os_name.to_lowercase();

        if (banner_lower.contains("linux")
            || banner_lower.contains("ubuntu")
            || banner_lower.contains("debian"))
            && os_lower.contains("linux")
        {
            bonus += 35;
        }

        if (banner_lower.contains("microsoft")
            || banner_lower.contains("iis")
            || banner_lower.contains("win64"))
            && os_lower.contains("windows")
        {
            bonus += 35;
        }

        if banner_lower.contains("google") || banner_lower.contains("gfe") {
            if os_lower.contains("linux") {
                bonus += 40;
            }
        }

        if (banner_lower.contains("microhttpd") || banner_lower.contains("rompager"))
            && os_lower.contains("embedded")
        {
            bonus += 30;
        }

        bonus
    }
}

pub fn capture_stack_info(target_ip: Ipv4Addr, target_port: u16) -> Option<StackInfo> {
let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);    let (_, mut rx) = transport_channel(4096, protocol).ok()?;
    let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);

    let timeout = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        if let Ok((packet, addr)) = iter.next() {
            if addr == target_ip {
                if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                    if tcp_packet.get_source() == target_port
                        && tcp_packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK)
                    {
                        return Some(StackInfo::from_packet(&packet, &tcp_packet));
                    }
                }
            }
        }
    }
    None
}

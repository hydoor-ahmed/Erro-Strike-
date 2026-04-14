use std::net::{IpAddr, ToSocketAddrs};

pub fn get_target_ip(target: &str) -> IpAddr {
    match format!("{}:80", target).to_socket_addrs() {
        Ok(mut addr) => {
            let ip = addr.next().map(|a| a.ip());
            if let Some(ip_addr) = ip {
                println!("🔎 DNS Success! Resolved to: {} -> {:?}", target, ip_addr);
                ip_addr
            } else {
                panic!("❌ Fatal: DNS returned no addresses for {}", target)
            }
        }
        Err(e) => {
            eprintln!("⚠️ DNS Lookup Failed for '{}': {}.", target, e);
            panic!("❌ Fatal: Could not resolve target.");
        }
    }
}

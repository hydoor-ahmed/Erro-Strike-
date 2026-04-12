use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
};

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

fn _default_ports() -> HashMap<u16, (String, String)> {
    let ports: HashMap<u16, (String, String)> = [
        (20, ("FTP Data", "TCP")),
        (21, ("FTP Control", "TCP")),
        (22, ("SSH", "TCP")),
        (23, ("Telnet", "TCP")),
        (25, ("SMTP", "TCP")),
        (53, ("DNS", "TCP/UDP")),
        (67, ("DHCP Server", "UDP")),
        (68, ("DHCP Client", "UDP")),
        (80, ("HTTP", "TCP")),
        (110, ("POP3", "TCP")),
        (123, ("NTP", "UDP")),
        (135, ("RPC", "TCP")),
        (137, ("NetBIOS Name", "UDP")),
        (138, ("NetBIOS Datagram", "UDP")),
        (139, ("NetBIOS Session", "TCP")),
        (143, ("IMAP", "TCP")),
        (161, ("SNMP", "UDP")),
        (389, ("LDAP", "TCP/UDP")),
        (443, ("HTTPS", "TCP")),
        (445, ("SMB", "TCP")),
        (465, ("SMTPS", "TCP")),
        (514, ("Syslog", "UDP")),
        (993, ("IMAPS", "TCP")),
        (995, ("POP3S", "TCP")),
        (1080, ("SOCKS Proxy", "TCP/UDP")),
        (1194, ("OpenVPN", "TCP/UDP")),
        (1433, ("MS SQL Server", "TCP")),
        (1723, ("PPTP", "TCP/UDP")),
        (1812, ("RADIUS", "UDP")),
        (1813, ("RADIUS Accounting", "UDP")),
        (3128, ("HTTP Proxy", "TCP")),
        (3306, ("MySQL", "TCP")),
        (3389, ("RDP", "TCP")),
        (5060, ("SIP", "TCP/UDP")),
        (5061, ("SIP TLS", "TCP")),
        (5432, ("PostgreSQL", "TCP")),
        (5900, ("VNC", "TCP")),
        (6379, ("Redis", "TCP")),
        (8080, ("HTTP Alternate", "TCP")),
        (8443, ("HTTPS Alternate", "TCP")),
    ]
    .iter()
    .map(|(port, (ser, proto))| (*port, (ser.to_string(), proto.to_string())))
    .collect();

    ports
}

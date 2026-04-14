pub fn is_udp_port(port: u16) -> bool {
    match port {
        53 | 161 | 123 | 67 | 68 | 1900 => true,
        _ => false,
    }
}

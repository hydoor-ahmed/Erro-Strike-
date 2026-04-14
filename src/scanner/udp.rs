use std::{net::{Ipv4Addr, SocketAddr, UdpSocket}, time::Duration};

use crate::core::probes::{Probe, get_probe_for_port, identify_service};

pub fn udp_banner_grap(ip: Ipv4Addr, port: u16) -> String {
  let address = SocketAddr::new(ip.into(), port);

  let socket = match UdpSocket::bind("0.0.0.0:0") {
    Ok(s) => s,
    Err(_) => return "Socket Error".to_string(),
  };

  let timeout = Duration::from_millis(1500);
  let _ = socket.set_read_timeout(Some(timeout));

  let probe = get_probe_for_port(port);

  match probe {
    Probe::Udp(payload) => {
      if socket.send_to(&payload, address).is_err() {
        return "Send Error".to_string();
      }

      let mut buffer = [0u8; 1024];
      match socket.recv_from(&mut buffer) {
        Ok((n, _)) if n > 0 => {
          let security_flags = parse_dns_flags(&buffer[..n]);
          let amplification = (n as f32 / payload.len() as f32).round();

          let res = String::from_utf8_lossy(&buffer[..n]);
          let service_name = identify_service(port, &res);

          format!("{} | {} [Amp: {}x]", service_name, security_flags, amplification)
        }
        _ => "No Responese (UDP)".to_string()
      }
    }
    _ => "Not a UDP Port".to_string(),
  }
}

pub fn parse_dns_flags(buffer: &[u8]) -> String {
    if buffer.len() < 12 { return "Invalid DNS Response".to_string(); }

    let byte_2 = buffer[2];
    let byte_3 = buffer[3];

    let is_response = (byte_2 >> 7) & 1 == 1;
    let is_authoritative = (byte_2 >> 2) & 1 == 1;
    let is_recursion_available = (byte_3 >> 7) & 1 == 1;
    let rcode = byte_3 & 0x0F;

    let mut security_info = Vec::new();

    if is_response {
        if is_recursion_available {
            security_info.push("VULN: Open Resolver (Recursion) ⚠️");
        }
        if is_authoritative {
            security_info.push("Auth: Yes");
        }
        if rcode == 0 {
            security_info.push("Status: NoError");
        }
    }

    security_info.join(" | ")
}

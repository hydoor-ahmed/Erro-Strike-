use native_tls::TlsConnector;

use crate::core::probes::{Probe, get_probe_for_port, identify_service};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;

pub fn banner_grab(ip: Ipv4Addr, port: u16) -> String {
    let address = format!("{}:{}", ip, port);
    let timeout = Duration::from_millis(2000);

    let stream_result = TcpStream::connect_timeout(&address.parse().unwrap(), timeout);

    match stream_result {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let mut buffer = [0u8; 1024];

            let probe = get_probe_for_port(port);

            match probe {
                Probe::Tcp(request) => {
                    if port == 443 || port == 853 || port == 993 {
                        return grab_tls_banner(&address, Duration::from_millis(1500));
                    }

                    let final_req = if port == 80 || port == 8080 {
                        "GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
                    } else {
                        request.as_str()
                    };

                    let _ = stream.write_all(final_req.as_bytes());
                    match stream.read(&mut buffer) {
                        Ok(n) if n > 0 => {
                            let response = String::from_utf8_lossy(&buffer[..n]);
                            identify_service(port, &response)
                        }
                        _ => "No Response".to_string(),
                    }
                }
                Probe::Null => match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        identify_service(port, &response)
                    }
                    _ => "No Banner (Passive)".to_string(),
                },
                Probe::Udp(_) => "Error: UDP Probe in TCP Stream".to_string(),
            }
        }
        Err(_) => "Down".to_string(),
    }
}

fn grab_tls_banner(address: &str, timeout: Duration) -> String {
    let hostname = address.split(':').next().unwrap_or(address);

    let stream = match TcpStream::connect_timeout(&address.parse().unwrap(), timeout) {
        Ok(s) => s,
        Err(_) => return "Down".to_string(),
    };
    let _ = stream.set_read_timeout(Some(timeout));

    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .unwrap();

    match connector.connect(hostname, stream) {
        Ok(mut tls_stream) => {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                hostname
            );
            let _ = tls_stream.write_all(request.as_bytes());

            let mut buffer = [0u8; 1024];
            match tls_stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let res = String::from_utf8_lossy(&buffer[..n]);
                    format!("{} | SSL Verified ✅", identify_service(443, &res))
                }
                _ => "SSL/TLS Active (No App Data)".to_string(),
            }
        }
        Err(e) => format!("TLS Error: {}", e),
    }
}

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;

pub fn banner_grab(ip: Ipv4Addr, port: u16) -> String {
    let address = format!("{}:{}", ip, port);
    
    let stream_result = TcpStream::connect_timeout(
        &address.parse().unwrap(), 
        Duration::from_millis(1500)
    );

    match stream_result {
        Ok(mut stream) => {
            let mut buffer = [0; 1024];
            // تعيين Timeout للقراءة حتى ما يعلك البرنامج إذا السيرفر ساكت
            let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));

            // المحاولة الأولى: قراءة الـ Banner التلقائي (مثل SSH أو FTP)
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .replace("\n", " ")
                    .replace("\r", ""),
                
                _ => {
                    if matches!(port, 80 | 8080 | 443) {
                        let _ = stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n");
                        let mut http_buffer = [0; 1024];
                        if let Ok(n) = stream.read(&mut http_buffer) {
                            if n > 0 {
                                String::from_utf8_lossy(&http_buffer[..n])
                                    .split("\r")
                                    .next()
                                    .unwrap_or("HTTP Server")
                                    .to_string()
                            } else {
                                "No Banner (HTTP Quiet).".to_string()
                            }
                        } else {
                            "No Banner (Timeout)".to_string()
                        }
                    } else {
                        "No Version Info".to_string()
                    }
                }
            }
        }
        Err(_) => "Connection Failed".to_string(),
    }
}

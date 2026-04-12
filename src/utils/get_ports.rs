use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn get_sys_ports() -> HashMap<u16, (String, String)> {
    let mut ports = HashMap::new();
    let path = "/etc/services";

    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with('#') || l.trim().is_empty() {
                    continue;
                }

                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 {
                    let service_name = parts[0].to_string();

                    if let Some((port_str, proto_str)) = parts[1].split_once('/') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            // نفحص فقط الـ TCP حالياً
                            if proto_str.to_lowercase() == "tcp" && port <= 1000 || port == 31337 {
                                ports
                                    .entry(port)
                                    .or_insert((service_name, "TCP".to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    ports
}

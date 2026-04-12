use std::{
    collections::HashMap,
    net::{IpAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

use indicatif::ProgressBar;

use crate::scanner::banner_grab::banner_grab;
use crate::scanner::{ScanConfig, ScanResult};

pub fn run_scan(
    config: ScanConfig,
    ports: HashMap<u16, (String, String)>,
    pb: ProgressBar,
) -> (Vec<ScanResult>, std::time::Duration) {
    let mut handles = vec![];
    let open_ports = Arc::new(Mutex::new(HashMap::new()));

    let start_time = Instant::now();
    let results = Arc::new(Mutex::new(vec![]));

    let ports_vec: Vec<(u16, (String, String))> = ports.into_iter().collect();

    for chunk in ports_vec.chunks(config.threads) {
        for (port, (service, _proto)) in chunk.to_owned() {
            let pb = pb.clone();
            let addr = std::net::SocketAddr::new(config.target, port);

            let open_ports = Arc::clone(&open_ports);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                match TcpStream::connect_timeout(&addr, config.timeout) {
                    Ok(stream) => {
                        let _ = stream.set_read_timeout(Some(config.timeout));

                        let version_info = banner_grab(
                            match config.target {
                                IpAddr::V4(v4) => v4,
                                IpAddr::V6(_) => panic!("IPv6 Is Not Supported."),
                            },
                            port,
                        );

                        let result = ScanResult {
                            port,
                            is_open: true,
                            banner: Some(version_info.clone()),
                            service: service.to_string(),
                        };
                        let mut res = results.lock().unwrap();
                        res.push(result);

                        let mut op = open_ports.lock().unwrap();
                        op.insert(port, (service.to_string(), version_info.clone()));
                        pb.println(format!("✨ Found: Port {}", port));
                    }
                    Err(_) => {} /*println!("❌ Closed Port {}", port)*/
                }
                pb.inc(1);
            });
            handles.push(handle);
        }
    }

    for h in handles {
        let _ = h.join();
    }

    pb.finish_with_message("Done!");
    let time_taken = start_time.elapsed();
    let final_results = results.lock().unwrap().clone();

    (final_results, time_taken)
}

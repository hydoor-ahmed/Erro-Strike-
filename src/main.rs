use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

mod scanner;
mod ui;
mod utils;

use clap::Parser;
use ui::{
    banner::{banner, clear_screen},
    progress::create_progress_bar,
    results::display_results,
};

use crate::scanner::{
    ScanConfig, banner_grab::banner_grab, networking::get_target_ip, stealth::run_stealth_scan,
    tcp::run_scan,
};

use crate::utils::{
    cli::CliArgs, export::save_to_file, get_ports::get_sys_ports, timer::start_timer_thread,
};

fn main() {
    let args = CliArgs::parse();

    clear_screen();
    banner(&args.target);

    let ports = get_sys_ports();
    let target_ip = get_target_ip(&args.target);
    let ports_vec: Vec<u16> = ports.keys().copied().collect();
    let port_arc = Arc::new(ports);

    let pb = create_progress_bar(ports_vec.len() as u64);
    let is_running = Arc::new(AtomicBool::new(true));
    let timer_handle = start_timer_thread(Arc::clone(&is_running), pb.clone());

    let scan_mode = if args.stealth {
        "Stealth (SYN) 👻"
    } else {
        "Connect"
    };

    let (mut results, duration) = if args.stealth {
        let ipv4 = match target_ip {
            IpAddr::V4(v4) => v4,
            _ => panic!("Stealth Scan Requires IPv4!"),
        };
        run_stealth_scan(ipv4, ports_vec, port_arc)
    } else {
        let config = ScanConfig {
            target: target_ip,
            threads: args.threads,
            timeout: Duration::from_millis(args.timeout),
        };
        run_scan(config, (*port_arc).clone(), pb)
    };

    is_running.store(false, Ordering::SeqCst);
    let _ = timer_handle.join();

    if results.iter().any(|r| r.is_open) {
        println!("\n🧬 Grabbing service banners...");
        for result in results.iter_mut().filter(|r| r.is_open) {
            if let IpAddr::V4(ipv4) = target_ip {
                result.banner = Some(banner_grab(ipv4, result.port));
            }
        }
    }

    display_results(results.clone(), &duration);

    if let Some(output_path) = args.output {
        let _ = save_to_file(
            &output_path,
            &results,
            &target_ip,
            &args.target,
            scan_mode,
            &duration,
        );
    }
}

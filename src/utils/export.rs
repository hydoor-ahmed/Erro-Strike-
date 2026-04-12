use crate::scanner::ScanResult;
use crate::utils::service_info::get_service_info;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;

pub fn save_to_file(
    file_path: &str,
    results: &Vec<ScanResult>,
    target_ip: &IpAddr,
    original_target: &str,
    scan_mode: &str,
    duration: &Duration,
) -> std::io::Result<()> {
    if file_path.ends_with(".json") {
        let json = serde_json::to_string_pretty(results)?;
        let mut file = File::create(file_path)?;
        file.write_all(json.as_bytes())?;
    } else {
        let mut file = File::create(file_path)?;
        writeln!(
            file,
            "⚡ ErrorStrike Scan Report ({}).",
            env!("CARGO_PKG_VERSION")
        )?;
        writeln!(file, "============================")?;
        writeln!(
            file,
            "ℹ️ Scan Info:\n- 🎯 Target: {} -- {}\n- Scan Type: {}\n- ⌛ Time Elapsed: {}s",
            target_ip,
            original_target,
            scan_mode,
            duration.as_secs()
        )?;
        writeln!(file, "============================\n")?;
        for (i, res) in results.iter().enumerate() {
            let (ser, emoji) = get_service_info(&res.service);
            writeln!(
                file,
                "{}. Port: {}\t|\t Service: {}({}) {}\t|\t Banner: {:?}",
                i,
                res.port,
                res.service,
                ser,
                emoji,
                res.banner.clone().unwrap()
            )?;
        }
    }
    Ok(())
}

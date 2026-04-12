use crate::{scanner::ScanResult, utils::service_info::get_service_info};

pub fn display_results(results: Vec<ScanResult>, duration: &std::time::Duration) {
    println!(
        "\n\n🏁 Done. Found {} open ports, ⏱️ Total Time Elapsed: {:.2?}.\n",
        results.len(),
        duration
    );

    println!(r"🔌 {: <10} ⚙️ {: <37} 🔰 Banner", "Port", "Service (Desc)");
    println!("{}", "-".repeat(75)); // خط فاصل للترتيب

    for res in results {
        let (ser_desc, emoji) = get_service_info(&res.service);

        let service_full = format!("{}({}) {}", res.service, ser_desc, emoji);

        println!(
            "{: <12} {: <40} {}",
            res.port,
            service_full,
            res.banner.as_deref().unwrap_or("No banner")
        );
    }
}

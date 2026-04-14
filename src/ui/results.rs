use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};

use crate::{scanner::ScanResult, utils::service_info::get_service_info};

pub fn display_results(results: Vec<ScanResult>, duration: &std::time::Duration) {
    println!(
        "\n\n🏁 Done. Found {} Open Ports, ⏱️ Total Time Elapsed: {:.2?}.\n",
        results.len(),
        duration
    );

    let mut table = Table::new();

    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("🔌 Port").fg(Color::Cyan),
            Cell::new("⚙️ Service").fg(Color::Cyan),
            Cell::new("🔰 Banner").fg(Color::Cyan),
            Cell::new("🐧 OS Guess").fg(Color::Cyan),
        ]);

    for res in results {
        let (ser_desc, emoji) = get_service_info(&res.service);
        let service_display = format!("{} {} \n({})", res.service, emoji, ser_desc);

        table.add_row(vec![
            Cell::new(res.port).fg(Color::Yellow),
            Cell::new(service_display),
            Cell::new(res.banner.as_deref().unwrap_or("No Banner")),
            Cell::new(res.os_guess.as_deref().unwrap_or("Unknown")).fg(Color::Green),
        ]);
    }
    println!("{table}");
}

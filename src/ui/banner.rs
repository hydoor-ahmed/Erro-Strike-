use colored::*;
use std::io::{stdout, Write};

pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // * Clear Screen and Move Cursor to (1,1).
    stdout().flush().unwrap();
}

pub fn banner(target: &str) {
    let tool_name = "ErrorStrike".bright_blue();
    let tool_version = format!("v{}", env!("CARGO_PKG_VERSION")).yellow();
    let tool_type = "Port Scanner".blue();
    let target_txt = format!("{} {}", "Target:".red(), target.bright_green());

    let b = r"
          __________                   ____________       ___________       
          ___  ____/_____________________  ___/_  /__________(_)__  /______ 
          __  __/  __  ___/_  ___/  __ \____ \_  __/_  ___/_  /__  //_/  _ \
          _  /___  _  /   _  /   / /_/ /___/ // /_ _  /   _  / _  ,<  /  __/
          /_____/  /_/    /_/    \____//____/ \__/ /_/    /_/  /_/|_| \___/";

    let info = format!(
        "
\t\t\t>> [ {} {} | {}] <<
\t\t\t>> [ {}        ] <<",
        tool_name, tool_version, tool_type, target_txt
    );

    println!("{}\n{}\n\n", b.cyan(), info);
}

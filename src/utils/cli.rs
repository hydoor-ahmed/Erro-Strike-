use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ErroStrike")]
#[command(author = "Error404")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "A High-Performance Port Scanner Build in Rust", long_about = None)]
pub struct  CliArgs {
  pub target: String,

  #[arg(short, long, default_value_t = 100)]
  pub threads: usize,

  #[arg(long, default_value_t = 3000)]
  pub timeout: u64,

  #[arg(short, long)]
  pub output: Option<String>,

  #[arg(short, long, action = clap::ArgAction::SetTrue)]
  pub stealth: bool,

  #[arg[short, long, default_value_t = 0]]
  pub decoys: u8,
}


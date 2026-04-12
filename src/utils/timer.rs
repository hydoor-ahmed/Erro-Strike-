use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use indicatif::ProgressBar;


pub fn start_timer_thread(running: Arc<AtomicBool>, pb: ProgressBar) -> thread::JoinHandle<()> {
  thread::spawn(move || {
    let start_time = Instant::now();
    while running.load(Ordering::SeqCst) {
      let elapsed = start_time.elapsed();

      let time_str = format!("{:02}:{:02}",
      elapsed.as_secs() / 60,
      elapsed.as_secs() % 60
    );
    pb.set_message(time_str);

        thread::sleep(Duration::from_millis(500));
    }
  })
}

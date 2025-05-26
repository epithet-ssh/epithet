use clap::Args;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Args)]
pub struct InfoArgs {
    /// Show system time
    #[arg(short, long)]
    time: bool,

    /// Show hostname
    #[arg(short = 'n', long)]
    hostname: bool,

    /// Show all information
    #[arg(short, long)]
    all: bool,
}

pub fn execute(args: InfoArgs) -> Result<(), String> {
    // If no specific flags are set or --all is specified, show everything
    let show_all = args.all || (!args.time && !args.hostname);

    if args.time || show_all {
        show_time()?;
    }

    if args.hostname || show_all {
        show_hostname()?;
    }

    Ok(())
}

fn show_time() -> Result<(), String> {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Error getting system time: {}", e))?
        .as_secs();
    
    println!("Current timestamp: {}", timestamp);
    Ok(())
}

fn show_hostname() -> Result<(), String> {
    let hostname = gethostname::gethostname()
        .to_string_lossy()
        .to_string();
    
    println!("Hostname: {}", hostname);
    Ok(())
}
use clap::Parser;
use std::process;

mod commands;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Set the verbosity level
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<commands::Command>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        if cli.verbose {
            println!("Executing command: {:?}", command);
        }

        if let Err(err) = command.execute() {
            eprintln!("Error: {}", err);
            process::exit(1);
        }
    } else {
        // When no command is provided, print the help message and exit
        // TODO Seems like a hack, but works :-)
        let _ = Cli::parse_from(&["epithet", "--help"]);
        process::exit(1);
    }
}

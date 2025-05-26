pub mod greet;
pub mod info;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Greet someone by name
    #[command(name = "greet")]
    Greet(greet::GreetArgs),

    /// Display information about the system
    #[command(name = "info")]
    Info(info::InfoArgs),
}

impl Command {
    pub fn execute(self) -> Result<(), String> {
        match self {
            Command::Greet(args) => greet::execute(args),
            Command::Info(args) => info::execute(args),
        }
    }
}

pub mod agent;
pub mod proxy;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Greet someone by name
    #[command(name = "proxy")]
    Greet(proxy::ProxyArgs),

    /// Display information about the system
    #[command(name = "agent")]
    Info(agent::AgentArgs),
}

impl Command {
    pub fn execute(self) -> Result<(), String> {
        match self {
            Command::Greet(args) => proxy::execute(args),
            Command::Info(args) => agent::execute(args),
        }
    }
}

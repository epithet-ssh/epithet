pub mod agent;
pub mod auth;
pub mod proxy;

use clap::Subcommand;
use std::error::Error;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Authenticate and setup agent
    #[command(name = "auth", alias = "match")]
    Auth(auth::AuthArgs),

    /// Start the agent
    #[command(name = "agent")]
    Agent(agent::AgentArgs),

    /// Start the agent
    #[command(name = "proxy")]
    Proxy(proxy::ProxyArgs),
}

impl Command {
    pub fn execute(self) -> Result<(), Box<dyn Error>> {
        match self {
            Command::Auth(args) => auth::execute(args),
            Command::Agent(args) => agent::execute(args),
            Command::Proxy(args) => proxy::execute(args),
        }
    }
}

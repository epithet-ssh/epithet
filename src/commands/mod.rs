pub mod agent;
pub mod auth;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Greet someone by name
    #[command(name = "auth", alias = "match")]
    Auth(auth::AuthArgs),

    /// Display information about the system
    #[command(name = "agent")]
    Agent(agent::AgentArgs),
}

impl Command {
    pub fn execute(self) -> Result<(), String> {
        match self {
            Command::Auth(args) => auth::execute(args),
            Command::Agent(args) => agent::execute(args),
        }
    }
}

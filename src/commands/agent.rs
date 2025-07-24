use clap::Args;
use std::error::Error;

/// Start the epithet agent
#[derive(Debug, Args)]
pub struct AgentArgs {}

pub fn execute(_: AgentArgs) -> Result<(), Box<dyn Error>> {
    println!("starting epithet agent");
    Ok(())
}

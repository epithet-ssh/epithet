use clap::Args;

/// Start the epithet agent
#[derive(Debug, Args)]
pub struct AgentArgs {}

pub fn execute(_: AgentArgs) -> Result<(), String> {
    println!("starting epithet agent");
    Ok(())
}

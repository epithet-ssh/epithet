use clap::Args;

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// host
    #[arg(short = 'H', long = "host")]
    host: String,

    /// user
    #[arg(short, long)]
    user: String,
}

pub fn execute(_: ProxyArgs) -> Result<(), String> {
    println!("run ssh now :-)");
    Ok(())
}

use clap::Args;
use directories::ProjectDirs;
use std::error::Error;

#[derive(Debug, Args)]
pub struct AuthArgs {
    /// host
    #[arg(short = 'H', long = "host")]
    host: String,

    /// user
    #[arg(short, long)]
    user: String,

    /// socket
    #[arg(short, long)]
    socket: String,
}

pub fn execute(args: AuthArgs) -> Result<(), Box<dyn Error>> {
    if let Some(proj_dirs) = ProjectDirs::from("dev", "epithet", "epithet-agent") {
        println!("{}", proj_dirs.config_dir().display());
        let agent_dir = proj_dirs.data_dir().join("agent").join(args.socket);

        println!("data\t{}", proj_dirs.data_dir().display());
        println!("agent\t{}", agent_dir.display());
    } else {
        panic!("Noooooo!");
    }

    Ok(())
}

use clap::Args;

#[derive(Debug, Args)]
pub struct GreetArgs {
    /// Name of the person to greet
    #[arg(short, long)]
    name: String,

    /// Use formal greeting
    #[arg(short, long)]
    formal: bool,
}

pub fn execute(args: GreetArgs) -> Result<(), String> {
    let greeting = if args.formal {
        format!("Good day, {}.", args.name)
    } else {
        format!("Hello, {}!", args.name)
    };
    
    println!("{}", greeting);
    Ok(())
}
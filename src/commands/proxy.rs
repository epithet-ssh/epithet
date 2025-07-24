use clap::Args;
use std::error::Error;
use tokio::net::TcpStream;

/// invoked for ProxyCommand
#[derive(Debug, Args)]
pub struct ProxyArgs {}

pub fn execute(_: ProxyArgs) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(run())?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut socket = TcpStream::connect("m0003:22").await?;
    let (mut reader, mut writer) = socket.split();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let f1 = tokio::io::copy(&mut reader, &mut stdout);
    let f2 = tokio::io::copy(&mut stdin, &mut writer);

    let _ = futures::try_join!(f1, f2);
    Ok(())
}

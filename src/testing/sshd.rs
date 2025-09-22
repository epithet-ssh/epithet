use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::TcpListener;

#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub async fn start(_ca_key: &ssh_key::PublicKey) -> Result<Self, Box<dyn std::error::Error>> {
        // obtain a random ephemeral port to listen on
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        drop(listener);

        // obtain local user

        Ok(Server { addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {

    use crate::ssh;

    use super::*;
    use assertor::*;

    #[tokio::test]
    async fn test_server_start() -> Result<(), anyhow::Error> {
        let key = ssh::generate_private_key()?;
        let s = Server::start(key.public_key()).await;
        assert_that!(s).is_ok();
        let srv = s.unwrap();
        assert_that!(srv.addr().port()).is_greater_than(1023);
        assert_that!(srv.addr().port()).is_less_than(65535);
        Ok(())
    }
}

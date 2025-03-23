use std::io;

use socks5_server::Server;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        let e = io::Error::other(format!(
            "Usage: {} <addr:port>\n\nExample: {} 0.0.0.0:1080",
            args[0], args[0]
        ));
        return Err(e);
    }

    Server::new()
        .user_pass("username", "password")
        .run(&args[1])
        .await
}

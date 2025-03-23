use socks5_server::Server;
use std::io;
use std::net::ToSocketAddrs;

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

    let Args { addr, user_pass } = parse(&args[1])?;

    let mut server = Server::new();
    if let Some(UserPass { username, password }) = user_pass {
        server.user_pass(username, password);
    }
    server.run(addr).await
}

struct UserPass {
    username: String,
    password: String,
}

struct Args {
    addr: String,
    user_pass: Option<UserPass>,
}

///
/// ```rust
/// parse("127.0.0.1:1080");
/// parse("username:password@127.0.0.1:1080");
/// ```
fn parse(arg: &str) -> io::Result<Args> {
    let args = arg.split('@').collect::<Vec<_>>();

    let addr;
    let user_pass;

    if args.len() == 1 {
        addr = args[0];
        user_pass = None;
    } else {
        addr = args[1];
        if args[0].is_empty() {
            user_pass = None;
        } else {
            let vec = args[0].split(':').collect::<Vec<_>>();
            if vec.len() != 2 {
                let e = io::Error::other("Invalid username:password");
                return Err(e);
            }
            user_pass = Some(UserPass {
                username: vec[0].to_string(),
                password: vec[1].to_string(),
            });
        }
    }
    let _ = addr.to_socket_addrs()?;

    Ok(Args {
        addr: addr.to_string(),
        user_pass,
    })
}


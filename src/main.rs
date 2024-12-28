mod method_selection;
mod request_reply;

use std::net::SocketAddr;

use method_selection::*;
use request_reply::*;

use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const SOCKS_VERSION_5: u8 = 0x05;
const NODELAY: bool = true;
const TTL: u32 = 64;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        return Err(anyhow::anyhow!("Usage: {} <addr:port>\n\nExample: {} 0.0.0.0:1080", args[0], args[0]));
    }

    let addr: SocketAddr = args[1].parse()?;

    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    println!("Listening on local address: {:?}", local_addr);

    while let Ok((mut conn, addr)) = listener.accept().await {
        conn.set_nodelay(crate::NODELAY)?;
        conn.set_ttl(crate::TTL)?;

        tokio::spawn(async move {
            println!("new connection from: {:?}", addr);
            match handle(&mut conn).await {
                Ok(_) => {
                    // println!("ok");
                }
                Err(e) => {
                    eprintln!("err: {e}");
                    let _ = conn.shutdown().await;
                }
            }
        });
    }
    Ok(())
}

async fn handle(conn: &mut TcpStream) -> io::Result<()> {
    method_select(conn).await?;
    request(conn).await
}

async fn method_select(conn: &mut TcpStream) -> io::Result<()> {
    let method_selection_request = MethodSelectionRequest::from_stream(conn).await?;
    println!("method_selection_request: {:?}", method_selection_request);

    if method_selection_request.ver != crate::SOCKS_VERSION_5 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS version {}", method_selection_request.ver),
        ));
    }
    if method_selection_request
        .methods
        .iter()
        .any(|m| *m == Method::NoAuthenticationRequired)
    {
        MethodSelectionResponse::default()
            .writeto_stream(conn)
            .await?;
    } else {
        MethodSelectionResponse::unacceptable()
            .writeto_stream(conn)
            .await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported method"),
        ));
    }
    Ok(())
}

async fn request(conn: &mut TcpStream) -> io::Result<()> {
    let request = Request::from_stream(conn).await?;
    println!("request: {:?}", request);
    match request.cmd {
        Cmd::Connect => {
            let mut server_stream = match connect(&request).await {
                Ok(stream) => {
                    Reply::new(ReplyStatus::Succeeded, request.address.clone())
                        .writeto_stream(conn)
                        .await?;
                    stream
                }
                Err(err) => {
                    Reply::new(err.kind().into(), request.address.clone())
                        .writeto_stream(conn)
                        .await?;
                    return Err(err);
                }
            };

            println!("connected to server: {:?}", server_stream.peer_addr()?);

            io::copy_bidirectional(conn, &mut server_stream).await?;
        }
        Cmd::Bind | Cmd::Udp => {
            Reply::new(ReplyStatus::CommandNotSupported, request.address.clone())
                .writeto_stream(conn)
                .await?;
        }
    }
    Ok(())
}

async fn connect(request: &Request) -> io::Result<TcpStream> {
    let stream = match request.address.addr {
        InnerAddress::SocketAddr(ref addr) => TcpStream::connect(addr).await?,
        InnerAddress::DomainAddr(ref domain, port) => {
            TcpStream::connect((domain.as_str(), port)).await?
        }
    };
    stream.set_nodelay(crate::NODELAY)?;
    stream.set_ttl(crate::TTL)?;
    Ok(stream)
}

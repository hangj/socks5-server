mod method_selection;
mod request_reply;
mod usr_pwd_auth;

use std::sync::Arc;

use method_selection::*;
use request_reply::*;
use usr_pwd_auth::*;

use std::io;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

const SOCKS_VERSION_5: u8 = 0x05;
const NODELAY: bool = true;
const TTL: u32 = 64;

#[derive(Debug, Default)]
pub struct Server {
    name_pass: Arc<Option<(String, String)>>,
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user_pass<S: Into<String>>(&mut self, username: S, password: S) -> &mut Self {
        self.name_pass = Arc::new(Some((username.into(), password.into())));
        self
    }

    pub async fn run<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        println!("Listening on address: {:?}", local_addr);

        while let Ok((mut conn, addr)) = listener.accept().await {
            let _ = conn.set_nodelay(NODELAY);
            let _ = conn.set_ttl(TTL);

            let name_pass = self.name_pass.clone();

            tokio::spawn(async move {
                println!("new connection from: {:?}", addr);
                match Self::handle(&mut conn, name_pass).await {
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

    async fn handle(
        conn: &mut TcpStream,
        name_pass: Arc<Option<(String, String)>>,
    ) -> io::Result<()> {
        Self::method_select(conn, name_pass).await?;
        Self::request(conn).await
    }

    async fn method_select(
        conn: &mut TcpStream,
        name_pass: Arc<Option<(String, String)>>,
    ) -> io::Result<()> {
        let method_selection_request = MethodSelectionRequest::from_stream(conn).await?;
        println!("method_selection_request: {:?}", method_selection_request);

        if method_selection_request.ver != crate::SOCKS_VERSION_5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS version {}", method_selection_request.ver),
            ));
        }

        if method_selection_request.methods().iter().any(|m| {
            *m == if name_pass.is_none() {
                Method::NoAuthenticationRequired.into()
            } else {
                Method::UsernamePassword.into()
            }
        }) {
            match name_pass.as_ref() {
                None => {
                    MethodSelectionResponse::no_auth_method()
                        .writeto_stream(conn)
                        .await
                }
                Some((name, pass)) => {
                    MethodSelectionResponse::username_password_method()
                        .writeto_stream(conn)
                        .await?;

                    let auth = UsrPwdAuth::from_stream(conn).await?;

                    if auth.uname() == name.as_bytes() && auth.passwd() == pass.as_bytes() {
                        AuthResponseStatus::success().writeto_stream(conn).await
                    } else {
                        AuthResponseStatus::failure().writeto_stream(conn).await?;
                        Err(io::Error::other("username or password incorrect"))
                    }
                }
            }
        } else {
            MethodSelectionResponse::no_acceptable_method()
                .writeto_stream(conn)
                .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported method",
            ))
        }
    }

    async fn request(conn: &mut TcpStream) -> io::Result<()> {
        let request = Request::from_stream(conn).await?;
        println!("request: {:?}", request);
        match request.cmd {
            Cmd::Connect => {
                let mut server_stream = match Self::connect(&request.address).await {
                    Ok(stream) => {
                        Reply::new(ReplyStatus::Succeeded, &request.address)
                            .writeto_stream(conn)
                            .await?;
                        stream
                    }
                    Err(err) => {
                        Reply::new(err.kind().into(), &request.address)
                            .writeto_stream(conn)
                            .await?;
                        return Err(err);
                    }
                };

                println!("connected to server: {:?}", server_stream.peer_addr()?);

                tokio::io::copy_bidirectional(conn, &mut server_stream).await?;
            }
            Cmd::Bind | Cmd::Udp => {
                Reply::new(ReplyStatus::CommandNotSupported, &request.address)
                    .writeto_stream(conn)
                    .await?;
            }
        }
        Ok(())
    }

    async fn connect(address: &Address) -> io::Result<TcpStream> {
        let stream = match address.addr {
            InnerAddress::SocketAddr(ref addr) => TcpStream::connect(addr).await?,
            InnerAddress::DomainAddr(ref domain, port) => {
                TcpStream::connect((domain.as_str(), port)).await?
            }
        };
        stream.set_nodelay(crate::NODELAY)?;
        stream.set_ttl(crate::TTL)?;
        Ok(stream)
    }
}

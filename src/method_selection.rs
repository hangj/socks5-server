/// https://www.rfc-editor.org/rfc/rfc1928.html
/// Procedure for TCP-based clients
///
///    When a TCP-based client wishes to establish a connection to an object
///    that is reachable only via a firewall (such determination is left up
///    to the implementation), it must open a TCP connection to the
///    appropriate SOCKS port on the SOCKS server system.  The SOCKS service
///    is conventionally located on TCP port 1080.  If the connection
///    request succeeds, the client enters a negotiation for the
///    authentication method to be used, authenticates with the chosen
///    method, then sends a relay request.  The SOCKS server evaluates the
///    request, and either establishes the appropriate connection or denies
///    it.

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

///
/// The client connects to the server, and sends a version
/// identifier/method selection message:
///
/// +----+----------+----------+  
/// |VER | NMETHODS | METHODS  |  
/// +----+----------+----------+  
/// | 1  |    1     | 1 to 255 |  
/// +----+----------+----------+  
///
#[allow(dead_code)]
#[derive(Debug)]
pub struct MethodSelectionRequest {
    pub ver: u8, // 0x05
    nmethods: u8,
    pub methods: Vec<Method>, // 1 to 255
}

impl MethodSelectionRequest {
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let nmethods = s.read_u8().await?;
        let mut methods = vec![0u8; nmethods as usize];
        s.read_exact(&mut methods).await?;

        Ok(Self {
            ver,
            nmethods,
            methods: methods
                .into_iter()
                .map(|m| m.into())
                .collect::<Vec<Method>>(),
        })
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.ver).await?;
        s.write_u8(self.nmethods).await?;
        let methods = self.methods.iter().map(|m|(*m).into()).collect::<Vec<u8>>();
        assert_eq!(self.nmethods as usize, methods.len());
        s.write(&methods).await?;
        Ok(())
    }
}

///  The server selects from one of the methods given in METHODS, and
/// sends a METHOD selection message:
///
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
pub struct MethodSelectionResponse {
    ver: u8,
    method: Method,
}

impl MethodSelectionResponse {
    pub fn unacceptable() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::UnacceptableMethod,
        }
    }
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let method = s.read_u8().await?.into();
        Ok(Self { ver, method })
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u8(self.ver).await?;
        stream.write_u8(self.method.into()).await?;
        Ok(())
    }
}

impl Default for MethodSelectionResponse {
    fn default() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::NoAuthenticationRequired,
        }
    }
}

/// The values currently defined for METHOD are:
///
/// o  X'00' NO AUTHENTICATION REQUIRED
/// o  X'01' GSSAPI
/// o  X'02' USERNAME/PASSWORD
/// o  X'03' to X'7F' IANA ASSIGNED
/// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
/// o  X'FF' NO ACCEPTABLE METHODS
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    NoAuthenticationRequired,
    Gssapi,
    UsernamePassword,
    UnacceptableMethod,
}

impl Method {
    const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    const GSSAPI: u8 = 0x01;
    const USERNAME_PASSWORD: u8 = 0x02;
    const UNACCEPTABLE_METHOD: u8 = 0xff;
}

impl From<u8> for Method {
    fn from(value: u8) -> Self {
        match value {
            Self::NO_AUTHENTICATION_REQUIRED => Self::NoAuthenticationRequired,
            Self::GSSAPI => Self::Gssapi,
            Self::USERNAME_PASSWORD => Self::UsernamePassword,
            _ => Self::UnacceptableMethod,
        }
    }
}

impl Into<u8> for Method {
    fn into(self) -> u8 {
        match self {
            Method::NoAuthenticationRequired => Self::NO_AUTHENTICATION_REQUIRED,
            Method::Gssapi => Self::GSSAPI,
            Method::UsernamePassword => Self::USERNAME_PASSWORD,
            Method::UnacceptableMethod => Self::UNACCEPTABLE_METHOD,
        }
    }
}

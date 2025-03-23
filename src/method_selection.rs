#![allow(dead_code)]

//! https://www.rfc-editor.org/rfc/rfc1928.html
//! Procedure for TCP-based clients
//!
//!    When a TCP-based client wishes to establish a connection to an object
//!    that is reachable only via a firewall (such determination is left up
//!    to the implementation), it must open a TCP connection to the
//!    appropriate SOCKS port on the SOCKS server system.  The SOCKS service
//!    is conventionally located on TCP port 1080.  If the connection
//!    request succeeds, the client enters a negotiation for the
//!    authentication method to be used, authenticates with the chosen
//!    method, then sends a relay request.  The SOCKS server evaluates the
//!    request, and either establishes the appropriate connection or denies
//!    it.

use inttype_enum::IntRange;
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
pub struct MethodSelectionRequest {
    pub ver: u8, // 0x05
    nmethods: u8,
    methods: [u8; u8::MAX as usize],
}

use std::fmt::Debug;

impl Debug for MethodSelectionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodSelectionRequest")
            .field("ver", &self.ver)
            .field("nmethods", &self.nmethods)
            .field("methods", &self.methods())
            .finish()
    }
}

impl MethodSelectionRequest {
    #[inline]
    pub fn methods(&self) -> &[u8] {
        &self.methods[..self.nmethods as usize]
    }
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let nmethods = s.read_u8().await?;
        let mut methods = [0xffu8; u8::MAX as usize];

        let n = nmethods as usize;
        let buf = &mut methods[..n];
        s.read_exact(buf).await?;

        Ok(Self {
            ver,
            nmethods,
            methods,
        })
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.ver).await?;
        s.write_u8(self.nmethods).await?;
        s.write_all(self.methods()).await?;
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
    pub fn no_auth_method() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::NoAuthenticationRequired,
        }
    }
    pub fn gssapi_method() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::Gssapi,
        }
    }
    pub fn username_password_method() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::UsernamePassword,
        }
    }
    pub fn no_acceptable_method() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            method: Method::NoAcceptable,
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

/// The values currently defined for METHOD are:
///
/// o  X'00' NO AUTHENTICATION REQUIRED
/// o  X'01' GSSAPI
/// o  X'02' USERNAME/PASSWORD
/// o  X'03' to X'7F' IANA ASSIGNED
/// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
/// o  X'FF' NO ACCEPTABLE METHODS
#[derive(IntRange, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Method {
    NoAuthenticationRequired = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02,
    /// X'03' to X'7F' IANA ASSIGNED
    #[range(0x03..=0x7f)]
    Iana(u8),
    /// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    #[range(0x80..=0xfe)]
    ReservedForPrivate(u8),
    NoAcceptable = 0xff,
}

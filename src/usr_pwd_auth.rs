//! https://www.rfc-editor.org/rfc/rfc1929
#![allow(unused)]

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

///    Once the SOCKS V5 server has started, and the client has selected the
///    Username/Password Authentication protocol, the Username/Password
///    subnegotiation begins.  This begins with the client producing a
///    Username/Password request:
///
///            +----+------+----------+------+----------+
///            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
///            +----+------+----------+------+----------+
///            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
///            +----+------+----------+------+----------+
///   The VER field contains the current version of the subnegotiation,
///   which is X'01'. The ULEN field contains the length of the UNAME field
///   that follows. The UNAME field contains the username as known to the
///   source operating system. The PLEN field contains the length of the
///   PASSWD field that follows. The PASSWD field contains the password
///   association with the given UNAME.
#[derive(Debug)]
pub struct UsrPwdAuth {
    #[allow(dead_code)]
    pub ver: u8,
    ulen: u8,
    uname: [u8; u8::MAX as usize],
    plen: u8,
    passwd: [u8; u8::MAX as usize],
}

impl UsrPwdAuth {
    #[inline]
    pub fn uname(&self) -> &[u8] {
        &self.uname[..self.ulen as usize]
    }
    #[inline]
    pub fn passwd(&self) -> &[u8] {
        &self.passwd[..self.plen as usize]
    }
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let ulen = s.read_u8().await?;

        let mut uname = [0u8; u8::MAX as usize];
        let n = ulen as usize;
        let buf = &mut uname[..n];
        s.read_exact(buf).await?;

        let plen = s.read_u8().await?;
        let mut passwd = [0u8; u8::MAX as usize];
        let buf = &mut passwd[..plen as usize];
        s.read_exact(buf).await?;

        Ok(Self {
            ver,
            ulen,
            uname,
            plen,
            passwd,
        })
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.ver).await?;
        s.write_u8(self.ulen).await?;
        s.write_all(self.uname()).await?;
        s.write_u8(self.plen).await?;
        s.write_all(self.passwd()).await?;
        Ok(())
    }
}

///    The server verifies the supplied UNAME and PASSWD, and sends the
///    following response:
///
///                         +----+--------+
///                         |VER | STATUS |
///                         +----+--------+
///                         | 1  |   1    |
///                         +----+--------+
///
///    A STATUS field of X'00' indicates success. If the server returns a
///    `failure' (STATUS value other than X'00') status, it MUST close the
///    connection.
pub struct AuthResponseStatus {
    pub ver: u8,
    /// 0 means success, other values means failure
    pub status: u8,
}

impl AuthResponseStatus {
    pub fn success() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            status: 0,
        }
    }
    pub fn failure() -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            status: 1,
        }
    }
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let status = s.read_u8().await?;

        Ok(Self { ver, status })
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.ver).await?;
        s.write_u8(self.status).await?;
        Ok(())
    }
}

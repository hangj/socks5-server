#![allow(dead_code)]

//! https://www.rfc-editor.org/rfc/rfc1928.html

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use inttype_enum::IntType;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Once the method-dependent subnegotiation has completed, the client
///    sends the request details.  If the negotiated method includes
///    encapsulation for purposes of integrity checking and/or
///    confidentiality, these requests MUST be encapsulated in the method-
///    dependent encapsulation.
///
///    The SOCKS request is formed as follows:
///
///         +----+-----+-------+------+----------+----------+
///         |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
///         +----+-----+-------+------+----------+----------+
///         | 1  |  1  | X'00' |  1   | Variable |    2     |
///         +----+-----+-------+------+----------+----------+
///
///      Where:
///
///           o  VER    protocol version: X'05'
///           o  CMD
///              o  CONNECT X'01'
///              o  BIND X'02'
///              o  UDP ASSOCIATE X'03'
///           o  RSV    RESERVED
///           o  ATYP   address type of following address
///              o  IP V4 address: X'01'
///              o  DOMAINNAME: X'03'
///              o  IP V6 address: X'04'
///           o  DST.ADDR       desired destination address
///           o  DST.PORT desired destination port in network octet
///              order
#[derive(Debug)]
pub struct Request {
    pub ver: u8,
    pub cmd: Cmd,
    pub rsv: u8, // reserved 0x00
    pub address: Address,
}

impl Request {
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let ver = s.read_u8().await?;
        let cmd =
            s.read_u8().await?.try_into().map_err(|x: u8| {
                io::Error::new(io::ErrorKind::Unsupported, x.to_string())
            })?;
        let rsv = s.read_u8().await?;
        let address = Address::from_stream(s).await?;

        if ver != crate::SOCKS_VERSION_5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS version {ver}"),
            ));
        }

        Ok(Self {
            ver,
            cmd,
            rsv,
            address,
        })
    }
}

#[derive(Debug, IntType)]
#[repr(u8)]
pub enum Cmd {
    /// CONNECT
    ///
    /// In the reply to a CONNECT, BND.PORT contains the port number that the
    /// server assigned to connect to the target host, while BND.ADDR
    /// contains the associated IP address.  The supplied BND.ADDR is often
    /// different from the IP address that the client uses to reach the SOCKS
    /// server, since such servers are often multi-homed.  It is expected
    /// that the SOCKS server will use DST.ADDR and DST.PORT, and the
    /// client-side source address and port in evaluating the CONNECT
    /// request.
    Connect = 0x01,
    ///BIND
    ///
    /// The BIND request is used in protocols which require the client to
    /// accept connections from the server.  FTP is a well-known example,
    /// which uses the primary client-to-server connection for commands and
    /// status reports, but may use a server-to-client connection for
    /// transferring data on demand (e.g. LS, GET, PUT).
    ///
    /// It is expected that the client side of an application protocol will
    /// use the BIND request only to establish secondary connections after a
    /// primary connection is established using CONNECT.  In is expected that
    /// a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
    /// request.
    ///
    /// Two replies are sent from the SOCKS server to the client during a
    /// BIND operation.  The first is sent after the server creates and binds
    /// a new socket.  The BND.PORT field contains the port number that the
    /// SOCKS server assigned to listen for an incoming connection.  The
    /// BND.ADDR field contains the associated IP address.  The client will
    /// typically use these pieces of information to notify (via the primary
    /// or control connection) the application server of the rendezvous
    /// address.  The second reply occurs only after the anticipated incoming
    /// connection succeeds or fails.
    /// In the second reply, the BND.PORT and BND.ADDR fields contain the
    /// address and port number of the connecting host.
    Bind = 0x02,
    /// UDP ASSOCIATE
    ///
    /// The UDP ASSOCIATE request is used to establish an association within
    /// the UDP relay process to handle UDP datagrams.  The DST.ADDR and
    /// DST.PORT fields contain the address and port that the client expects
    /// to use to send UDP datagrams on for the association.  The server MAY
    /// use this information to limit access to the association.  If the
    /// client is not in possesion of the information at the time of the UDP
    /// ASSOCIATE, the client MUST use a port number and address of all
    /// zeros.
    ///
    /// A UDP association terminates when the TCP connection that the UDP
    /// ASSOCIATE request arrived on terminates.
    ///
    /// In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
    /// fields indicate the port number/address where the client MUST send
    /// UDP request messages to be relayed.
    Udp = 0x03,
}

#[derive(Debug, Clone)]
pub struct Address {
    pub atyp: AddressType,
    pub addr: InnerAddress,
}

impl Address {
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let atyp =
            s.read_u8().await?.try_into().map_err(|x: u8| {
                io::Error::new(io::ErrorKind::Unsupported, x.to_string())
            })?;
        let address = match atyp {
            AddressType::Ipv4 => {
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::from(buf);
                let port = s.read_u16().await?;
                InnerAddress::SocketAddr(SocketAddr::from((ip, port)))
            }
            AddressType::Domain => {
                let len = s.read_u8().await?;
                let mut buf = vec![0u8; len as usize];
                s.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid address encoding: {e}"),
                    )
                })?;
                let port = s.read_u16().await?;
                InnerAddress::DomainAddr(domain, port)
            }
            AddressType::Ipv6 => {
                let mut buf = [0u8; 16];
                s.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::from(buf);
                let port = s.read_u16().await?;
                InnerAddress::SocketAddr(SocketAddr::from((ip, port)))
            }
        };

        Ok(Self {
            atyp,
            addr: address,
        })
    }

    async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.atyp.into()).await?;

        match self.addr {
            InnerAddress::SocketAddr(addr) => {
                match addr {
                    SocketAddr::V4(addr) => {
                        s.write_all(&addr.ip().octets()).await?;
                    }
                    SocketAddr::V6(addr) => {
                        s.write_all(&addr.ip().octets()).await?;
                    }
                }
                s.write_u16(addr.port()).await?;
            }
            InnerAddress::DomainAddr(ref domain, port) => {
                s.write_u8(domain.len() as u8).await?;
                s.write_all(domain.as_bytes()).await?;
                s.write_u16(port).await?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum InnerAddress {
    SocketAddr(SocketAddr),
    DomainAddr(String, u16),
}

#[derive(Debug, Clone, Copy, IntType)]
#[repr(u8)]
pub enum AddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

///    The SOCKS request information is sent by the client as soon as it has
///    established a connection to the SOCKS server, and completed the
///    authentication negotiations.  The server evaluates the request, and
///    returns a reply formed as follows:
///
///         +----+-----+-------+------+----------+----------+
///         |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///         +----+-----+-------+------+----------+----------+
///         | 1  |  1  | X'00' |  1   | Variable |    2     |
///         +----+-----+-------+------+----------+----------+
///
///      Where:
///
///           o  VER    protocol version: X'05'
///           o  REP    Reply field:
///              o  X'00' succeeded
///              o  X'01' general SOCKS server failure
///              o  X'02' connection not allowed by ruleset
///              o  X'03' Network unreachable
///              o  X'04' Host unreachable
///              o  X'05' Connection refused
///              o  X'06' TTL expired
///              o  X'07' Command not supported
///              o  X'08' Address type not supported
///              o  X'09' to X'FF' unassigned
///           o  RSV    RESERVED
///           o  ATYP   address type of following address
///              o  IP V4 address: X'01'
///              o  DOMAINNAME: X'03'
///              o  IP V6 address: X'04'
///           o  BND.ADDR       server bound address
///           o  BND.PORT       server bound port in network octet order
pub struct Reply {
    pub ver: u8,
    pub rep: ReplyStatus,
    pub rsv: u8,
    pub address: Address,
}

impl Reply {
    pub fn new(rep: ReplyStatus, address: Address) -> Self {
        Self {
            ver: crate::SOCKS_VERSION_5,
            rep,
            rsv: 0x00,
            address,
        }
    }
    pub async fn writeto_stream<S: AsyncWrite + Unpin>(&self, s: &mut S) -> io::Result<()> {
        s.write_u8(self.ver).await?;
        s.write_u8(self.rep.into()).await?;
        s.write_u8(self.rsv).await?;
        self.address.writeto_stream(s).await?;

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, IntType)]
#[repr(u8)]
pub enum ReplyStatus {
    Succeeded = 0x00,
    GeneralSocksServerFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
    Unassigned = 0xff,
}

impl From<io::ErrorKind> for ReplyStatus {
    fn from(value: io::ErrorKind) -> Self {
        match value {
            io::ErrorKind::NotFound => todo!(),
            io::ErrorKind::PermissionDenied => todo!(),
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::ConnectionReset => todo!(),
            // io::ErrorKind::HostUnreachable => todo!(),
            // io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::ConnectionAborted => todo!(),
            io::ErrorKind::NotConnected => todo!(),
            io::ErrorKind::AddrInUse => todo!(),
            io::ErrorKind::AddrNotAvailable => todo!(),
            // io::ErrorKind::NetworkDown => todo!(),
            io::ErrorKind::BrokenPipe => todo!(),
            io::ErrorKind::AlreadyExists => todo!(),
            io::ErrorKind::WouldBlock => todo!(),
            io::ErrorKind::InvalidInput => todo!(),
            io::ErrorKind::InvalidData => todo!(),
            io::ErrorKind::TimedOut => Self::TtlExpired,
            io::ErrorKind::WriteZero => todo!(),
            io::ErrorKind::Interrupted => todo!(),
            io::ErrorKind::Unsupported => todo!(),
            io::ErrorKind::UnexpectedEof => todo!(),
            io::ErrorKind::OutOfMemory => todo!(),
            io::ErrorKind::Other => todo!(),
            _ => Self::GeneralSocksServerFailure,
        }
    }
}

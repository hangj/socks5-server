/// https://www.rfc-editor.org/rfc/rfc1928.html
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
        let cmd = s.read_u8().await?.try_into()?;
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

#[derive(Debug)]
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
    Connect,
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
    Bind,
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
    Udp,
}

impl Cmd {
    const CONNECT: u8 = 0x01;
    const BIND: u8 = 0x02;
    const UDP: u8 = 0x03;
}

impl TryFrom<u8> for Cmd {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::CONNECT => Ok(Self::Connect),
            Self::BIND => Ok(Self::Bind),
            Self::UDP => Ok(Self::Udp),
            _ => Err(Self::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported command {value}"),
            )),
        }
    }
}

impl Into<u8> for Cmd {
    fn into(self) -> u8 {
        match self {
            Self::Connect => Self::CONNECT,
            Self::Bind => Self::BIND,
            Self::Udp => Self::UDP,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Address {
    pub atyp: AddressType,
    pub addr: InnerAddress,
}

impl Address {
    pub async fn from_stream<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Self> {
        let atyp = s.read_u8().await?.try_into()?;
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

#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    Ipv4,
    Domain,
    Ipv6,
}

impl AddressType {
    const ATYP_IPV4: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x03; // fully-qualified domain name
    const ATYP_IPV6: u8 = 0x04;
}

impl TryFrom<u8> for AddressType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::ATYP_IPV4 => Ok(Self::Ipv4),
            Self::ATYP_DOMAIN => Ok(Self::Domain),
            Self::ATYP_IPV6 => Ok(Self::Ipv6),
            _ => Err(Self::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported atyp: {value}"),
            )),
        }
    }
}

impl Into<u8> for AddressType {
    fn into(self) -> u8 {
        match self {
            AddressType::Ipv4 => Self::ATYP_IPV4,
            AddressType::Domain => Self::ATYP_DOMAIN,
            AddressType::Ipv6 => Self::ATYP_IPV6,
        }
    }
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

#[derive(Debug, Copy, Clone)]
pub enum ReplyStatus {
    Succeeded,
    GeneralSocksServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned,
}

impl ReplyStatus {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_SOCKS_SERVER_FAILURE: u8 = 0x01;
    pub const CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESSTYPE_NOT_SUPPORTED: u8 = 0x08;
    pub const UNASSIGNED: u8 = 0xff;
}

impl From<u8> for ReplyStatus {
    fn from(value: u8) -> Self {
        match value {
            Self::SUCCEEDED => Self::Succeeded,
            Self::GENERAL_SOCKS_SERVER_FAILURE => Self::GeneralSocksServerFailure,
            Self::CONNECTION_NOT_ALLOWED => Self::ConnectionNotAllowed,
            Self::NETWORK_UNREACHABLE => Self::NetworkUnreachable,
            Self::HOST_UNREACHABLE => Self::HostUnreachable,
            Self::CONNECTION_REFUSED => Self::ConnectionRefused,
            Self::TTL_EXPIRED => Self::TtlExpired,
            Self::COMMAND_NOT_SUPPORTED => Self::CommandNotSupported,
            Self::ADDRESSTYPE_NOT_SUPPORTED => Self::AddressTypeNotSupported,
            _ => Self::Unassigned,
        }
    }
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

impl Into<u8> for ReplyStatus {
    fn into(self) -> u8 {
        match self {
            ReplyStatus::Succeeded => Self::SUCCEEDED,
            ReplyStatus::GeneralSocksServerFailure => Self::GENERAL_SOCKS_SERVER_FAILURE,
            ReplyStatus::ConnectionNotAllowed => Self::CONNECTION_NOT_ALLOWED,
            ReplyStatus::NetworkUnreachable => Self::NETWORK_UNREACHABLE,
            ReplyStatus::HostUnreachable => Self::HOST_UNREACHABLE,
            ReplyStatus::ConnectionRefused => Self::CONNECTION_REFUSED,
            ReplyStatus::TtlExpired => Self::TTL_EXPIRED,
            ReplyStatus::CommandNotSupported => Self::COMMAND_NOT_SUPPORTED,
            ReplyStatus::AddressTypeNotSupported => Self::ADDRESSTYPE_NOT_SUPPORTED,
            ReplyStatus::Unassigned => Self::UNASSIGNED,
        }
    }
}

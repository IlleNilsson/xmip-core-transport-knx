#![forbid(unsafe_code)]

//! Streams that arrive over KNX. One group value write is one Stream where
//! it fits an extended frame; a longer Stream travels as a sequence of
//! telegrams to the same group address, flagged first and last, and arrives
//! whole.
//!
//! KNX is the building's own bus — lighting, blinds, heating — and
//! KNXnet/IP tunnelling is how a computer joins it: a UDP connection to an
//! interface on the bus, each cEMI frame sent as a tunnelling request and
//! acknowledged in sequence. What is here is the tunnelling connection —
//! connect, request and acknowledgement, disconnect — and the cEMI `L_Data`
//! frame with an `A_GroupValue_Write`. A Send Location writes to a group
//! address through an interface; a Receive Location is the interface's end
//! of a tunnel, taking what a client writes.
//!
//! The far end is in-process: [`KnxTransport::receive`] serves one tunnel
//! on a UDP socket the way an interface would, and the loopback pair is a
//! client and that server on this machine. The origin URI names the client
//! and the group: `knx://127.0.0.1:49152/1/2/3`.

pub mod cemi;
pub mod settings;
pub mod tunnelling;

use std::net::UdpSocket;
use std::time::Duration;

pub use cemi::{GroupAddress, IndividualAddress, Telegram};
use net::Target;
use transport::bound::{Bound, Reading};
use transport::error::{Result, TransportError, classify, protocol_error};
use transport::kept::Kept;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Directions, Transport};
use tunnelling::Service;

/// The telegram carries the Stream's first bytes.
pub const FIRST: u8 = 0x40;
/// The telegram carries the Stream's last bytes.
pub const LAST: u8 = 0x80;
/// What one telegram carries past its flags byte.
pub const MAX_CHUNK: usize = cemi::MAX_DATA - 1;
/// The most a KNXnet/IP datagram holds: the header, the connection header
/// and an extended cEMI frame.
const MAX_FRAME: usize = 6 + 4 + 9 + 2 + cemi::MAX_DATA;

/// One end of a tunnel: a client of an interface, or the interface's end.
#[derive(Clone)]
pub struct KnxTransport {
    bind: String,
    interface: String,
    source: IndividualAddress,
    group: GroupAddress,
    timeout: Duration,
    /// The interface's socket the first receive binds, and every receive
    /// serves a tunnel on.
    receiving: Kept<UdpSocket>,
}

impl KnxTransport {
    /// Bound at `bind`, tunnelling through the interface at `interface`,
    /// writing group `1/2/3` from individual address `1.1.10`.
    #[must_use]
    pub fn new(bind: impl Into<String>, interface: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            interface: interface.into(),
            source: IndividualAddress::new(1, 1, 10),
            group: GroupAddress::new(1, 2, 3),
            timeout: Duration::from_secs(1),
            receiving: Kept::new(),
        }
    }

    /// Write to `group` unless the target names another.
    #[must_use]
    pub const fn writing_to(mut self, group: GroupAddress) -> Self {
        self.group = group;
        self
    }

    /// Give up on an acknowledgement or a client that does not come within
    /// `timeout` — one second, as the specification's tunnelling timeout is.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Bind and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(UdpSocket, String)> {
        transport::socket::bind_udp(&self.bind, Some(self.timeout))
    }

    fn next(socket: &UdpSocket) -> Result<(Service, String)> {
        let mut buffer = vec![0u8; MAX_FRAME];
        let (read, peer) = socket
            .recv_from(&mut buffer)
            .map_err(|e| classify("waiting for a tunnelling frame", &e))?;
        Ok((Service::decode(&buffer[..read])?, peer.to_string()))
    }

    fn exchange(socket: &UdpSocket, to: &str, service: &Service) -> Result<Service> {
        socket
            .send_to(&service.encode(), to)
            .map_err(|e| classify("sending a tunnelling frame", &e))?;
        Self::next(socket).map(|(answer, _)| answer)
    }

    fn acknowledged(socket: &UdpSocket, to: &str, request: &Service) -> Result<()> {
        let Service::TunnellingRequest {
            channel, sequence, ..
        } = *request
        else {
            return Err(protocol_error("not a tunnelling request"));
        };
        // Repeated once where the acknowledgement does not come, as the
        // specification says; refused where it comes and says no.
        for attempt in 0..2 {
            match Self::exchange(socket, to, request) {
                Ok(Service::TunnellingAck {
                    channel: c,
                    sequence: s,
                    status: tunnelling::OK,
                }) if (c, s) == (channel, sequence) => return Ok(()),
                Ok(Service::TunnellingAck { status, .. }) => {
                    return Err(protocol_error(format!(
                        "the interface refused the telegram with status {status:#04x}"
                    )));
                }
                Ok(_) => return Err(protocol_error("not the acknowledgement that was due")),
                Err(error) if error.retryable && attempt == 0 => {}
                Err(error) => return Err(error),
            }
        }
        Err(TransportError::retryable(
            "no acknowledgement after a repeat",
        ))
    }

    /// Write `bytes` to `group` through the interface, one telegram per
    /// chunk, on one tunnelling connection.
    ///
    /// # Errors
    /// An interface that does not answer, refuses the connection, or does
    /// not acknowledge a telegram after a repeat.
    pub fn write(&self, group: GroupAddress, bytes: &[u8]) -> Result<()> {
        let (socket, _) = self.bind()?;
        let to = &self.interface;
        let channel = match Self::exchange(&socket, to, &Service::ConnectRequest)? {
            Service::ConnectResponse {
                channel,
                status: tunnelling::OK,
                ..
            } => channel,
            Service::ConnectResponse { status, .. } => {
                return Err(protocol_error(format!(
                    "the interface refused the tunnel with status {status:#04x}"
                )));
            }
            _ => return Err(protocol_error("not a connect response")),
        };
        for (sequence, chunk) in chunks(bytes).into_iter().enumerate() {
            let telegram = Telegram::new(self.source, group, &chunk)?;
            let request = Service::TunnellingRequest {
                channel,
                sequence: u8::try_from(sequence % 256).unwrap_or(0),
                cemi: telegram.encode(cemi::L_DATA_REQ),
            };
            Self::acknowledged(&socket, to, &request)?;
        }
        match Self::exchange(&socket, to, &Service::DisconnectRequest { channel })? {
            Service::DisconnectResponse { .. } => Ok(()),
            _ => Err(protocol_error("not a disconnect response")),
        }
    }

    /// Serve one tunnel on `socket` as an interface would: answer the
    /// connect, acknowledge each telegram, and hand over the Stream when the
    /// client disconnects. `None` when no client connected in time.
    ///
    /// # Errors
    /// Where the socket could not be read or the client broke the protocol.
    pub fn serve(&self, socket: &UdpSocket) -> Result<Option<Arrived>> {
        let (first, peer) = match Self::next(socket) {
            Ok(next) => next,
            Err(error) if error.retryable => return Ok(None),
            Err(error) => return Err(error),
        };
        let Service::ConnectRequest = first else {
            return Err(protocol_error("a frame before the connect request"));
        };
        let answer = |service: &Service| {
            socket
                .send_to(&service.encode(), &peer)
                .map(drop)
                .map_err(|e| classify("answering the client", &e))
        };
        let channel = 1;
        answer(&Service::ConnectResponse {
            channel,
            status: tunnelling::OK,
            address: self.source.0,
        })?;
        let mut arriving = Vec::new();
        let mut group = self.group;
        loop {
            let (service, _) = Self::next(socket)?;
            match service {
                Service::TunnellingRequest { sequence, cemi, .. } => {
                    answer(&Service::TunnellingAck {
                        channel,
                        sequence,
                        status: tunnelling::OK,
                    })?;
                    let (_, telegram) = Telegram::decode(&cemi)?;
                    group = telegram.destination;
                    let (flags, chunk) = telegram
                        .data
                        .split_first()
                        .ok_or_else(|| protocol_error("a telegram without its flags"))?;
                    if flags & FIRST != 0 {
                        arriving.clear();
                    }
                    arriving.extend_from_slice(chunk);
                }
                Service::DisconnectRequest { .. } => {
                    answer(&Service::DisconnectResponse {
                        channel,
                        status: tunnelling::OK,
                    })?;
                    return Ok(Some(Arrived::new(
                        format!("knx://{peer}/{group}"),
                        arriving,
                    )));
                }
                _ => return Err(protocol_error("a frame the tunnel was not expecting")),
            }
        }
    }
}

/// `bytes` as the data of the telegrams that carry it: a flags byte then up
/// to [`MAX_CHUNK`] bytes. An empty Stream is one telegram, first and last.
#[must_use]
pub fn chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    let pieces: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(MAX_CHUNK).collect()
    };
    let count = pieces.len();
    pieces
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            let flags =
                if index == 0 { FIRST } else { 0 } | if index + 1 == count { LAST } else { 0 };
            let mut out = Vec::with_capacity(piece.len() + 1);
            out.push(flags);
            out.extend_from_slice(piece);
            out
        })
        .collect()
}

impl Transport for KnxTransport {
    fn name(&self) -> &'static str {
        "knx"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// No client connecting is not an error: an empty vector. Served on the
    /// socket the first receive bound and kept, so a client's connect sent
    /// between two receives waits in its buffer.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let socket = self.receiving.bound(|| self.bind())?;
        Ok(self.serve(socket)?.into_iter().collect())
    }

    /// `target` may name the interface and the group, `knx://host:3671/1/2/3`,
    /// overriding the transport's.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        match Target::under(&["knx"], target).map(|named| (named.authority(), named.path())) {
            Some((interface, group)) if !interface.is_empty() => {
                let group = if group.is_empty() {
                    self.group
                } else {
                    GroupAddress::parse(group)?
                };
                Self::new(self.bind.clone(), interface)
                    .timing_out_after(self.timeout)
                    .write(group, bytes)
            }
            _ => self.write(self.group, bytes),
        }
    }
}

impl KnxTransport {
    /// Both ends on this machine: an ephemeral local port each, the loopback
    /// timeout on the acknowledgements.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", "127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Reading for KnxTransport {
    /// The interface's end of the tunnel, bound and waiting for its one client.
    fn take_one(self, socket: &UdpSocket) -> Result<Arrived> {
        self.serve(socket)?
            .ok_or_else(|| protocol_error("no client connected"))
    }
}

impl Loopback for KnxTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Bound::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0", address)
            .writing_to(self.group)
            .timing_out_after(self.timeout)
            .send("", payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    /// The shapes a protocol breaks on, as the Playground lists them.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        let mut payloads = edge_payloads();
        payloads.extend([(
            "sixty-four kibibytes plus one",
            (0..65_537u32)
                .map(|n| u8::try_from(n * 31 % 256).unwrap_or(0))
                .collect(),
        )]);
        payloads
    }

    #[test]
    fn every_receive_serves_on_the_socket_the_first_bound() {
        let receiver = KnxTransport::loopback();
        receiver.receiving.bound(|| receiver.bind()).expect("bound");
        let address = receiver.receiving.address().expect("address");
        transport::kept::held_across_receives(&receiver, address, 5, |at, payload| {
            KnxTransport::loopback().send_to(at, payload)
        });
    }

    #[test]
    fn a_loopback_round_tunnels_a_stream_to_the_interface() {
        let loopback = KnxTransport::loopback();
        let arrived = loopback.round(b"\x01").expect("round");
        assert_eq!(arrived.bytes, b"\x01");
        assert!(
            arrived.origin_uri.starts_with("knx://127.0.0.1:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.ends_with("/1/2/3"),
            "{}",
            arrived.origin_uri
        );
        let long = vec![7; 1000];
        assert_eq!(loopback.round(&long).expect("four telegrams").bytes, long);
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(b"anything").is_none());
        assert_eq!(loopback.name(), "knx");
        assert!(loopback.directions().receives() && loopback.directions().sends());
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = KnxTransport::loopback();
        for (name, bytes) in payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_target_names_the_interface_and_group_and_a_bad_group_is_refused() {
        let server = KnxTransport::loopback().writing_to(GroupAddress::new(0, 0, 1));
        let (socket, address) = server.bind().expect("binding");
        let client = KnxTransport::loopback();
        let target = format!("knx://{address}/5/6/7");
        let sending = std::thread::spawn(move || client.send(&target, b"on"));
        let arrived = server.serve(&socket).expect("serving").expect("a client");
        sending.join().expect("thread").expect("sending");
        assert_eq!(arrived.bytes, b"on");
        assert!(
            arrived.origin_uri.ends_with("/5/6/7"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            KnxTransport::loopback()
                .send("knx://127.0.0.1:1/9/9/9", b"x")
                .is_err()
        );
        assert!(
            server.receive().expect("nobody").is_empty(),
            "nobody is not an error"
        );
    }

    #[test]
    fn a_stream_is_chunked_with_first_and_last_flags() {
        assert_eq!(chunks(&[]), vec![vec![FIRST | LAST]]);
        let short = chunks(b"ab");
        assert_eq!(short, vec![vec![FIRST | LAST, b'a', b'b']]);
        let long: Vec<u8> = (0..600u32)
            .map(|n| u8::try_from(n % 256).unwrap_or(0))
            .collect();
        let pieces = chunks(&long);
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces[0][0], FIRST);
        assert_eq!(pieces[0].len(), 1 + MAX_CHUNK);
        assert_eq!(pieces[1][0], 0);
        assert_eq!(pieces[2][0], LAST);
        assert_eq!(pieces[2].len(), 1 + 600 - 2 * MAX_CHUNK);
        let joined: Vec<u8> = pieces.iter().flat_map(|p| p[1..].to_vec()).collect();
        assert_eq!(joined, long);
    }
}

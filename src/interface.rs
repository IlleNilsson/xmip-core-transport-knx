//! The interface's end of a KNXnet/IP tunnel, as a Receive Location serves
//! it: the connect answered, each telegram acknowledged in sequence, and
//! the telegram that ends a Stream acknowledged only once its receive cycle
//! has ended. The tunnel stays open between receives, so the client's
//! disconnect, or its next Stream, is taken by the next.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, PoisonError};

use transport::answer::Datagram;
use transport::error::{Result, classify, protocol_error};
use transport::{Acknowledgement, Arrived, Verdict};

use crate::cemi::{GroupAddress, IndividualAddress, Telegram};
use crate::tunnelling::{self, Service};
use crate::{FIRST, KnxTransport, LAST};

/// The status a tunnelling acknowledgement fails a telegram with,
/// `E_DATA_CONNECTION` (KNX Standard 3.8.2, KNXnet/IP Core, the common
/// status codes): an error on the data connection, and the client sends
/// it again.
pub const DATA_CONNECTION_ERROR: u8 = 0x26;

/// The one channel this interface opens.
const CHANNEL: u8 = 1;

/// The tunnel a client holds open: who it is, and the Stream arriving.
struct Tunnel {
    peer: SocketAddr,
    group: GroupAddress,
    arriving: Vec<u8>,
    /// The sequence of the telegram last taken: a repeat of it is the
    /// client's, sent again where its acknowledgement was late.
    last: Option<u8>,
}

/// The tunnel open on a Receive Location's socket, kept between receives.
/// A copy of a transport serves its own, as a kept socket is its own.
#[derive(Default)]
pub struct Interface {
    tunnel: Mutex<Option<Tunnel>>,
}

impl Clone for Interface {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Interface {
    /// Serve the tunnel on `socket` until a Stream has arrived: answer a
    /// connect, acknowledge each telegram but the last, and answer a
    /// disconnect. The last telegram's acknowledgement is the arrival's
    /// verdict: `OK` on accepted and on refused — KNXnet/IP has no status
    /// that refuses a telegram for good, so a refused Stream is taken, not
    /// sent again, and the refusal is Xmip's audit's —
    /// [`DATA_CONNECTION_ERROR`] on failed. `None` when
    /// nothing came in time. `address` is the interface's own; `group` the
    /// one a Stream is said to arrive at before its first telegram names
    /// another.
    ///
    /// # Errors
    /// Where the socket could not be read, or the client broke the
    /// protocol.
    pub fn serve(
        &self,
        socket: &UdpSocket,
        address: IndividualAddress,
        group: GroupAddress,
    ) -> Result<Option<Arrived>> {
        let mut open = self.tunnel.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let (service, peer) = match KnxTransport::next(socket) {
                Ok(next) => next,
                Err(error) if error.retryable => return Ok(None),
                Err(error) => return Err(error),
            };
            let reply = |service: &Service| answer(socket, peer, service);
            match service {
                Service::ConnectRequest => {
                    *open = Some(Tunnel {
                        peer,
                        group,
                        arriving: Vec::new(),
                        last: None,
                    });
                    reply(&Service::ConnectResponse {
                        channel: CHANNEL,
                        status: tunnelling::OK,
                        address: address.0,
                    })?;
                }
                Service::TunnellingRequest { sequence, cemi, .. } => {
                    let tunnel = open
                        .as_mut()
                        .ok_or_else(|| protocol_error("a telegram before the connect request"))?;
                    if tunnel.last == Some(sequence) {
                        continue;
                    }
                    tunnel.last = Some(sequence);
                    let (_, telegram) = Telegram::decode(&cemi)?;
                    tunnel.group = telegram.destination;
                    let (flags, chunk) = telegram
                        .data
                        .split_first()
                        .ok_or_else(|| protocol_error("a telegram without its flags"))?;
                    if flags & FIRST != 0 {
                        tunnel.arriving.clear();
                    }
                    tunnel.arriving.extend_from_slice(chunk);
                    if flags & LAST == 0 {
                        reply(&acknowledgement(sequence, tunnelling::OK))?;
                        continue;
                    }
                    let origin = format!("knx://{}/{}", tunnel.peer, tunnel.group);
                    let bytes = std::mem::take(&mut tunnel.arriving);
                    let answering = Datagram::to(socket, tunnel.peer)?;
                    let verdict = Acknowledgement::deferred(move |verdict| {
                        let status = match verdict {
                            // No status refuses a telegram for good: a
                            // refused Stream is acknowledged, taken.
                            Verdict::Accepted | Verdict::Refused(_) => tunnelling::OK,
                            Verdict::Failed => DATA_CONNECTION_ERROR,
                        };
                        answering.send(&acknowledgement(sequence, status).encode())
                    });
                    let from = tunnel.peer;
                    return Ok(Some(Arrived::whole(origin, bytes, verdict).from_peer(from)));
                }
                Service::DisconnectRequest { .. } => {
                    *open = None;
                    reply(&Service::DisconnectResponse {
                        channel: CHANNEL,
                        status: tunnelling::OK,
                    })?;
                }
                _ => return Err(protocol_error("a frame the tunnel was not expecting")),
            }
        }
    }

    /// Answer the client's disconnect, which follows the Stream it sent:
    /// what a far end does once it has taken its one Stream.
    ///
    /// # Errors
    /// Where the client sent something else, or went away.
    pub fn closed(&self, socket: &UdpSocket) -> Result<()> {
        let (service, peer) = KnxTransport::next(socket)?;
        let Service::DisconnectRequest { .. } = service else {
            return Err(protocol_error("not the disconnect that was due"));
        };
        *self.tunnel.lock().unwrap_or_else(PoisonError::into_inner) = None;
        answer(
            socket,
            peer,
            &Service::DisconnectResponse {
                channel: CHANNEL,
                status: tunnelling::OK,
            },
        )
    }
}

const fn acknowledgement(sequence: u8, status: u8) -> Service {
    Service::TunnellingAck {
        channel: CHANNEL,
        sequence,
        status,
    }
}

fn answer(socket: &UdpSocket, peer: SocketAddr, service: &Service) -> Result<()> {
    socket
        .send_to(&service.encode(), peer)
        .map(drop)
        .map_err(|e| classify("answering the client", &e))
}

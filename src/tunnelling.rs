//! The KNXnet/IP frames of a tunnelling connection: a six-byte header
//! naming the service and the total length, then the service's body — a
//! connect request and response with the channel it opened, a tunnelling
//! request carrying a cEMI frame under a sequence counter and the
//! acknowledgement that answers it, and the disconnect pair. Every host
//! protocol address is the zero one, which asks the other end to answer
//! where the datagram came from.

use transport::error::{Result, protocol_error};

/// KNXnet/IP version 1.0: the header's first two bytes.
const HEADER: [u8; 2] = [0x06, 0x10];

const CONNECT_REQUEST: u16 = 0x0205;
const CONNECT_RESPONSE: u16 = 0x0206;
const DISCONNECT_REQUEST: u16 = 0x0209;
const DISCONNECT_RESPONSE: u16 = 0x020a;
const TUNNELLING_REQUEST: u16 = 0x0420;
const TUNNELLING_ACK: u16 = 0x0421;

/// A host protocol address for UDP over IPv4, all zeros: answer to the
/// sender.
const HPAI: [u8; 8] = [0x08, 0x01, 0, 0, 0, 0, 0, 0];
/// Connection request information: a tunnel connection at the link layer.
const CRI: [u8; 4] = [0x04, 0x04, 0x02, 0x00];

/// No error.
pub const OK: u8 = 0x00;
/// The interface has no channel left.
pub const NO_MORE_CONNECTIONS: u8 = 0x24;

/// One frame of the tunnelling protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Service {
    ConnectRequest,
    /// The channel opened, with `status` [`OK`]; `address` is the interface's
    /// individual address, which the client sends from.
    ConnectResponse {
        channel: u8,
        status: u8,
        address: u16,
    },
    TunnellingRequest {
        channel: u8,
        sequence: u8,
        cemi: Vec<u8>,
    },
    TunnellingAck {
        channel: u8,
        sequence: u8,
        status: u8,
    },
    DisconnectRequest {
        channel: u8,
    },
    DisconnectResponse {
        channel: u8,
        status: u8,
    },
}

impl Service {
    /// The frame as the datagram carries it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (service, body): (u16, Vec<u8>) = match self {
            Self::ConnectRequest => {
                let mut body = HPAI.to_vec();
                body.extend_from_slice(&HPAI);
                body.extend_from_slice(&CRI);
                (CONNECT_REQUEST, body)
            }
            Self::ConnectResponse {
                channel,
                status,
                address,
            } => {
                let mut body = vec![*channel, *status];
                body.extend_from_slice(&HPAI);
                body.extend_from_slice(&[0x04, 0x04]);
                body.extend_from_slice(&address.to_be_bytes());
                (CONNECT_RESPONSE, body)
            }
            Self::TunnellingRequest {
                channel,
                sequence,
                cemi,
            } => {
                let mut body = vec![0x04, *channel, *sequence, 0x00];
                body.extend_from_slice(cemi);
                (TUNNELLING_REQUEST, body)
            }
            Self::TunnellingAck {
                channel,
                sequence,
                status,
            } => (TUNNELLING_ACK, vec![0x04, *channel, *sequence, *status]),
            Self::DisconnectRequest { channel } => {
                let mut body = vec![*channel, 0x00];
                body.extend_from_slice(&HPAI);
                (DISCONNECT_REQUEST, body)
            }
            Self::DisconnectResponse { channel, status } => {
                (DISCONNECT_RESPONSE, vec![*channel, *status])
            }
        };
        let total = u16::try_from(6 + body.len()).unwrap_or(u16::MAX);
        let mut out = HEADER.to_vec();
        out.extend_from_slice(&service.to_be_bytes());
        out.extend_from_slice(&total.to_be_bytes());
        out.extend(body);
        out
    }

    /// The frame `bytes` carry.
    ///
    /// # Errors
    /// Not a KNXnet/IP 1.0 header, a total length the bytes do not match, a
    /// service this crate does not carry, or a body cut off.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (head, body) = bytes
            .split_at_checked(6)
            .ok_or_else(|| protocol_error("a frame cut off inside its header"))?;
        if head[..2] != HEADER {
            return Err(protocol_error("not a KNXnet/IP 1.0 header"));
        }
        if usize::from(u16::from_be_bytes([head[4], head[5]])) != bytes.len() {
            return Err(protocol_error("a total length the frame does not match"));
        }
        let cut = || protocol_error("a body cut off");
        let at = |index: usize| body.get(index).copied().ok_or_else(cut);
        match u16::from_be_bytes([head[2], head[3]]) {
            CONNECT_REQUEST => Ok(Self::ConnectRequest),
            CONNECT_RESPONSE => Ok(Self::ConnectResponse {
                channel: at(0)?,
                status: at(1)?,
                address: u16::from_be_bytes([at(12).unwrap_or(0), at(13).unwrap_or(0)]),
            }),
            TUNNELLING_REQUEST => {
                if at(0)? != 0x04 {
                    return Err(protocol_error("a connection header of another length"));
                }
                Ok(Self::TunnellingRequest {
                    channel: at(1)?,
                    sequence: at(2)?,
                    cemi: body.get(4..).ok_or_else(cut)?.to_vec(),
                })
            }
            TUNNELLING_ACK => Ok(Self::TunnellingAck {
                channel: at(1)?,
                sequence: at(2)?,
                status: at(3)?,
            }),
            DISCONNECT_REQUEST => Ok(Self::DisconnectRequest { channel: at(0)? }),
            DISCONNECT_RESPONSE => Ok(Self::DisconnectResponse {
                channel: at(0)?,
                status: at(1)?,
            }),
            other => Err(protocol_error(format!(
                "a service this crate does not carry: {other:#06x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_reads_back_as_it_was_written() {
        let services = [
            Service::ConnectRequest,
            Service::ConnectResponse {
                channel: 7,
                status: OK,
                address: 0x110a,
            },
            Service::TunnellingRequest {
                channel: 7,
                sequence: 3,
                cemi: vec![0x11, 0, 0xbc],
            },
            Service::TunnellingAck {
                channel: 7,
                sequence: 3,
                status: OK,
            },
            Service::DisconnectRequest { channel: 7 },
            Service::DisconnectResponse {
                channel: 7,
                status: OK,
            },
        ];
        for service in services {
            let bytes = service.encode();
            assert_eq!(&bytes[..2], &HEADER);
            assert_eq!(usize::from(bytes[5]), bytes.len());
            assert_eq!(Service::decode(&bytes).expect("decode"), service);
        }
        let connect = Service::ConnectRequest.encode();
        assert_eq!(connect.len(), 26, "header, two HPAIs, CRI");
        assert_eq!(&connect[2..4], &[0x02, 0x05]);
    }

    #[test]
    fn what_is_not_a_tunnelling_frame_is_refused() {
        let bytes = Service::TunnellingAck {
            channel: 1,
            sequence: 0,
            status: OK,
        }
        .encode();
        assert!(Service::decode(&bytes[..5]).is_err(), "cut off");
        assert!(Service::decode(&bytes[..9]).is_err(), "total length");
        let mut bad = bytes.clone();
        bad[0] = 0x05;
        assert!(Service::decode(&bad).is_err(), "not the header");
        let mut bad = bytes.clone();
        bad[3] = 0x30;
        assert!(Service::decode(&bad).is_err(), "routing indication");
        let mut bad = bytes;
        bad[6] = 0x05;
        bad[3] = 0x20;
        assert!(Service::decode(&bad).is_err(), "connection header length");
    }
}

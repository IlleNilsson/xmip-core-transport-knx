//! The cEMI `L_Data` frame KNXnet/IP tunnels: a message code, the two control
//! fields, an individual source address, a group destination address, the
//! length, and the TPCI/APCI bytes of an `A_GroupValue_Write` with its data.
//! A standard frame carries fourteen bytes of data; an extended frame,
//! which this crate sends, carries two hundred and fifty-four.

use std::fmt;

use transport::error::{Result, protocol_error};

/// A data request from the client to the bus.
pub const L_DATA_REQ: u8 = 0x11;
/// A data indication from the bus to the client.
pub const L_DATA_IND: u8 = 0x29;
/// The bus's confirmation of a request.
pub const L_DATA_CON: u8 = 0x2e;

/// The most data an extended frame's length byte can say, less the APCI
/// byte it also counts.
pub const MAX_DATA: usize = 254;
/// The most data a standard frame carries.
pub const MAX_STANDARD_DATA: usize = 14;

/// Control field 1 of an extended frame: not repeated, system broadcast,
/// low priority.
const CONTROL_EXTENDED: u8 = 0x3c;
/// Control field 1 of a standard frame: the same with the frame-type bit.
const CONTROL_STANDARD: u8 = 0xbc;
/// Control field 2: a group address, hop count six.
const CONTROL_GROUP: u8 = 0xe0;
/// TPCI unnumbered data, APCI `A_GroupValue_Write`.
const GROUP_VALUE_WRITE: [u8; 2] = [0x00, 0x80];

/// An individual address, `area.line.device`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndividualAddress(pub u16);

impl IndividualAddress {
    #[must_use]
    pub const fn new(area: u8, line: u8, device: u8) -> Self {
        Self((area as u16 & 0x0f) << 12 | (line as u16 & 0x0f) << 8 | device as u16)
    }
}

impl fmt::Display for IndividualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            self.0 >> 12,
            (self.0 >> 8) & 0x0f,
            self.0 & 0xff
        )
    }
}

/// A group address, `main/middle/sub`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupAddress(pub u16);

impl GroupAddress {
    #[must_use]
    pub const fn new(main: u8, middle: u8, sub: u8) -> Self {
        Self((main as u16 & 0x1f) << 11 | (middle as u16 & 0x07) << 8 | sub as u16)
    }

    /// `1/2/3` as a group address.
    ///
    /// # Errors
    /// Not three numbers within five, three and eight bits.
    pub fn parse(text: &str) -> Result<Self> {
        let refused = || protocol_error(format!("{text:?} is not a group address"));
        let mut parts = text.split('/').map(|part| part.parse::<u8>().ok());
        let (Some(Some(main)), Some(Some(middle)), Some(Some(sub)), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(refused());
        };
        if main > 31 || middle > 7 {
            return Err(refused());
        }
        Ok(Self::new(main, middle, sub))
    }
}

impl fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.0 >> 11,
            (self.0 >> 8) & 0x07,
            self.0 & 0xff
        )
    }
}

/// One group value written to the bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Telegram {
    pub source: IndividualAddress,
    pub destination: GroupAddress,
    pub data: Vec<u8>,
}

impl Telegram {
    /// A telegram, refusing more data than an extended frame says.
    ///
    /// # Errors
    /// Data over [`MAX_DATA`].
    pub fn new(source: IndividualAddress, destination: GroupAddress, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_DATA {
            return Err(protocol_error("more data than one extended frame carries"));
        }
        Ok(Self {
            source,
            destination,
            data: data.to_vec(),
        })
    }

    /// The frame under `message_code`, standard where the data fits.
    #[must_use]
    pub fn encode(&self, message_code: u8) -> Vec<u8> {
        let control = if self.data.len() <= MAX_STANDARD_DATA {
            CONTROL_STANDARD
        } else {
            CONTROL_EXTENDED
        };
        let mut out = vec![message_code, 0, control, CONTROL_GROUP];
        out.extend_from_slice(&self.source.0.to_be_bytes());
        out.extend_from_slice(&self.destination.0.to_be_bytes());
        out.push(u8::try_from(1 + self.data.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&GROUP_VALUE_WRITE);
        out.extend_from_slice(&self.data);
        out
    }

    /// The message code and telegram `bytes` carry.
    ///
    /// # Errors
    /// A frame cut off, additional information (which this crate does not
    /// carry), a destination that is not a group, a length the bytes do not
    /// match, or an APCI that is not a group value write.
    pub fn decode(bytes: &[u8]) -> Result<(u8, Self)> {
        let cut = || protocol_error("a cEMI frame cut off inside its header");
        let (head, apdu) = bytes.split_at_checked(9).ok_or_else(cut)?;
        if head[1] != 0 {
            return Err(protocol_error(
                "additional information this crate does not carry",
            ));
        }
        if head[3] & 0x80 == 0 {
            return Err(protocol_error(
                "an individual destination where a group was due",
            ));
        }
        if apdu.len() != usize::from(head[8]) + 1 {
            return Err(protocol_error("a length the frame does not match"));
        }
        let (apci, data) = apdu.split_at_checked(2).ok_or_else(cut)?;
        if apci[0] & 0xfc != 0 || apci[1] & 0xc0 != 0x80 {
            return Err(protocol_error("not a group value write"));
        }
        Ok((
            head[0],
            Self {
                source: IndividualAddress(u16::from_be_bytes([head[4], head[5]])),
                destination: GroupAddress(u16::from_be_bytes([head[6], head[7]])),
                data: data.to_vec(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_write_is_a_standard_frame_and_a_long_one_extended() {
        let telegram = Telegram::new(
            IndividualAddress::new(1, 1, 10),
            GroupAddress::new(1, 2, 3),
            &[0x01],
        )
        .expect("telegram");
        let bytes = telegram.encode(L_DATA_REQ);
        assert_eq!(
            bytes,
            [
                0x11, 0x00, 0xbc, 0xe0, 0x11, 0x0a, 0x0a, 0x03, 0x02, 0x00, 0x80, 0x01
            ]
        );
        assert_eq!(
            Telegram::decode(&bytes).expect("decode"),
            (L_DATA_REQ, telegram)
        );
        let long = Telegram::new(
            IndividualAddress::new(1, 1, 10),
            GroupAddress::new(1, 2, 3),
            &[7; MAX_DATA],
        )
        .expect("telegram");
        let bytes = long.encode(L_DATA_IND);
        assert_eq!(bytes[2], 0x3c, "extended");
        assert_eq!(bytes[8], 255);
        assert_eq!(
            Telegram::decode(&bytes).expect("decode"),
            (L_DATA_IND, long)
        );
        assert!(Telegram::new(IndividualAddress(0), GroupAddress(0), &[0; MAX_DATA + 1]).is_err());
    }

    #[test]
    fn what_is_not_a_group_value_write_is_refused() {
        let bytes = Telegram::new(IndividualAddress(0x110a), GroupAddress(0x0a03), b"x")
            .expect("telegram")
            .encode(L_DATA_REQ);
        assert!(Telegram::decode(&bytes[..8]).is_err(), "cut off");
        assert!(Telegram::decode(&bytes[..11]).is_err(), "length");
        let mut bad = bytes.clone();
        bad[1] = 2;
        assert!(Telegram::decode(&bad).is_err(), "additional info");
        let mut bad = bytes.clone();
        bad[3] = 0x60;
        assert!(Telegram::decode(&bad).is_err(), "individual destination");
        let mut bad = bytes;
        bad[10] = 0x00;
        assert!(Telegram::decode(&bad).is_err(), "a group value read");
    }

    #[test]
    fn addresses_read_from_text_and_write_back_to_it() {
        assert_eq!(
            GroupAddress::parse("1/2/3").expect("group"),
            GroupAddress(0x0a03)
        );
        assert_eq!(GroupAddress(0x0a03).to_string(), "1/2/3");
        assert_eq!(
            GroupAddress::parse("31/7/255").expect("group").to_string(),
            "31/7/255"
        );
        assert!(GroupAddress::parse("32/0/0").is_err());
        assert!(GroupAddress::parse("1/8/0").is_err());
        assert!(GroupAddress::parse("1/2").is_err());
        assert!(GroupAddress::parse("1/2/3/4").is_err());
        assert!(GroupAddress::parse("a/b/c").is_err());
        assert_eq!(IndividualAddress::new(15, 15, 255).to_string(), "15.15.255");
        assert_eq!(IndividualAddress::new(1, 1, 10).0, 0x110a);
    }
}

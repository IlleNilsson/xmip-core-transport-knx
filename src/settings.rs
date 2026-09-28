//! What a KNX Location says beyond its address, declared once and read
//! through (ADR-0064, amendment 2026-09-26).

use transport::Configured;
use transport::error::Result;
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::{GroupAddress, KnxTransport};

/// Any local address, a port the operating system chooses: where a client
/// binds unless told otherwise.
const ANY_LOCAL: &str = "0.0.0.0:0";

impl Configured for KnxTransport {
    /// The address is the interface: where a Receive Location serves the
    /// tunnel as one, and the one a Send Location tunnels through.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "local",
                kind: Kind::Address,
                presence: Presence::Default(Fixed::Text(ANY_LOCAL)),
                meaning: "The local address a Send Location binds to reach the interface.",
                applies: Applies::Send,
            },
            Setting {
                name: "group",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The group address, main/middle/sub, written when the target names none.",
                applies: Applies::Send,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long an acknowledgement or a connecting client is waited for.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let transport = match settings.optional_text("local") {
            // Only a Send Location reads one: it binds there and tunnels to
            // the interface at the address.
            Some(local) => Self::new(local, address),
            // A Receive Location is the interface's end, bound at the address.
            None => Self::new(address, address),
        };
        let transport = match settings.optional_text("group") {
            Some(group) => transport.writing_to(GroupAddress::parse(group)?),
            None => transport,
        };
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xcore::settings::Given;

    #[test]
    fn knx_declares_its_settings_and_reads_through_them() {
        let declared = KnxTransport::SETTINGS;
        assert!(declared.problems().is_empty(), "{:?}", declared.problems());

        let given = [
            ("group".to_string(), Given::Text("1/2/4".to_string())),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let sender = KnxTransport::open("192.168.1.20:3671", Applies::Send, &given).expect("built");
        assert_eq!(sender.bind, ANY_LOCAL);
        assert_eq!(sender.interface, "192.168.1.20:3671");
        assert_eq!(sender.group, GroupAddress::new(1, 2, 4));
        assert_eq!(sender.timeout, Duration::from_secs(2));

        let receiver =
            KnxTransport::open("0.0.0.0:3671", Applies::Receive, &given[1..]).expect("built");
        assert_eq!(receiver.bind, "0.0.0.0:3671");

        let Err(refused) = KnxTransport::open("0.0.0.0:3671", Applies::Receive, &given) else {
            panic!("a Receive Location writes to no group");
        };
        assert!(refused.message.contains("\"group\""), "{refused}");
    }
}

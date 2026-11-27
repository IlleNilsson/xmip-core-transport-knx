//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use std::time::Duration;

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Any local address, a port the operating system chooses: where a client
/// binds unless told otherwise.
pub const ANY_LOCAL: &str = "0.0.0.0:0";

/// How long an acknowledgement or a connecting client is waited for unless
/// a Location says.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Every setting a Location takes beyond its address, the interface: where
/// a Receive Location serves the tunnel as one, and the one a Send Location
/// tunnels through.
pub const SETTINGS: &Settings = &Settings {
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
        transport::configured::timeout(
            Applies::Both,
            Some(DEFAULT_TIMEOUT),
            "How long an acknowledgement or a connecting client is waited for.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["knx"];

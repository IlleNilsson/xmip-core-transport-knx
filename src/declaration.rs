//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

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

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["knx"];

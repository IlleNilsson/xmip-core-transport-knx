//! How a KNX Location is configured: `Configured`, reading what it says
//! beyond its address, which its [`declaration`](crate::declaration)
//! declares once (ADR-0064, amendments 2026-09-26 and 2026-11-26).

use transport::Configured;
use transport::error::Result;
use xcore::settings::{Read, Settings};

use crate::{GroupAddress, KnxTransport, declaration};

impl Configured for KnxTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let transport = match settings.optional_text("local") {
            // Only a Send Location reads one: it binds there and tunnels to
            // the interface at the address.
            Some(local) => Self::new(local, address),
            // A Receive Location is the interface's end, bound at the address.
            None => Self::new(address, address),
        };
        Ok(match settings.optional_text("group") {
            Some(group) => transport.writing_to(GroupAddress::parse(group)?),
            None => transport,
        })
    }

    /// The socket every receive takes from, bound where a Receive Location
    /// listens.
    fn listening(&self) -> Result<Option<&str>> {
        self.receiving.listening(|| self.bind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{ANY_LOCAL, DEFAULT_TIMEOUT};
    use std::time::Duration;
    use xcore::settings::{Applies, Given};

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
        // Left out, the Location waits the default it declares.
        let unsaid = declared.read(Applies::Receive, &[]).expect("read");
        let timeout = unsaid.optional_duration(transport::configured::TIMEOUT);
        assert_eq!(timeout, Some(DEFAULT_TIMEOUT));
        let unsaid = KnxTransport::open("0.0.0.0:3671", Applies::Receive, &[]).expect("built");
        assert_eq!(unsaid.timeout, DEFAULT_TIMEOUT);

        let Err(refused) = KnxTransport::open("0.0.0.0:3671", Applies::Receive, &given) else {
            panic!("a Receive Location writes to no group");
        };
        assert!(refused.message.contains("\"group\""), "{refused}");
    }
}

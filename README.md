# xmip-core-transport-knx

KNX transport: KNXnet/IP tunnelling over UDP — a connection, tunnelling requests acknowledged in sequence, cEMI L_Data frames to a group address; a Stream longer than one telegram travels as a sequence of extended frames; an in-process tunnelling server stands in for the interface. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location keeps its socket, bound as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16) (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Acknowledgement

The client is acknowledged after the whole receive cycle. A Receive Location
is the interface's end of the tunnel and keeps it open between receives: the
telegrams of a Stream are acknowledged as they come, but the one that ends
it, flagged last, is acknowledged by the verdict: status `OK` on Accepted,
`E_DATA_CONNECTION` (0x26, KNX Standard 3.8.2, KNXnet/IP Core) on Failed,
which fails the client's write as retryable so it sends the Stream again.
KNXnet/IP has no status that refuses a telegram for good: every error status a
tunnelling acknowledgement carries concerns the connection, and a client
repeats or reconnects on it. So on Refused the telegram is acknowledged `OK`:
the Stream is taken and not sent again, and the refusal is what the runtime
audited. A client's disconnect is answered by
the receive that follows; a Send Location does not fail a write whose
disconnect goes unanswered, since every telegram was acknowledged. Each Stream
arrives whole. Until 2026-10-02 a Stream arrived at the client's disconnect,
every telegram acknowledged as it came.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `local`, `group` and `timeout`, and `SCHEMES`, `knx`. The address `local` defaults to and the wait `timeout` defaults to, `ANY_LOCAL` and `DEFAULT_TIMEOUT`, are there too, and the code reads them from there, where they were the settings module's and the crate root's until then. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on are behind the default feature. So the library the surfaces load can carry it without the code, for the language server and the desktop to suggest and check a KNX Location's settings though no node in their process loaded the technology, once the gathering crate of open problem 48 links it. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

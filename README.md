# xmip-core-transport-knx

KNX transport: KNXnet/IP tunnelling over UDP — a connection, tunnelling requests acknowledged in sequence, cEMI L_Data frames to a group address; a Stream longer than one telegram travels as a sequence of extended frames; an in-process tunnelling server stands in for the interface. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

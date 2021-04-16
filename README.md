# Highly Dependable Location Tracker

## Requirements
[Rust 1.51](https://www.rust-lang.org/learn/get-started)
*(only tested Linux)*

## Directory/Crate overview
`client/` the logic of the 3 clients, *correct*, *malicious* and *HA*

`driver/` a background process that updates the clients' state

`keygen/` a helper binary to generate Keys and Keystores

`lib/model` library with the domain types, used by the binaries

`lib/protos` gRPC library defining the services

`lib/tracing-utils` common tracing utilities (setup, trace context propagation through tonic)

`lib/tracing-utils/tracing-utils-macros/` *same as above*

## Compiling

`cargo build`

## Running tests

`cargo test`

## Running

All binaries will be in `./target/debug/`

`keygen -h <ha-client-ids> -s <server_id> -u <users_ids>`
`-s` can be ommited, `0`

Running each binary with `--help` explains the required arguments, `secrets` and `entities`
are the files created by `keygen`.

Start with `server`, followed by the `client`s and then the `driver`.

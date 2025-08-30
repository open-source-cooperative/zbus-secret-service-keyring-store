# dbus Secret Service keyring store

[![build](https://github.com/open-source-cooperative/dbus-secret-service-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/dbus-secret-service-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/dbus-secret-service-keyring-store.svg?style=flat-square)](https://crates.io/crates/dbus-secret-service-keyring-store) [![docs.rs](https://docs.rs/dbus-secret-service-keyring-store/badge.svg)](https://docs.rs/dbus-secret-service-keyring-store)

This is a [keyring credential store provider](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring) that stores credentials in Secret Service. It’s compatible with [keyring-core](https://crates.io/crates/keyring-core) v0.5 and later.

## Usage

To use this credential store provider, you must take a dependency on the [keyring-core crate](https://crates.io/crates/keyring-core) and on [this crate](https://crates.io/crates/dbus-secret-service-keyring-store). Then you instantiate and use a credential store as shown in the [example program](https://github.com/open-source-cooperative/dbus-secret-service-keyring-store/blob/main/examples/example.rs) in this crate. See the [docs for this crate](https://docs.rs/docs/dbus-secret-service-keyring-store) for more detail.

## Features

This crate has no features of its own: all of its features are simply passed on to the [dbus-secret-service crate](https://crates.io/crates/dbus-secret-service) that it uses to communicate with Secret Service. (See the [docs for that crate](https://docs.rs/docs/dbus-secret-service) for details.) You must enable either the `crypto-rust` or the `crypto-openssl` feature because this crate always encrypts communication with the Secret Service; the default specified by this crate is `crypto-rust`.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.

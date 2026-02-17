# zbus Secret Service keyring store

[![build](https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/zbus-secret-service-keyring-store.svg?style=flat-square)](https://crates.io/crates/zbus-secret-service-keyring-store) [![docs.rs](https://docs.rs/zbus-secret-service-keyring-store/badge.svg)](https://docs.rs/zbus-secret-service-keyring-store)

This library provides a credential store for use with the [keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring) that uses the [Secret Service](https://specifications.freedesktop.org/secret-service/latest/description.html) for credential storage.

## Usage

To use this credential store provider, you must take a dependency on the [keyring-core crate](https://crates.io/crates/keyring-core) and on [this crate](https://crates.io/crates/zbus-secret-service-keyring-store). Then you instantiate and use a credential store as shown in the [example program](https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/blob/main/examples/example.rs) in this crate. See the [docs for this crate](https://docs.rs/docs/zbus-secret-service-keyring-store) for more detail.

## Features

This crate has no features of its own: all of its features are simply passed on to the [secret-service crate](https://crates.io/crates/secret-service) that it uses to communicate with Secret Service. (See the [docs for that crate](https://docs.rs/docs/zbus-secret-service) for details.) You must enable exactly one of the four (mutually-exclusive) features in order to declare which async runtime you are using and which cryptography utilities you want to use.

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.

# Experiments with learning rust "features" and TLS

## Run

### Run the server that uses Rust Native-TLS

- run command `cargo run --bin server`

### Run the client that uses Rustls

- run command `cargo run --bin client`

## Root certificates

You need to generate certificates and put to the directory `certs`. There are:

- ca.crt // Root certificates
- server_identity.pfx // Server private and public keys

To generate them you can either use OpenSSL or apps like [xdb](https://hohnstaedt.de/xca/) that helps to generate Root CA / Intermediate CA and the identities.

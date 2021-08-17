FROM ekidd/rust-musl-builder:nightly-2020-08-26 as builder

RUN USER=rust cargo init
#COPY --chown=rust:rust Cargo.toml Cargo.lock ./
#RUN USER=rust cargo build --release

ADD --chown=rust:rust . ./
RUN USER=rust cargo build --release

FROM scratch

COPY --from=builder --chown=0:0 /home/rust/src/target/x86_64-unknown-linux-musl/release/ehealth-apple-wallet /
COPY --from=builder --chown=0:0 /etc/ssl/certs /etc/ssl/certs
COPY --chown=0:0 templates /templates
COPY --chown=0:0 static /static

ENTRYPOINT ["/ehealth-apple-wallet"]

FROM rustlang/rust:nightly AS builder
RUN update-ca-certificates
WORKDIR /usr/src/

RUN USER=rust cargo new ehealth-apple-wallet
WORKDIR /usr/src/ehealth-apple-wallet

ADD --chown=rust:rust . ./
RUN cargo install --path .

FROM debian:buster-slim

RUN apt-get update && apt-get install -y libssl1.1 libpq5 ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

COPY --from=builder --chown=0:0 /usr/local/cargo/bin/ehealth-apple-wallet /
COPY --from=builder --chown=0:0 /etc/ssl/certs /etc/ssl/certs
COPY --chown=0:0 templates /templates
COPY --chown=0:0 static /static

ENTRYPOINT ["/ehealth-apple-wallet"]

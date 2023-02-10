FROM rust:1.67.1 as builder
WORKDIR /usr/src/hcloud-firewall-controller
COPY Cargo.* .
COPY src src
RUN cargo install --locked --path .

FROM debian:11.6-slim
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/hcloud-firewall-controller /usr/local/bin/hcloud-firewall-controller
ENTRYPOINT ["hcloud-firewall-controller"]

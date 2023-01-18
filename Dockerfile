FROM rust:1.66.1 as builder
WORKDIR /usr/src/hcloud-firewall-controller
COPY . .
RUN cargo install --locked --path .

FROM debian:11.6-slim
COPY --from=builder /usr/local/cargo/bin/hcloud-firewall-controller /usr/local/bin/hcloud-firewall-controller
ENTRYPOINT ["hcloud-firewall-controller"]

# syntax=docker/dockerfile:1
#
# hopf endpoint for the quic-interop-runner. Build from the repo root:
#
#   docker build -f test/quic-interop-runner/Dockerfile -t hopf-interop .
#
# Public runner images need linux/amd64; on Apple silicon add --platform linux/amd64.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p quic-interop

FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=build /src/target/release/quic-interop /hopf/quic-interop

ARG INTEROP_DEBUG=
ENV INTEROP_DEBUG=${INTEROP_DEBUG}

WORKDIR /hopf
COPY test/quic-interop-runner/run_endpoint.sh ./
RUN chmod +x run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]

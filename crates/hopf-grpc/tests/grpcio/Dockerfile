# syntax=docker/dockerfile:1
#
# Minimal Python (grpcio) gRPC server and client for hopf-grpc's
# interoperability tests (crates/hopf-grpc/tests/grpcio_interop.rs).
#
# Python's grpcio is a real, independent gRPC/HTTP2/protobuf
# implementation (C-core). The same image holds both roles: server.py
# listens insecure (h2c prior-knowledge cleartext, no TLS) on port 50051
# and implements the Echo service of echo.proto; client.py calls the same
# service on a hopf server.
#
# The tests build and run this themselves with podman or docker; by hand:
#   podman build -t hopf-grpc-grpcio-test crates/hopf-grpc/tests/grpcio
#   podman run -d --name grpc-test -p 15051:50051 hopf-grpc-grpcio-test
#   podman run --rm hopf-grpc-grpcio-test python3 client.py host.containers.internal:15052

FROM python:3.12-slim

RUN pip install --no-cache-dir grpcio==1.66.2 grpcio-tools==1.66.2

WORKDIR /app
COPY echo.proto .
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. echo.proto

COPY server.py client.py ./

EXPOSE 50051

CMD ["python3", "server.py"]

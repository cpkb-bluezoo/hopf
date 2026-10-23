"""gRPC client driver for hopf-grpc's server interoperability tests.

Plain grpcio (Python's C-core gRPC implementation), wholly independent of
hopf's own HTTP/2 and protobuf code. Calls the Echo service of echo.proto
on the hopf server at the address given as the first argument, and prints
"ok <name>" or "FAIL <name>: <reason>" for each scenario. Exits 0 if they
all passed. Further arguments name the scenarios to run (default: all).
"""

import sys

import grpc

import echo_pb2
import echo_pb2_grpc


def metadata_value(metadata, key):
    for k, v in metadata or ():
        if k == key:
            return v
    return None


def unary(stub):
    response = stub.SayEcho(echo_pb2.EchoRequest(message="ab", repeat_count=3))
    assert response.message == "ababab", response.message
    assert response.length == 6, response.length


def unary_empty_messages(stub):
    # An all-default message is a zero-length frame in both directions
    response = stub.SayEcho(echo_pb2.EchoRequest())
    assert response.message == "", response.message
    assert response.length == 0, response.length


def unary_error(stub):
    try:
        stub.AlwaysFail(echo_pb2.FailRequest(reason="because"))
        raise AssertionError("the call did not fail")
    except grpc.RpcError as e:
        assert e.code() == grpc.StatusCode.INVALID_ARGUMENT, e.code()
        assert e.details() == "always fails: because", e.details()


def server_streaming(stub):
    messages = [r.message for r in stub.Watch(echo_pb2.EchoRequest(message="x", repeat_count=3))]
    assert messages == ["x1", "x2", "x3"], messages


def server_streaming_error(stub):
    call = stub.Watch(echo_pb2.EchoRequest(message="fail"))
    messages = []
    try:
        for r in call:
            messages.append(r.message)
        raise AssertionError("the stream ended without an error")
    except grpc.RpcError as e:
        assert e.code() == grpc.StatusCode.NOT_FOUND, e.code()
        assert e.details() == "gone", e.details()
    assert messages == ["first"], messages


def client_streaming(stub):
    requests = (echo_pb2.EchoRequest(message=m) for m in ["a", "b", "c"])
    response = stub.Collect(requests)
    assert response.message == "abc", response.message


def client_streaming_empty(stub):
    response = stub.Collect(iter(()))
    assert response.message == "", response.message


def bidirectional(stub):
    requests = (echo_pb2.EchoRequest(message=m) for m in ["a", "b", "c"])
    messages = [r.message for r in stub.Chat(requests)]
    assert messages == ["re a", "re b", "re c"], messages


def bidirectional_empty_messages(stub):
    requests = (echo_pb2.EchoRequest() for _ in range(3))
    messages = [r.message for r in stub.Chat(requests)]
    assert messages == ["re "] * 3, messages


def metadata(stub):
    call = stub.Metadata.with_call(
        echo_pb2.EchoRequest(message="m"),
        metadata=(("x-test", "hello"), ("x-test-bin", b"\x00\x01\x02\xff")),
    )
    response, rpc = call
    assert response.message == "hello", response.message
    initial = rpc.initial_metadata()
    assert metadata_value(initial, "x-echo") == "hello", initial
    assert metadata_value(initial, "x-echo-bin") == b"\x00\x01\x02\xff", initial
    assert metadata_value(rpc.trailing_metadata(), "x-trailer") == "done", rpc.trailing_metadata()


def deadline(stub):
    try:
        stub.Slow(echo_pb2.EchoRequest(message="s"), timeout=0.5)
        raise AssertionError("the call was not cut short")
    except grpc.RpcError as e:
        assert e.code() == grpc.StatusCode.DEADLINE_EXCEEDED, e.code()


def deadline_propagated(stub):
    # grpc-timeout reaches the server as the time left to the call, which
    # the C-core rounds up when it encodes it
    response = stub.Deadline(echo_pb2.EchoRequest(), timeout=20)
    assert 10000 < response.length <= 21000, response.length
    response = stub.Deadline(echo_pb2.EchoRequest())
    assert response.length == -1, response.length


def cancellation(stub):
    call = stub.Slow.future(echo_pb2.EchoRequest(message="s"))
    call.cancel()
    assert call.cancelled()


def compressed_request(stub, algorithm):
    text = "a" * 3000
    response = stub.SayEcho(echo_pb2.EchoRequest(message=text), compression=algorithm)
    assert response.message == text, len(response.message)


def gzip_request(stub):
    compressed_request(stub, grpc.Compression.Gzip)


def deflate_request(stub):
    compressed_request(stub, grpc.Compression.Deflate)


def compressed_response(stub):
    # Whether and how the server compresses it is up to the server; the
    # channel accepts every algorithm, so it may use any it offers
    response = stub.Compressed(echo_pb2.EchoRequest(repeat_count=3000))
    assert response.message == "a" * 3000, len(response.message)
    assert response.length == 3000, response.length


def compressed_request_beyond_the_limit(stub):
    # 5 MB of one letter is a few KB of gzip, which the frame limit lets
    # through, so it is the decompressed size that the server must refuse
    try:
        stub.SayEcho(echo_pb2.EchoRequest(message="a" * 5000000), compression=grpc.Compression.Gzip)
        raise AssertionError("the message was accepted")
    except grpc.RpcError as e:
        assert e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED, e.code()


SCENARIOS = [
    ("unary", unary),
    ("unary-empty-messages", unary_empty_messages),
    ("unary-error", unary_error),
    ("server-streaming", server_streaming),
    ("server-streaming-error", server_streaming_error),
    ("client-streaming", client_streaming),
    ("client-streaming-empty", client_streaming_empty),
    ("bidirectional", bidirectional),
    ("bidirectional-empty-messages", bidirectional_empty_messages),
    ("metadata", metadata),
    ("deadline", deadline),
    ("deadline-propagated", deadline_propagated),
    ("cancellation", cancellation),
    ("gzip-request", gzip_request),
    ("deflate-request", deflate_request),
    ("compressed-response", compressed_response),
    ("compressed-request-beyond-the-limit", compressed_request_beyond_the_limit),
]


def main():
    target = sys.argv[1]
    wanted = sys.argv[2:]
    known = [name for name, _ in SCENARIOS]
    unknown = [name for name in wanted if name not in known]
    if unknown:
        print("FAIL unknown scenario: %s" % ", ".join(unknown), flush=True)
        sys.exit(2)
    failed = 0
    with grpc.insecure_channel(target) as channel:
        stub = echo_pb2_grpc.EchoStub(channel)
        for name, scenario in SCENARIOS:
            if wanted and name not in wanted:
                continue
            try:
                scenario(stub)
                print("ok " + name, flush=True)
            except Exception as e:  # reported, not raised, so every scenario runs
                failed += 1
                print("FAIL %s: %r" % (name, e), flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

# hopf-redis benchmarks

```text
cargo bench -p hopf-redis --bench client                  # everything
cargo bench -p hopf-redis --bench client -- cluster       # scenarios whose name contains "cluster"
cargo bench -p hopf-redis --bench client -- --scale 0.1   # a tenth of the operations
```

The harness has no dependency beyond the workspace's. It prints a Markdown
table, one row per scenario, every figure per operation (one command and its
reply):

- **ops/s** is wall-clock throughput.
- **allocs/op** and **bytes/op** are counted by a global allocator in the
  benchmark process.
- **cpu us/op** is the process's user plus system time, from `getrusage`.

The server is a minimal RESP server in a child process (the benchmark binary run
again with `--serve`), so allocations and CPU time are the client's alone. It
answers any key on any node, so a cluster scenario never sees a redirection, and
a TLS scenario uses a self-signed certificate. It is not Redis: the numbers say
how much work the client does per command, not how fast a real server answers,
and they are for comparing one build of the client with another on the same
machine, not for comparing machines.

Scenarios:

- Pipelined `GET` and `SET` on one node at depths 1, 16 and 256, and with 64 KiB
  values.
- The same on a three-master cluster, keyed, and keyless (`PUBLISH`).
- A few of them over TLS.
- Parsing a 1 KiB, 64 KiB and 1 MiB bulk reply fed in 512-byte reads and in one.
- Failing 1024, 4096 and 16384 pipelined commands that all time out against a
  server that has stopped answering.

## Results

Before and after the cluster router stopped scanning the slot table for a
keyless command, kept the master list with the layout, picked a node without
allocating, shared a command's arguments instead of copying them on each
dispatch, encoded a command in one exact-size allocation, and moved a command's
bytes into the outbox instead of copying them. Apple M4, release
build, loopback, one reactor thread; the figures vary a few per cent from run to
run.

| scenario | ops/s | allocs/op | bytes/op | cpu us/op |
|---|---:|---:|---:|---:|
| single get 16B depth 1 | 29449 -> 30502 | 26.0 -> 19.1 | 1203 -> 1093 | 15.69 -> 14.89 |
| single get 16B depth 16 | 260454 -> 285766 | 20.7 -> 14.7 | 847 -> 768 | 2.27 -> 1.97 |
| single get 16B depth 256 | 545460 -> 646313 | 20.0 -> 14.1 | 843 -> 766 | 1.35 -> 1.08 |
| single set 16B depth 16 | 252905 -> 285529 | 22.8 -> 15.7 | 920 -> 839 | 2.29 -> 1.91 |
| single set 64KiB depth 16 | 45292 -> 47594 | 25.1 -> 16.0 | 399580 -> 264412 | 20.04 -> 19.15 |
| single get 64KiB depth 16 | 62506 -> 63855 | 21.6 -> 15.7 | 66401 -> 66325 | 10.18 -> 9.85 |
| cluster get 16B depth 16 | 149946 -> 164143 | 36.7 -> 22.4 | 1449 -> 1153 | 6.52 -> 6.02 |
| cluster publish depth 16 | 11217 -> 166115 | 36.6 -> 18.5 | 1365 -> 996 | 89.05 -> 5.98 |
| cluster get 16B depth 256 | 397844 -> 548435 | 34.3 -> 20.4 | 1423 -> 1154 | 2.51 -> 1.83 |
| cluster publish depth 256 | 12106 -> 663971 | 34.4 -> 16.4 | 1432 -> 972 | 82.55 -> 1.51 |
| cluster set 64KiB depth 16 | 35102 -> 44446 | 42.5 -> 23.1 | 522595 -> 227863 | 28.38 -> 22.48 |
| tls single get 16B depth 16 | 247925 -> 278962 | 21.1 -> 15.1 | 1006 -> 927 | 2.35 -> 2.02 |
| tls single set 64KiB depth 16 | 14936 -> 16299 | 36.5 -> 27.5 | 850882 -> 712844 | 51.55 -> 48.02 |
| tls cluster publish depth 16 | 11159 -> 151361 | 39.3 -> 21.9 | 1574 -> 1218 | 89.51 -> 6.57 |
| parse 1KiB reply, 512B reads | 5340549 -> 5418879 | 2.0 -> 2.0 | 1032 -> 1032 | 0.19 -> 0.18 |
| parse 1KiB reply, one read | 6287809 -> 6008261 | 2.0 -> 2.0 | 1032 -> 1032 | 0.16 -> 0.17 |
| parse 64KiB reply, 512B reads | 307276 -> 310205 | 2.0 -> 2.0 | 65544 -> 65544 | 3.25 -> 3.22 |
| parse 64KiB reply, one read | 753490 -> 774893 | 2.0 -> 2.0 | 65544 -> 65544 | 1.32 -> 1.29 |
| parse 1MiB reply, 512B reads | 11990 -> 13390 | 6.0 -> 6.0 | 2031625 -> 2031625 | 83.35 -> 74.68 |
| parse 1MiB reply, one read | 38677 -> 38718 | 3.0 -> 3.0 | 1114121 -> 1114121 | 25.84 -> 25.83 |
| timeouts 1024 pending | 322740 -> 250357 | 19.7 -> 14.1 | 1300 -> 1248 | 9.29 -> 10.41 |
| timeouts 4096 pending | 245141 -> 273860 | 19.8 -> 14.1 | 1351 -> 1296 | 10.29 -> 8.20 |
| timeouts 16384 pending | 141515 -> 144226 | 19.8 -> 14.2 | 1356 -> 1302 | 11.84 -> 11.05 |

What the figures show:

- **Keyless commands were the outlier.** `PUBLISH` on a cluster walked all 16384
  slots, de-duplicated the masters and built a `Vec` per command: about 85 us of
  CPU, against 6 us for a keyed `GET`. It now costs the same as one.
- **A large value was copied too often.** A 64 KiB `SET` through the cluster
  allocated 523 KB per command and now allocates 228 KB, less than the single
  connection did before. The retry copy of the command, the grow-by-doubling of
  its encoding and the copy into the outbox are gone.
- **Every command saves allocations**: about 6 on one connection, from numbers
  formatted into strings during encoding, and about 14 through the cluster, which
  also cloned a node address several times per route.
- **Per-command timers were not a problem.** The cost of failing a command that
  timed out stays flat from 1024 to 16384 pending (about 10 us each), because
  commands expire in the order they were sent and each is found at the front of
  the queue. A deadline-ordered structure would not pay for itself, so the
  timers are unchanged.
- **The parser used to buffer whole replies, which was a defect.** It collected a
  bulk string's payload until it was complete and only then handed it on, so a
  reply was held in full: up to 512 MiB for one string, with the buffer growing
  by doubling on the way. It is now event-driven (see below).

## The streaming core

The parser tells a sink what it reads, with a string's payload as chunks that
borrow from the connection's ring, and holds none of it
([#541](https://github.com/cpkb-bluezoo/hopf/issues/541)). The `stream` rows
feed a reply of the given size, in 512-byte reads, to a sink that keeps nothing:

| scenario | ops/s | allocs/op | bytes/op | cpu us/op |
|---|---:|---:|---:|---:|
| stream 64KiB reply, 512B reads | 963755 | 0.0 | 0 | 1.04 |
| stream 1MiB reply, 512B reads | 63248 | 0.0 | 0 | 15.81 |
| stream 64MiB reply, 512B reads | 993 | 0.0 | 0 | 1007.09 |

Bytes per operation is flat at zero from 64 KiB to 64 MiB, where the `parse` rows
above, which assemble a `Value` for a callback, allocate the size of the reply.
The small-reply rows are unchanged within noise from the table above, and each
allocates about one fewer time, since the buffer a reply is assembled in is now
reused from one reply to the next.

`tests/memory_bound.rs` measures the peak of the live heap rather than the
allocations: a 1 GiB reply fed to the parser in 4 KiB and 64 KiB reads, streamed
or skipped, raises it by 36 bytes; a late 256 MiB reply to a command that had
already timed out raises it by about 2.8 KB, where before it raised it by 256 MiB.

## Streaming replies to a sink

`send_streaming` gives a command a sink of its own, and every command now has a
cell that its queue entry, the reader of its reply and its timer share, so that a
timeout can take the sink out from under a reply that has begun, and a consumer
on another thread can pause, resume or cancel it. That costs the small-reply
path two allocations and some CPU per operation, most visibly at high pipeline
depths, where each reply's few events each take the cell's lock:

| scenario | ops/s | allocs/op | cpu us/op |
|---|---:|---:|---:|
| single get 16B depth 1 | 30201 -> 29845 | 17.1 -> 19.1 | 15.10 -> 15.57 |
| single get 16B depth 16 | 293799 -> 271040 | 13.5 -> 15.5 | 1.97 -> 2.24 |
| single get 16B depth 256 | 703281 -> 596988 | 13.1 -> 15.1 | 1.08 -> 1.35 |
| cluster publish depth 16 | 164495 -> 159181 | 17.0 -> 18.9 | 6.04 -> 6.23 |
| cluster publish depth 256 | 667095 -> 579374 | 15.3 -> 17.3 | 1.50 -> 1.73 |
| tls single get 16B depth 16 | 275125 -> 256189 | 13.9 -> 15.9 | 2.11 -> 2.35 |

(Before, then after. On macOS `std::sync::Mutex` allocates its pthread mutex on
first use, which is one of the two allocations; on Linux the lock is a futex and
allocates nothing, so the count there is lower.)

`tests/memory_bound.rs` measures what streaming through a real client costs in
memory: a 256 MiB value through `get_stream` to a sink that keeps nothing raises
the peak heap by about 2.9 KB, and the same with the consumer paused in the
middle for half a second raises it by the same. Pausing is by `pause_read`, so the
value waits in the socket and the server's writes are held back by TCP; it relies
on the reactor stopping reading as soon as a handler pauses (a read loop that
carried on until the ring was full used to fail the connection with "inbound
buffer full", under load).

## Streaming arguments out

`Command::arg_stream` pulls an argument from a source a block at a time, and
a command larger than the outbound buffer is written in blocks that wait for the
buffer to drain, where it was written in one go and failed the connection with
"outbound buffer overflow". The write queue this needed changes nothing for the
small commands that are nearly all of them: every row of the table above is the
same within noise, and the 64 KiB `SET` rows are slightly better.

`tests/memory_bound.rs` sends a 256 MiB value out of a client, made by a
generator as it is asked for, and the peak heap rises by about 770 KB (one block
of the source and the outbound buffer), not by the size of the value. A 12 MiB
value in memory, larger than the 4 MiB outbound buffer, is sent where it used to
fail.

## Streaming through a cluster

`RedisCluster::send_streaming` puts a small gate in front of the caller's sink
for each attempt, holding back only the first event of a reply to see if it is
an error to follow. The cluster rows above are unchanged, and a 256 MiB value
streamed through a cluster client to a sink that keeps nothing raises the peak
heap by about 3.6 KB, the same as through one connection.

## Pub/sub and pushes

A subscriber's messages and a command connection's pushes were built whole and
then handed on; they are now events, routed during the parse. A message reaches
the handler as a header (the channel, whole, under `max_field`) and the body in
chunks, and a push reaches the application's sink as the events of a reply, or
is skipped as it arrives if there is none. The single-node and cluster rows above
are unchanged (allocations per operation are identical, row for row), since the
extra routing arms are not on the path of an ordinary reply.

`tests/memory_bound.rs` sends a 256 MiB message to a subscriber whose handler
keeps nothing: the peak heap rises by about 1 KB, with the handler paused for
half a second in the middle of the message as well as without. A 128 MiB push
to a command connection with no sink, discarded as it arrives, raises it by
about 3 KB, and the reply behind it is the reply. (A discard past `max_skip`,
256 MiB by default, closes the connection, so a push larger than that is not
discarded in this way.)

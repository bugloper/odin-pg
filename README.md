# odin-pg

A production-grade PostgreSQL client driver written in pure [Odin](https://odin-lang.org) —
a native implementation of the PostgreSQL wire protocol (v3.0) with **no dependency on libpq**.

## Features

- **Pure Odin protocol implementation** over `core:net` sockets — no C required for the core driver
- **SCRAM-SHA-256** authentication (RFC 7677, verified against the RFC test vectors), with md5 and cleartext fallbacks
- **Simple + extended query protocol**: parameterized queries are always sent out-of-band (`$1`, `$2`, …) — never string interpolation
- **Prepared statements** with a per-connection LRU cache (transparent for parameterized queries) and **binary wire formats** for well-known types
- **Typed row access**: `pg.get(row, i64, 0)`, `Maybe(T)` for NULLs, `pg.scan(row, &id, &name)`, `pg.scan_struct` with `db:"…"` tags, arrays as nested slices (`[]i64`, `[][]i64`, `[]Maybe(string)`, …), exact `pg.Numeric`, `pg.get_json`
- **Transactions** with isolation options and nested SAVEPOINTs
- **Connection pool**: acquire timeout, max lifetime / idle limits, background health-check reaper, transaction reset on release
- **TLS** via an optional OpenSSL subpackage — importing `odin-pg/openssl` is what links libssl; core binaries carry zero TLS dependency
- **Query cancellation** from another thread (CancelRequest side-channel)
- **COPY** in/out streaming and **LISTEN/NOTIFY**
- **Pipeline mode**: batch many extended-protocol commands into one round trip, with per-command results/errors and protocol-correct abort semantics
- **Unix-domain sockets** (`host=/var/run/postgresql`, libpq-style socket directories) and a real **connect timeout** (dials never hang on black-holed hosts)
- **SQLSTATE-first error model**: `union #shared_nil` errors that compose with `or_return`
- Designed for protocol 3.2 upgradeability (variable-length cancel keys, PG 18+)

## Quick start

```odin
import pg "odin-pg"

main :: proc() {
	conn, err := pg.connect_dsn("postgres://user:pass@localhost:5432/mydb")
	if err != nil { /* handle */ }
	defer pg.conn_close(conn)

	// Parameterized query (extended protocol, cached prepared statement).
	res, qerr := pg.query(conn, "SELECT id, name FROM users WHERE age > $1", 21)
	if qerr != nil { /* handle */ }
	defer pg.result_destroy(&res)

	for row in res.rows {
		id, _   := pg.get(row, i64, 0)
		name, _ := pg.get(row, string, 1) // cloned into context.allocator
		defer delete(name)
	}
}
```

### Transactions

```odin
tx := pg.begin(conn) or_return
defer pg.rollback(&tx) // no-op after commit
pg.exec(&tx, "INSERT INTO t VALUES ($1)", 42) or_return
pg.commit(&tx) or_return
```

### Pool (for servers)

```odin
cfg, _ := pg.parse_dsn(dsn)
pool, _ := pg.pool_create(pg.Pool_Config{conn_config = cfg, max_conns = 16})
defer pg.pool_close(pool)

res, err := pg.pool_query(pool, "SELECT $1::int8", 7) // acquire→query→release
```

### TLS

```odin
import pg_ssl "odin-pg/openssl" // this import links libssl/libcrypto

cfg.tls = pg_ssl.tls_config(.Verify_Full, ca_file = "root.crt")
```

Without that import your binary never links OpenSSL; `sslmode` values in DSNs
(`?sslmode=require`) still parse, and `connect` fails fast with
`.TLS_Not_Available` if TLS is requested with no implementation wired in.

### LISTEN/NOTIFY

```odin
l, _ := pg.listener_create_dsn(dsn)
defer pg.listener_close(l)
pg.listen(l, "jobs")
for {
	n, err := pg.next_notification(l, 30 * time.Second)
	if err == pg.Error(pg.Driver_Error.Read_Timeout) do continue
	if err != nil { pg.listener_reconnect(l); continue }
	// n.channel, n.payload (valid until the next call)
}
```

### COPY

```odin
c, _ := pg.copy_in_begin(conn, "COPY t FROM STDIN")
pg.copy_in_write(&c, data)
tag, err := pg.copy_in_finish(&c)
```

### Pipeline

```odin
p := pg.pipeline_begin(conn) or_return
defer pg.pipeline_close(&p)
pg.pipeline_query(&p, "SELECT $1::int8", 1) or_return
pg.pipeline_query(&p, "SELECT $1::int8", 2) or_return
items := pg.pipeline_sync(&p) or_return // one round trip for the whole batch
defer pg.pipeline_items_destroy(items)
// items[i].result / items[i].err — a failed command errors its own item;
// later items get .Pipeline_Aborted (protocol semantics).
```

## Memory ownership

- Procs that allocate take a trailing `allocator := context.allocator`.
- A `Result` owns all its rows in one arena — one `result_destroy` frees everything; it outlives pool release.
- `pg.get(row, string, i)` **clones**; `pg.row_cell`/`pg.row_text` are the zero-copy borrows.
- A `^Server_Error` from a live connection borrows that connection's arena and is valid **until the next command**; from a failed `connect` it is caller-owned (`server_error_destroy`).

## Errors

```odin
if code, ok := pg.sqlstate(err); ok { /* server error with SQLSTATE */ }
if pg.is_unique_violation(err) { /* 23505 */ }
```

`pg.Error` distinguishes `Driver_Error` (client-side), `^Server_Error` (parsed
ErrorResponse), `net.Network_Error`, and `mem.Allocator_Error`.

## Testing

```sh
odin test .                                     # unit tests, no network
docker compose -f tests/docker-compose.yml up -d --wait
PG_TEST_DSN="postgres://odin:odin_pg_test@localhost:5435/odin_pg_test" \
PG_TEST_DSN_MD5="postgres://odin:odin_pg_test@localhost:5434/odin_pg_test" \
  odin test tests/integration
```

TLS tests live in `tests/integration_tls` (see the header comment there).

## Examples

- `examples/basic` — connect, transactions, typed scanning, arrays, numerics
- `examples/bench` — throughput micro-benchmarks (simple/extended/pipelined/pooled)
- `examples/web` — a JSON todo API on [laytan/odin-http](https://github.com/laytan/odin-http) backed by a connection pool (clone odin-http into `examples/vendor/` first; see the file header)

## Performance

`examples/bench` measures round-trip-bound throughput. Against a local
Dockerized PostgreSQL 18 (Apple M-series), odin-pg is at parity with libpq
(via the laytan/odin-postgresql bindings) on single queries — both land
around 6k ops/s / ~160 µs/op, within run-to-run noise of each other — while
pipeline mode reaches ~100k ops/s (~10 µs/op) by amortizing round trips
across batches of 50.

Two implementation details matter for the single-query numbers: the message
reader drains the socket into a reusable buffer (one or two `recv` syscalls
per query response instead of two per message), and `Result` arenas reserve
64 KiB instead of the multi-megabyte default (halving per-query mmap cost).

## Status

Core driver (auth, queries, types incl. multi-D arrays/numeric/JSON,
statements, pool, TLS, COPY, LISTEN/NOTIFY, pipeline mode) is implemented and
integration-tested against PostgreSQL 14–18, with fuzz tests over every wire
parser. Unix sockets are POSIX-only (not Windows). Not yet done:
`SCRAM-SHA-256-PLUS` channel binding, SASLprep.

## License

MIT

package pg_integration_tests

import "core:testing"
import "core:time"

import pg "../.."

// No live server needed: 192.0.2.0/24 (RFC 5737 TEST-NET-1) black-holes SYNs
// on most networks, so this proves the dialer thread enforces the timeout.
// Some networks answer with ICMP unreachable instead, so a fast network
// error is also acceptable — what must never happen is blocking for the OS
// default (~75s).
@(test)
test_connect_timeout :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)

	cfg := pg.default_config()
	cfg.host = "192.0.2.1"
	cfg.port = 5432
	cfg.user = "nobody"
	cfg.connect_timeout = 500 * time.Millisecond

	started := time.tick_now()
	conn, err := pg.connect(cfg)
	waited := time.tick_diff(started, time.tick_now())

	testing.expect(t, conn == nil)
	testing.expectf(t, err != nil, "expected dial failure")
	testing.expectf(t, waited < 5 * time.Second, "dial took %v; timeout not enforced", waited)
}

// Gated on PG_TEST_UNIX_DSN, e.g.
//	PG_TEST_UNIX_DSN="postgres://user@/db?host=/var/run/postgresql"
// or the kv form: "host=/tmp user=x dbname=y".
@(test)
test_unix_socket :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_UNIX_DSN")
	if !ok {
		return
	}

	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "unix socket connect failed: %v", err)
	if err != nil {
		return
	}
	defer pg.conn_close(conn)

	res, q_err := pg.query(conn, "SELECT 1")
	testing.expect_value(t, q_err, nil)
	defer pg.result_destroy(&res)
	one, _ := pg.row_text(res.rows[0], 0)
	testing.expect_value(t, one, "1")
}

// A missing socket file fails fast with a refused-style error.
@(test)
test_unix_socket_missing :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)

	cfg := pg.default_config()
	cfg.host = "/nonexistent_odin_pg_dir"
	cfg.user = "nobody"

	started := time.tick_now()
	conn, err := pg.connect(cfg)
	waited := time.tick_diff(started, time.tick_now())

	testing.expect(t, conn == nil)
	testing.expect(t, err != nil)
	testing.expect(t, waited < time.Second)
}

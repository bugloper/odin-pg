package pg_integration_tests

import "core:testing"

import pg "../.."

@(private = "file")
connect_with_cache :: proc(t: ^testing.T, cache_size: int) -> ^pg.Conn {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return nil
	}
	parsed, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&parsed)
	cfg := parsed
	cfg.allocator = {}
	cfg.statement_cache_size = cache_size

	conn, conn_err := pg.connect(cfg)
	testing.expectf(t, conn_err == nil, "connect failed: %v", conn_err)
	return conn
}

@(test)
test_explicit_prepare :: proc(t: ^testing.T) {
	conn := connect_with_cache(t, -1) // cache disabled: exercise stmt API alone
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	stmt, err := pg.prepare(conn, "SELECT $1::int8 * 2 AS doubled")
	testing.expectf(t, err == nil, "prepare failed: %v", err)
	if err != nil {
		return
	}
	defer pg.stmt_close(conn, stmt)

	testing.expect_value(t, len(stmt.param_oids), 1)
	testing.expect_value(t, stmt.param_oids[0], pg.INT8)
	testing.expect_value(t, len(stmt.fields), 1)
	testing.expect_value(t, stmt.fields[0].name, "doubled")

	for expected in ([]i64{2, 4, 6}) {
		res, q_err := pg.stmt_query(conn, stmt, expected / 2)
		testing.expect_value(t, q_err, nil)
		defer pg.result_destroy(&res)
		v, get_err := pg.get(res.rows[0], i64, 0)
		testing.expect_value(t, get_err, nil)
		testing.expect_value(t, v, expected)
	}

	// Statement errors surface and leave the conn usable.
	_, bad_err := pg.prepare(conn, "SELECT nope FROM nowhere")
	code, has_code := pg.sqlstate(bad_err)
	testing.expect(t, has_code)
	testing.expect_value(t, code, "42P01")
	_, ok_err := pg.exec(conn, "SELECT 1")
	testing.expect_value(t, ok_err, nil)
}

@(test)
test_stmt_cache_eviction :: proc(t: ^testing.T) {
	conn := connect_with_cache(t, 2)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	// Three distinct parameterized queries with a cache of two forces an
	// eviction (deferred Close of the LRU statement), then re-running the
	// evicted SQL re-prepares it. Every step must produce correct results.
	queries := []string {
		"SELECT $1::int8 + 1",
		"SELECT $1::int8 + 2",
		"SELECT $1::int8 + 3",
		"SELECT $1::int8 + 1", // re-prepare after eviction
		"SELECT $1::int8 + 2",
	}
	expected := []i64{11, 12, 13, 11, 12}
	for sql, i in queries {
		res, err := pg.query(conn, sql, 10)
		testing.expectf(t, err == nil, "query %d failed: %v", i, err)
		if err != nil {
			return
		}
		defer pg.result_destroy(&res)
		v, get_err := pg.get(res.rows[0], i64, 0)
		testing.expect_value(t, get_err, nil)
		testing.expect_value(t, v, expected[i])
	}

	// The server must agree only 2 statements remain (the deferred Close
	// messages have all been flushed by subsequent commands by now).
	res, err := pg.query(conn, "SELECT count(*) FROM pg_prepared_statements")
	testing.expect_value(t, err, nil)
	defer pg.result_destroy(&res)
	count, _ := pg.row_text(res.rows[0], 0)
	testing.expect_value(t, count, "2")
}

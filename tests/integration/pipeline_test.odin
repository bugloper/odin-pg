package pg_integration_tests

import "core:testing"

import pg "../.."

@(test)
test_pipeline :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}
	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "connect failed: %v", err)
	if err != nil {
		return
	}
	defer pg.conn_close(conn)

	p, begin_err := pg.pipeline_begin(conn)
	testing.expect_value(t, begin_err, nil)
	defer pg.pipeline_close(&p)

	// Regular queries are blocked while the pipeline is open.
	_, blocked := pg.query(conn, "SELECT 1")
	testing.expect_value(t, blocked, pg.Error(pg.Driver_Error.In_Pipeline))

	// Batch of three commands, one round trip.
	testing.expect_value(t, pg.pipeline_query(&p, "SELECT $1::int8 * 2", 21), nil)
	testing.expect_value(t, pg.pipeline_exec(&p, "CREATE TEMP TABLE pipe_test (id int8)"), nil)
	testing.expect_value(t, pg.pipeline_exec(&p, "INSERT INTO pipe_test VALUES ($1), ($2)", 1, 2), nil)

	items, sync_err := pg.pipeline_sync(&p)
	testing.expectf(t, sync_err == nil, "pipeline_sync failed: %v", sync_err)
	if sync_err != nil {
		return
	}
	testing.expect_value(t, len(items), 3)
	testing.expect_value(t, items[0].err, nil)
	v, _ := pg.get(items[0].result.rows[0], i64, 0)
	testing.expect_value(t, v, i64(42))
	testing.expect_value(t, items[1].err, nil)
	testing.expect_value(t, items[2].err, nil)
	testing.expect_value(t, items[2].result.tag.rows_affected, i64(2))
	pg.pipeline_items_destroy(items)

	// Error mid-batch: first succeeds, second fails, third is aborted.
	testing.expect_value(t, pg.pipeline_query(&p, "SELECT 1::int8"), nil)
	testing.expect_value(t, pg.pipeline_query(&p, "SELECT 1/0"), nil)
	testing.expect_value(t, pg.pipeline_query(&p, "SELECT 3::int8"), nil)

	items2, sync_err2 := pg.pipeline_sync(&p)
	testing.expectf(t, sync_err2 == nil, "second sync failed: %v", sync_err2)
	if sync_err2 != nil {
		return
	}
	testing.expect_value(t, len(items2), 3)
	testing.expect_value(t, items2[0].err, nil)
	code, has_code := pg.sqlstate(items2[1].err)
	testing.expect(t, has_code)
	testing.expect_value(t, code, "22012") // division_by_zero
	testing.expect_value(t, items2[2].err, pg.Error(pg.Driver_Error.Pipeline_Aborted))
	pg.pipeline_items_destroy(items2)

	// The pipeline (and connection) remain usable after an aborted batch.
	testing.expect_value(t, pg.pipeline_query(&p, "SELECT 'recovered'"), nil)
	items3, sync_err3 := pg.pipeline_sync(&p)
	testing.expect_value(t, sync_err3, nil)
	if sync_err3 == nil {
		text, _ := pg.row_text(items3[0].result.rows[0], 0)
		testing.expect_value(t, text, "recovered")
		pg.pipeline_items_destroy(items3)
	}

	// Close reopens normal queries.
	testing.expect_value(t, pg.pipeline_close(&p), nil)
	_, after_err := pg.exec(conn, "SELECT 1")
	testing.expect_value(t, after_err, nil)
}

@(test)
test_pipeline_cached_statements :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}
	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "connect failed: %v", err)
	if err != nil {
		return
	}
	defer pg.conn_close(conn)

	// Warm the statement cache, then pipeline the same SQL: the pipeline
	// binds against the named statement (binary results included).
	warm, warm_err := pg.query(conn, "SELECT $1::int8 + 5", 0)
	testing.expect_value(t, warm_err, nil)
	pg.result_destroy(&warm)

	p, _ := pg.pipeline_begin(conn)
	defer pg.pipeline_close(&p)
	for i in 1 ..= 3 {
		testing.expect_value(t, pg.pipeline_query(&p, "SELECT $1::int8 + 5", i), nil)
	}
	items, sync_err := pg.pipeline_sync(&p)
	testing.expect_value(t, sync_err, nil)
	if sync_err != nil {
		return
	}
	defer pg.pipeline_items_destroy(items)
	for it, i in items {
		testing.expect_value(t, it.err, nil)
		v, get_err := pg.get(it.result.rows[0], i64, 0)
		testing.expect_value(t, get_err, nil)
		testing.expect_value(t, v, i64(i + 6))
	}
}

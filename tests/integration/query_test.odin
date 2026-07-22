package pg_integration_tests

import "core:testing"
import "core:thread"
import "core:time"

import pg "../.."

@(private = "file")
connect_or_skip :: proc(t: ^testing.T) -> ^pg.Conn {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return nil
	}
	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "connect failed: %v", err)
	return conn
}

@(test)
test_simple_query :: proc(t: ^testing.T) {
	conn := connect_or_skip(t)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	res, err := pg.query(conn, "SELECT 1 AS one, 'hello' AS greeting, NULL::text AS nothing")
	testing.expectf(t, err == nil, "query failed: %v", err)
	if err != nil {
		return
	}
	defer pg.result_destroy(&res)

	testing.expect_value(t, len(res.rows), 1)
	testing.expect_value(t, len(res.fields), 3)
	testing.expect_value(t, res.fields[0].name, "one")
	testing.expect_value(t, res.tag.tag, "SELECT 1")
	testing.expect_value(t, res.tag.rows_affected, i64(1))

	row := res.rows[0]
	one, _ := pg.row_text(row, 0)
	testing.expect_value(t, one, "1")
	greeting, _ := pg.row_text(row, 1)
	testing.expect_value(t, greeting, "hello")
	_, not_null := pg.row_text(row, 2)
	testing.expect(t, !not_null)

	col, found := pg.column_index(row, "greeting")
	testing.expect(t, found)
	testing.expect_value(t, col, 1)
}

@(test)
test_extended_query_params :: proc(t: ^testing.T) {
	conn := connect_or_skip(t)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	res, err := pg.query(
		conn,
		"SELECT $1::int8 + 1, $2::text, $3::bool, $4::float8, $5::text",
		41,
		"param",
		true,
		2.5,
		nil,
	)
	testing.expectf(t, err == nil, "extended query failed: %v", err)
	if err != nil {
		return
	}
	defer pg.result_destroy(&res)

	testing.expect_value(t, len(res.rows), 1)
	row := res.rows[0]
	// Parameterized queries ride the statement cache, so well-known types
	// arrive in binary format — read them through the typed accessors.
	sum, sum_err := pg.get(row, i64, 0)
	testing.expect_value(t, sum_err, nil)
	testing.expect_value(t, sum, i64(42))
	param, _ := pg.get(row, string, 1, context.temp_allocator)
	testing.expect_value(t, param, "param")
	flag, _ := pg.get(row, bool, 2)
	testing.expect_value(t, flag, true)
	f, _ := pg.get(row, f64, 3)
	testing.expect_value(t, f, 2.5)
	null_text, null_err := pg.get(row, Maybe(string), 4, context.temp_allocator)
	testing.expect_value(t, null_err, nil)
	testing.expect(t, null_text == nil)
}

@(test)
test_error_recovery :: proc(t: ^testing.T) {
	conn := connect_or_skip(t)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	// A failing query must surface the SQLSTATE and leave the conn usable.
	_, err := pg.query(conn, "SELECT * FROM table_that_does_not_exist")
	code, has_code := pg.sqlstate(err)
	testing.expectf(t, has_code, "expected server error, got: %v", err)
	testing.expect_value(t, code, "42P01") // undefined_table

	res, err2 := pg.query(conn, "SELECT 'still alive'")
	testing.expectf(t, err2 == nil, "conn unusable after error: %v", err2)
	if err2 == nil {
		defer pg.result_destroy(&res)
		text, _ := pg.row_text(res.rows[0], 0)
		testing.expect_value(t, text, "still alive")
	}

	// Same for the extended-protocol path.
	_, err3 := pg.query(conn, "SELECT $1::int8 / 0", 1)
	code3, has_code3 := pg.sqlstate(err3)
	testing.expect(t, has_code3)
	testing.expect_value(t, code3, "22012") // division_by_zero
	_, err4 := pg.exec(conn, "SELECT 1")
	testing.expectf(t, err4 == nil, "conn unusable after extended error: %v", err4)
}

@(test)
test_exec_and_transactions :: proc(t: ^testing.T) {
	conn := connect_or_skip(t)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	_, err := pg.exec(conn, "CREATE TEMP TABLE tx_test (id int8 PRIMARY KEY, name text)")
	testing.expect_value(t, err, nil)

	// Committed transaction.
	{
		tx, tx_err := pg.begin(conn)
		testing.expect_value(t, tx_err, nil)
		defer pg.rollback(&tx)
		tag, ins_err := pg.exec(&tx, "INSERT INTO tx_test VALUES ($1, $2), ($3, $4)", 1, "one", 2, "two")
		testing.expect_value(t, ins_err, nil)
		testing.expect_value(t, tag.rows_affected, i64(2))
		testing.expect_value(t, pg.commit(&tx), nil)
	}

	// Rolled-back transaction.
	{
		tx, tx_err := pg.begin(conn)
		testing.expect_value(t, tx_err, nil)
		_, _ = pg.exec(&tx, "INSERT INTO tx_test VALUES (3, 'three')")
		testing.expect_value(t, pg.rollback(&tx), nil)
	}

	// Savepoint: inner rolled back, outer committed.
	{
		tx, _ := pg.begin(conn, pg.Tx_Options{iso = .Serializable})
		defer pg.rollback(&tx)
		inner, inner_err := pg.begin(&tx)
		testing.expect_value(t, inner_err, nil)
		_, _ = pg.exec(&inner, "INSERT INTO tx_test VALUES (4, 'four')")
		testing.expect_value(t, pg.rollback(&inner), nil)
		_, _ = pg.exec(&tx, "INSERT INTO tx_test VALUES (5, 'five')")
		testing.expect_value(t, pg.commit(&tx), nil)
	}

	res, q_err := pg.query(conn, "SELECT count(*), min(id), max(id) FROM tx_test")
	testing.expect_value(t, q_err, nil)
	defer pg.result_destroy(&res)
	count, _ := pg.row_text(res.rows[0], 0)
	testing.expect_value(t, count, "3") // ids 1, 2, 5
	max_id, _ := pg.row_text(res.rows[0], 2)
	testing.expect_value(t, max_id, "5")
}

@(private = "file")
Cancel_Job :: struct {
	conn: ^pg.Conn,
}

@(test)
test_cancel :: proc(t: ^testing.T) {
	conn := connect_or_skip(t)
	if conn == nil {
		return
	}
	defer pg.conn_close(conn)

	job := Cancel_Job {
		conn = conn,
	}
	canceller := thread.create_and_start_with_poly_data(&job, proc(job: ^Cancel_Job) {
		time.sleep(300 * time.Millisecond)
		_ = pg.cancel(job.conn)
	})
	defer thread.destroy(canceller)

	_, err := pg.query(conn, "SELECT pg_sleep(15)")
	code, has_code := pg.sqlstate(err)
	testing.expectf(t, has_code, "expected 57014 server error, got: %v", err)
	testing.expect_value(t, code, "57014") // query_canceled
	testing.expect(t, pg.is_query_canceled(err))

	// The canceled connection must remain usable.
	_, err2 := pg.exec(conn, "SELECT 1")
	testing.expectf(t, err2 == nil, "conn unusable after cancel: %v", err2)
}

package pg_integration_tests

import "core:strings"
import "core:testing"
import "core:time"

import pg "../.."

@(test)
test_copy_roundtrip :: proc(t: ^testing.T) {
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

	_, err = pg.exec(conn, "CREATE TEMP TABLE copy_test (id int8, name text)")
	testing.expect_value(t, err, nil)

	// COPY IN: 3 rows of tab-separated text.
	c, begin_err := pg.copy_in_begin(conn, "COPY copy_test FROM STDIN")
	testing.expectf(t, begin_err == nil, "copy_in_begin failed: %v", begin_err)
	if begin_err != nil {
		return
	}
	testing.expect_value(t, pg.copy_in_write(&c, transmute([]byte)string("1\talpha\n")), nil)
	testing.expect_value(t, pg.copy_in_write(&c, transmute([]byte)string("2\tbeta\n3\t\\N\n")), nil)
	tag, finish_err := pg.copy_in_finish(&c)
	testing.expect_value(t, finish_err, nil)
	testing.expect_value(t, tag.rows_affected, i64(3))

	// COPY OUT: stream the rows back and compare.
	out := strings.builder_make(context.temp_allocator)
	_, out_err := pg.copy_out(
		conn,
		"COPY (SELECT * FROM copy_test ORDER BY id) TO STDOUT",
		proc(chunk: []byte, user: rawptr) -> pg.Error {
			sb := (^strings.Builder)(user)
			strings.write_bytes(sb, chunk)
			return nil
		},
		&out,
	)
	testing.expect_value(t, out_err, nil)
	testing.expect_value(t, strings.to_string(out), "1\talpha\n2\tbeta\n3\t\\N\n")

	// COPY abort leaves the connection usable and inserts nothing.
	c2, _ := pg.copy_in_begin(conn, "COPY copy_test FROM STDIN")
	_ = pg.copy_in_write(&c2, transmute([]byte)string("9\tzeta\n"))
	abort_err := pg.copy_in_abort(&c2, "test abort")
	testing.expect(t, abort_err != nil) // the server reports the CopyFail

	res, q_err := pg.query(conn, "SELECT count(*) FROM copy_test")
	testing.expect_value(t, q_err, nil)
	defer pg.result_destroy(&res)
	count, _ := pg.row_text(res.rows[0], 0)
	testing.expect_value(t, count, "3")
}

@(test)
test_listen_notify :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}

	listener, l_err := pg.listener_create_dsn(dsn)
	testing.expectf(t, l_err == nil, "listener_create failed: %v", l_err)
	if l_err != nil {
		return
	}
	defer pg.listener_close(listener)
	testing.expect_value(t, pg.listen(listener, "jobs"), nil)

	// Notify from a separate connection.
	notifier, n_err := pg.connect_dsn(dsn)
	testing.expect_value(t, n_err, nil)
	defer pg.conn_close(notifier)
	_, err := pg.exec(notifier, "NOTIFY jobs, 'payload one'")
	testing.expect_value(t, err, nil)

	n, wait_err := pg.next_notification(listener, 10 * time.Second)
	testing.expectf(t, wait_err == nil, "next_notification failed: %v", wait_err)
	testing.expect_value(t, n.channel, "jobs")
	testing.expect_value(t, n.payload, "payload one")
	testing.expect_value(t, n.backend_pid, pg.backend_pid(notifier))

	// Timeout path: no notification pending.
	_, timeout_err := pg.next_notification(listener, 200 * time.Millisecond)
	testing.expect_value(t, timeout_err, pg.Error(pg.Driver_Error.Read_Timeout))

	// UNLISTEN stops delivery.
	testing.expect_value(t, pg.unlisten(listener, "jobs"), nil)
	_, _ = pg.exec(notifier, "NOTIFY jobs, 'should not arrive'")
	_, gone_err := pg.next_notification(listener, 300 * time.Millisecond)
	testing.expect_value(t, gone_err, pg.Error(pg.Driver_Error.Read_Timeout))
}

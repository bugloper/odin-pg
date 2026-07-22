package pg_integration_tests

import "core:encoding/uuid"
import "core:testing"
import "core:time"
import "core:time/datetime"

import pg "../.."

@(test)
test_typed_get_live :: proc(t: ^testing.T) {
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

	res, q_err := pg.query(
		conn,
		`SELECT 9007199254740993::int8,
		        2.25::float8,
		        true,
		        'text value'::text,
		        '\xcafe'::bytea,
		        'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid,
		        '2024-06-15 12:30:45.123456+00'::timestamptz,
		        '2024-06-15'::date,
		        NULL::int8`,
	)
	testing.expectf(t, q_err == nil, "query failed: %v", q_err)
	if q_err != nil {
		return
	}
	defer pg.result_destroy(&res)
	row := res.rows[0]

	big, _ := pg.get(row, i64, 0)
	testing.expect_value(t, big, i64(9007199254740993))

	f, _ := pg.get(row, f64, 1)
	testing.expect_value(t, f, 2.25)

	b, _ := pg.get(row, bool, 2)
	testing.expect_value(t, b, true)

	s, _ := pg.get(row, string, 3, context.temp_allocator)
	testing.expect_value(t, s, "text value")

	bytes, bytes_err := pg.get(row, []byte, 4, context.temp_allocator)
	testing.expect_value(t, bytes_err, nil)
	testing.expect_value(t, len(bytes), 2)
	testing.expect_value(t, bytes[0], u8(0xCA))
	testing.expect_value(t, bytes[1], u8(0xFE))

	id, id_err := pg.get(row, uuid.Identifier, 5)
	testing.expect_value(t, id_err, nil)
	testing.expect_value(t, id[0], u8(0xA0))

	ts, ts_err := pg.get(row, time.Time, 6)
	testing.expect_value(t, ts_err, nil)
	expected_ts, _ := time.components_to_time(2024, 6, 15, 12, 30, 45, 123_456_000)
	testing.expect_value(t, ts, expected_ts)

	d, d_err := pg.get(row, datetime.Date, 7)
	testing.expect_value(t, d_err, nil)
	testing.expect_value(t, d.year, i64(2024))
	testing.expect_value(t, d.month, i8(6))
	testing.expect_value(t, d.day, i8(15))

	null_val, null_err := pg.get(row, Maybe(i64), 8)
	testing.expect_value(t, null_err, nil)
	testing.expect(t, null_val == nil)
}

package pg_integration_tests

import "core:testing"

import pg "../.."

@(test)
test_arrays_numeric_json_live :: proc(t: ^testing.T) {
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

	// Simple protocol → text-format arrays (incl. multi-D).
	res, q_err := pg.query(
		conn,
		`SELECT ARRAY[1,2,3]::int8[],
		        ARRAY['a','b,c',NULL]::text[],
		        '{}'::int4[],
		        123456.789::numeric,
		        'NaN'::numeric,
		        '{"k": [1, 2]}'::jsonb,
		        ARRAY[[1,2],[3,4]]::int8[]`,
	)
	testing.expectf(t, q_err == nil, "query failed: %v", q_err)
	if q_err != nil {
		return
	}
	defer pg.result_destroy(&res)
	row := res.rows[0]

	ints, i_err := pg.get(row, []i64, 0, context.temp_allocator)
	testing.expect_value(t, i_err, nil)
	testing.expect_value(t, len(ints), 3)
	testing.expect_value(t, ints[2], i64(3))

	texts, t_err := pg.get(row, []Maybe(string), 1, context.temp_allocator)
	testing.expect_value(t, t_err, nil)
	testing.expect_value(t, len(texts), 3)
	testing.expect_value(t, texts[1].? or_else "", "b,c")
	testing.expect(t, texts[2] == nil)

	empty, e_err := pg.get(row, []i32, 2, context.temp_allocator)
	testing.expect_value(t, e_err, nil)
	testing.expect_value(t, len(empty), 0)

	num, n_err := pg.get(row, pg.Numeric, 3, context.temp_allocator)
	testing.expect_value(t, n_err, nil)
	testing.expect_value(t, pg.numeric_to_string(num, context.temp_allocator), "123456.789")

	nan, nan_err := pg.get(row, pg.Numeric, 4, context.temp_allocator)
	testing.expect_value(t, nan_err, nil)
	testing.expect_value(t, nan.kind, pg.Numeric_Kind.NaN)

	Payload :: struct {
		k: []i64,
	}
	p, j_err := pg.get_json(row, Payload, 5, context.temp_allocator)
	testing.expect_value(t, j_err, nil)
	testing.expect_value(t, len(p.k), 2)
	testing.expect_value(t, p.k[1], i64(2))

	grid, m_err := pg.get(row, [][]i64, 6, context.temp_allocator)
	testing.expect_value(t, m_err, nil)
	testing.expect_value(t, len(grid), 2)
	testing.expect_value(t, grid[0][1], i64(2))
	testing.expect_value(t, grid[1][0], i64(3))
	testing.expect_value(t, grid[1][1], i64(4))
}

@(test)
test_scan_struct_live :: proc(t: ^testing.T) {
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

	Account :: struct {
		id:      i64,
		name:    string,
		balance: f64 `db:"credit"`,
		note:    Maybe(string),
	}

	// Extended protocol (binary formats for id/balance via the stmt cache).
	res, q_err := pg.query(
		conn,
		"SELECT $1::int8 AS id, $2::text AS name, $3::float8 AS credit, NULL::text AS note",
		77,
		"carol",
		12.5,
	)
	testing.expect_value(t, q_err, nil)
	if q_err != nil {
		return
	}
	defer pg.result_destroy(&res)

	acct: Account
	s_err := pg.scan_struct(res.rows[0], &acct, context.temp_allocator)
	testing.expect_value(t, s_err, nil)
	testing.expect_value(t, acct.id, i64(77))
	testing.expect_value(t, acct.name, "carol")
	testing.expect_value(t, acct.balance, 12.5)
	testing.expect(t, acct.note == nil)
}

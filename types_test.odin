package pg

import "core:encoding/endian"
import "core:encoding/uuid"
import "core:testing"
import "core:time"
import "core:time/datetime"

@(private = "file")
text_row :: proc(fields: []Field, values: []string, nulls: []bool = nil) -> Row {
	cells := make([]Cell, len(values), context.temp_allocator)
	for v, i in values {
		if nulls != nil && nulls[i] {
			cells[i] = Cell{is_null = true}
		} else {
			cells[i] = Cell{data = transmute([]byte)v}
		}
	}
	return Row{fields = fields, cells = cells}
}

@(test)
test_get_text_scalars :: proc(t: ^testing.T) {
	fields := []Field{{name = "a"}, {name = "b"}, {name = "c"}, {name = "d"}, {name = "e"}}
	row := text_row(fields, {"42", "-7", "3.5", "t", "hello"})

	i, err := get(row, i64, 0)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, i, i64(42))

	neg, _ := get(row, int, 1)
	testing.expect_value(t, neg, -7)

	f, _ := get(row, f64, 2)
	testing.expect_value(t, f, 3.5)

	b, _ := get(row, bool, 3)
	testing.expect_value(t, b, true)

	s, s_err := get(row, string, 4, context.temp_allocator)
	testing.expect_value(t, s_err, nil)
	testing.expect_value(t, s, "hello")

	by_name, name_err := get_by_name(row, i64, "a")
	testing.expect_value(t, name_err, nil)
	testing.expect_value(t, by_name, i64(42))

	_, missing := get_by_name(row, i64, "zzz")
	testing.expect_value(t, missing, Error(Driver_Error.No_Such_Column))
}

@(test)
test_get_null_handling :: proc(t: ^testing.T) {
	fields := []Field{{name = "a"}}
	row := text_row(fields, {""}, {true})

	_, err := get(row, i64, 0)
	testing.expect_value(t, err, Error(Driver_Error.Null_Value))

	maybe, m_err := get(row, Maybe(i64), 0)
	testing.expect_value(t, m_err, nil)
	testing.expect(t, maybe == nil)

	row2 := text_row(fields, {"9"})
	maybe2, _ := get(row2, Maybe(i64), 0)
	v, has := maybe2.?
	testing.expect(t, has)
	testing.expect_value(t, v, i64(9))
}

@(test)
test_get_range_checks :: proc(t: ^testing.T) {
	fields := []Field{{name = "a"}}

	_, err := get(text_row(fields, {"70000"}), i16, 0)
	testing.expect_value(t, err, Error(Driver_Error.Out_Of_Range))

	_, err2 := get(text_row(fields, {"-1"}), u64, 0)
	testing.expect_value(t, err2, Error(Driver_Error.Out_Of_Range))

	_, err3 := get(text_row(fields, {"not_a_number"}), i64, 0)
	testing.expect_value(t, err3, Error(Driver_Error.Type_Mismatch))

	_, err4 := get(text_row(fields, {"1"}), i64, 5)
	testing.expect_value(t, err4, Error(Driver_Error.Column_Out_Of_Range))
}

@(test)
test_get_bytea_text :: proc(t: ^testing.T) {
	fields := []Field{{name = "a", type_oid = BYTEA}}
	row := text_row(fields, {"\\xdeadbeef"})

	b, err := get(row, []byte, 0, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(b), 4)
	testing.expect_value(t, b[0], u8(0xDE))
	testing.expect_value(t, b[3], u8(0xEF))

	_, bad := get(text_row(fields, {"\\xzz"}), []byte, 0, context.temp_allocator)
	testing.expect_value(t, bad, Error(Driver_Error.Type_Mismatch))
}

@(test)
test_get_uuid_text :: proc(t: ^testing.T) {
	fields := []Field{{name = "a", type_oid = UUID}}
	row := text_row(fields, {"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"})

	id, err := get(row, uuid.Identifier, 0)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, id[0], u8(0xA0))
	testing.expect_value(t, id[15], u8(0x11))
}

@(test)
test_get_timestamp_text :: proc(t: ^testing.T) {
	fields := []Field{{name = "a", type_oid = TIMESTAMPTZ}}

	// 2024-01-02 03:04:05.5 UTC
	row := text_row(fields, {"2024-01-02 03:04:05.5+00"})
	ts, err := get(row, time.Time, 0)
	testing.expect_value(t, err, nil)
	expected, _ := time.components_to_time(2024, 1, 2, 3, 4, 5, 500_000_000)
	testing.expect_value(t, ts, expected)

	// Same instant expressed with a +05:30 offset.
	row2 := text_row(fields, {"2024-01-02 08:34:05.5+05:30"})
	ts2, _ := get(row2, time.Time, 0)
	testing.expect_value(t, ts2, expected)

	// Plain timestamp without offset or fraction.
	row3 := text_row(fields, {"2024-01-02 03:04:05"})
	ts3, _ := get(row3, time.Time, 0)
	expected3, _ := time.components_to_time(2024, 1, 2, 3, 4, 5)
	testing.expect_value(t, ts3, expected3)

	_, inf_err := get(text_row(fields, {"infinity"}), time.Time, 0)
	testing.expect_value(t, inf_err, Error(Driver_Error.Out_Of_Range))

	_, bc_err := get(text_row(fields, {"0001-01-01 00:00:00 BC"}), time.Time, 0)
	testing.expect_value(t, bc_err, Error(Driver_Error.Out_Of_Range))
}

@(test)
test_get_date_text :: proc(t: ^testing.T) {
	fields := []Field{{name = "a", type_oid = DATE}}
	row := text_row(fields, {"2024-02-29"})

	d, err := get(row, datetime.Date, 0)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, d.year, i64(2024))
	testing.expect_value(t, d.month, i8(2))
	testing.expect_value(t, d.day, i8(29))

	_, bad := get(text_row(fields, {"2023-02-29"}), datetime.Date, 0)
	testing.expect_value(t, bad, Error(Driver_Error.Type_Mismatch))
}

@(test)
test_get_binary_scalars :: proc(t: ^testing.T) {
	buf8: [8]u8
	endian.put_i64(buf8[:], .Big, -123456789)
	buf4: [4]u8
	endian.put_u32(buf4[:], .Big, transmute(u32)f32(1.5))
	buf2: [2]u8
	endian.put_i16(buf2[:], .Big, -300)

	fields := []Field {
		{name = "a", type_oid = INT8, format = .Binary},
		{name = "b", type_oid = FLOAT4, format = .Binary},
		{name = "c", type_oid = INT2, format = .Binary},
		{name = "d", type_oid = BOOL, format = .Binary},
	}
	cells := []Cell{{data = buf8[:]}, {data = buf4[:]}, {data = buf2[:]}, {data = {1}}}
	row := Row {
		fields = fields,
		cells  = cells,
	}

	i, err := get(row, i64, 0)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, i, i64(-123456789))

	f, _ := get(row, f32, 1)
	testing.expect_value(t, f, f32(1.5))

	small, _ := get(row, i16, 2)
	testing.expect_value(t, small, i16(-300))

	b, _ := get(row, bool, 3)
	testing.expect_value(t, b, true)

	// i16 wire value fits any wider integer.
	wide, _ := get(row, i64, 2)
	testing.expect_value(t, wide, i64(-300))
}

@(test)
test_get_binary_timestamp_date_uuid :: proc(t: ^testing.T) {
	// 2000-01-01 00:00:01 UTC = 1_000_000 µs after the PG epoch.
	ts_buf: [8]u8
	endian.put_i64(ts_buf[:], .Big, 1_000_000)
	// 2000-03-01 is day 60 of 2000 (leap year: 31 + 29).
	date_buf: [4]u8
	endian.put_i32(date_buf[:], .Big, 60)
	id_bytes := [16]u8{0xA0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF}

	fields := []Field {
		{name = "a", type_oid = TIMESTAMPTZ, format = .Binary},
		{name = "b", type_oid = DATE, format = .Binary},
		{name = "c", type_oid = UUID, format = .Binary},
	}
	cells := []Cell{{data = ts_buf[:]}, {data = date_buf[:]}, {data = id_bytes[:]}}
	row := Row {
		fields = fields,
		cells  = cells,
	}

	ts, err := get(row, time.Time, 0)
	testing.expect_value(t, err, nil)
	expected, _ := time.components_to_time(2000, 1, 1, 0, 0, 1)
	testing.expect_value(t, ts, expected)

	d, _ := get(row, datetime.Date, 1)
	testing.expect_value(t, d.year, i64(2000))
	testing.expect_value(t, d.month, i8(3))
	testing.expect_value(t, d.day, i8(1))

	id, _ := get(row, uuid.Identifier, 2)
	testing.expect_value(t, id[0], u8(0xA0))
	testing.expect_value(t, id[15], u8(0xFF))
}

@(test)
test_scan :: proc(t: ^testing.T) {
	fields := []Field{{name = "id"}, {name = "name"}, {name = "score"}, {name = "note"}}
	row := text_row(fields, {"7", "alice", "9.75", ""}, {false, false, false, true})

	id: i64
	name: string
	score: f64
	note: Maybe(string)
	err := scan(row, &id, &name, &score, &note, allocator = context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, id, i64(7))
	testing.expect_value(t, name, "alice")
	testing.expect_value(t, score, 9.75)
	testing.expect(t, note == nil)

	unsupported: complex64
	bad := scan(row, &unsupported)
	testing.expect_value(t, bad, Error(Driver_Error.Unsupported_Type))
}

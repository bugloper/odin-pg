package pg

import "core:encoding/endian"
import "core:testing"

@(test)
test_array_text :: proc(t: ^testing.T) {
	fields := []Field{{name = "a", type_oid = INT8_ARRAY}}
	row := text_row_x(fields, {"{1,2,3}"})

	ints, err := get(row, []i64, 0, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(ints), 3)
	testing.expect_value(t, ints[0], i64(1))
	testing.expect_value(t, ints[2], i64(3))

	// Empty array.
	empty, empty_err := get(text_row_x(fields, {"{}"}), []i64, 0, context.temp_allocator)
	testing.expect_value(t, empty_err, nil)
	testing.expect_value(t, len(empty), 0)

	// NULL element requires Maybe.
	_, null_err := get(text_row_x(fields, {"{1,NULL}"}), []i64, 0, context.temp_allocator)
	testing.expect_value(t, null_err, Error(Driver_Error.Null_Value))
	maybes, m_err := get(text_row_x(fields, {"{1,NULL}"}), []Maybe(i64), 0, context.temp_allocator)
	testing.expect_value(t, m_err, nil)
	testing.expect_value(t, len(maybes), 2)
	testing.expect(t, maybes[1] == nil)

	// Quoted strings with escapes and embedded delimiters.
	sfields := []Field{{name = "a", type_oid = TEXT_ARRAY}}
	strs, s_err := get(
		text_row_x(sfields, {`{plain,"with, comma","esc \" quote","",NULL}`}),
		[]Maybe(string),
		0,
		context.temp_allocator,
	)
	testing.expect_value(t, s_err, nil)
	testing.expect_value(t, len(strs), 5)
	testing.expect_value(t, strs[0].? or_else "", "plain")
	testing.expect_value(t, strs[1].? or_else "", "with, comma")
	testing.expect_value(t, strs[2].? or_else "", `esc " quote`)
	testing.expect_value(t, strs[3].? or_else "?", "")
	testing.expect(t, strs[4] == nil)

	// Rank mismatch: multi-D wire into 1-D dest is rejected, not mis-decoded.
	_, multi_err := get(text_row_x(fields, {"{{1},{2}}"}), []i64, 0, context.temp_allocator)
	testing.expect_value(t, multi_err, Error(Driver_Error.Unsupported_Type))

	// 2-D text array → [][]i64.
	grid, m2_err := get(text_row_x(fields, {"{{1,2},{3,4}}"}), [][]i64, 0, context.temp_allocator)
	testing.expect_value(t, m2_err, nil)
	testing.expect_value(t, len(grid), 2)
	testing.expect_value(t, len(grid[0]), 2)
	testing.expect_value(t, grid[0][0], i64(1))
	testing.expect_value(t, grid[0][1], i64(2))
	testing.expect_value(t, grid[1][0], i64(3))
	testing.expect_value(t, grid[1][1], i64(4))

	// Explicit multi-D bounds prefix.
	bounded, b_err := get(text_row_x(fields, {"[1:2][1:2]={{10,20},{30,40}}"}), [][]i64, 0, context.temp_allocator)
	testing.expect_value(t, b_err, nil)
	testing.expect_value(t, bounded[1][1], i64(40))

	// Empty multi-D destination from empty literal.
	empty2, e2_err := get(text_row_x(fields, {"{}"}), [][]i64, 0, context.temp_allocator)
	testing.expect_value(t, e2_err, nil)
	testing.expect_value(t, len(empty2), 0)

	// 1-D wire into multi-D dest is rejected.
	_, rank_err := get(text_row_x(fields, {"{1,2}"}), [][]i64, 0, context.temp_allocator)
	testing.expect_value(t, rank_err, Error(Driver_Error.Unsupported_Type))

	// Nested NULLs require Maybe at the leaf.
	null_grid, nm_err := get(
		text_row_x(fields, {"{{1,NULL},{2,3}}"}),
		[][]Maybe(i64),
		0,
		context.temp_allocator,
	)
	testing.expect_value(t, nm_err, nil)
	testing.expect(t, null_grid[0][1] == nil)
	testing.expect_value(t, null_grid[1][0].? or_else 0, i64(2))
}

@(test)
test_array_binary :: proc(t: ^testing.T) {
	// Build binary array [10, NULL, 30]::int8[].
	buf := make([dynamic]u8, context.temp_allocator)
	four: [4]u8
	eight: [8]u8
	put_i32 :: proc(b: ^[dynamic]u8, four: ^[4]u8, v: i32) {
		endian.put_i32(four[:], .Big, v)
		append(b, ..four[:])
	}
	put_i32(&buf, &four, 1) // ndim
	put_i32(&buf, &four, 1) // hasnull
	endian.put_u32(four[:], .Big, u32(INT8))
	append(&buf, ..four[:]) // elem oid
	put_i32(&buf, &four, 3) // dim length
	put_i32(&buf, &four, 1) // lower bound
	put_i32(&buf, &four, 8) // elem 0 length
	endian.put_i64(eight[:], .Big, 10)
	append(&buf, ..eight[:])
	put_i32(&buf, &four, -1) // elem 1 NULL
	put_i32(&buf, &four, 8) // elem 2 length
	endian.put_i64(eight[:], .Big, 30)
	append(&buf, ..eight[:])

	fields := []Field{{name = "a", type_oid = INT8_ARRAY, format = .Binary}}
	cells := []Cell{{data = buf[:]}}
	row := Row {
		fields = fields,
		cells  = cells,
	}

	vals, err := get(row, []Maybe(i64), 0, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(vals), 3)
	testing.expect_value(t, vals[0].? or_else 0, i64(10))
	testing.expect(t, vals[1] == nil)
	testing.expect_value(t, vals[2].? or_else 0, i64(30))
}

@(test)
test_array_binary_2d :: proc(t: ^testing.T) {
	// Binary [[1, 2], [3, 4]]::int8[][] — ndim=2, dims 2×2, row-major.
	buf := make([dynamic]u8, context.temp_allocator)
	four: [4]u8
	eight: [8]u8
	put_i32 :: proc(b: ^[dynamic]u8, four: ^[4]u8, v: i32) {
		endian.put_i32(four[:], .Big, v)
		append(b, ..four[:])
	}
	put_i64 :: proc(b: ^[dynamic]u8, four: ^[4]u8, eight: ^[8]u8, v: i64) {
		put_i32(b, four, 8)
		endian.put_i64(eight[:], .Big, v)
		append(b, ..eight[:])
	}
	put_i32(&buf, &four, 2) // ndim
	put_i32(&buf, &four, 0) // hasnull
	endian.put_u32(four[:], .Big, u32(INT8))
	append(&buf, ..four[:])
	put_i32(&buf, &four, 2) // dim0 length
	put_i32(&buf, &four, 1) // dim0 lower
	put_i32(&buf, &four, 2) // dim1 length
	put_i32(&buf, &four, 1) // dim1 lower
	put_i64(&buf, &four, &eight, 1)
	put_i64(&buf, &four, &eight, 2)
	put_i64(&buf, &four, &eight, 3)
	put_i64(&buf, &four, &eight, 4)

	fields := []Field{{name = "a", type_oid = INT8_ARRAY, format = .Binary}}
	cells := []Cell{{data = buf[:]}}
	row := Row {
		fields = fields,
		cells  = cells,
	}

	grid, err := get(row, [][]i64, 0, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, len(grid), 2)
	testing.expect_value(t, grid[0][0], i64(1))
	testing.expect_value(t, grid[0][1], i64(2))
	testing.expect_value(t, grid[1][0], i64(3))
	testing.expect_value(t, grid[1][1], i64(4))

	// Rank mismatch: 2-D wire into 1-D dest.
	_, rank_err := get(row, []i64, 0, context.temp_allocator)
	testing.expect_value(t, rank_err, Error(Driver_Error.Unsupported_Type))
}

@(test)
test_numeric_text_roundtrip :: proc(t: ^testing.T) {
	cases := []string {
		"0",
		"1",
		"-1",
		"123.45",
		"-0.001",
		"12345678901234567890.123456789",
		"0.0000",
		"10000",
		"9999.9999",
		"NaN",
		"Infinity",
		"-Infinity",
	}
	for input in cases {
		n, err := parse_numeric_text(input, context.temp_allocator)
		testing.expectf(t, err == nil, "parse %q failed: %v", input, err)
		out := numeric_to_string(n, context.temp_allocator)
		expected := input
		if input == "0.0000" {
			expected = "0.0000" // dscale preserved
		}
		testing.expectf(t, out == expected, "roundtrip %q -> %q", input, out)
	}

	_, bad := parse_numeric_text("12a4", context.temp_allocator)
	testing.expect_value(t, bad, Error(Driver_Error.Type_Mismatch))
}

@(test)
test_numeric_binary :: proc(t: ^testing.T) {
	// -12345.6789 = sign neg, weight 1, dscale 4, digits [1, 2345, 6789].
	buf := make([dynamic]u8, context.temp_allocator)
	two: [2]u8
	put16 :: proc(b: ^[dynamic]u8, two: ^[2]u8, v: u16) {
		endian.put_u16(two[:], .Big, v)
		append(b, ..two[:])
	}
	put16(&buf, &two, 3) // ndigits
	put16(&buf, &two, 1) // weight
	put16(&buf, &two, 0x4000) // sign: negative
	put16(&buf, &two, 4) // dscale
	put16(&buf, &two, 1)
	put16(&buf, &two, 2345)
	put16(&buf, &two, 6789)

	n, err := parse_numeric_binary(buf[:], context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, numeric_to_string(n, context.temp_allocator), "-12345.6789")
	testing.expect_value(t, numeric_to_f64(n), -12345.6789)
}

@(test)
test_get_json :: proc(t: ^testing.T) {
	Payload :: struct {
		id:   i64,
		name: string,
	}
	fields := []Field{{name = "a", type_oid = JSONB}}
	row := text_row_x(fields, {`{"id": 7, "name": "alice"}`})

	p, err := get_json(row, Payload, 0, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, p.id, i64(7))
	testing.expect_value(t, p.name, "alice")

	// Binary jsonb: version byte prefix.
	body := []u8{1, '{', '"', 'i', 'd', '"', ':', '3', ',', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 'x', '"', '}'}
	bfields := []Field{{name = "a", type_oid = JSONB, format = .Binary}}
	bcells := []Cell{{data = body}}
	brow := Row {
		fields = bfields,
		cells  = bcells,
	}
	p2, err2 := get_json(brow, Payload, 0, context.temp_allocator)
	testing.expect_value(t, err2, nil)
	testing.expect_value(t, p2.id, i64(3))
}

@(test)
test_scan_struct :: proc(t: ^testing.T) {
	User :: struct {
		id:       i64,
		name:     string,
		note:     Maybe(string) `db:"comment"`,
		internal: bool `db:"-"`,
		missing:  f64, // untagged, no matching column: skipped
	}
	fields := []Field{{name = "id"}, {name = "name"}, {name = "comment"}}
	row := text_row_x(fields, {"9", "bob", ""}, {false, false, true})

	u: User
	err := scan_struct(row, &u, context.temp_allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, u.id, i64(9))
	testing.expect_value(t, u.name, "bob")
	testing.expect(t, u.note == nil)
	testing.expect_value(t, u.missing, 0.0)

	// A tagged field whose column is absent is an error.
	Strict :: struct {
		nope: i64 `db:"no_such"`,
	}
	s: Strict
	strict_err := scan_struct(row, &s, context.temp_allocator)
	testing.expect_value(t, strict_err, Error(Driver_Error.No_Such_Column))
}

// Local text-row fixture (types_test.odin has a file-private twin).
@(private = "file")
text_row_x :: proc(fields: []Field, values: []string, nulls: []bool = nil) -> Row {
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

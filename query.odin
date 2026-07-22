package pg

import "core:mem/virtual"
import "core:strconv"
import "core:strings"

// Command_Tag is the summary from CommandComplete ("INSERT 0 5",
// "SELECT 3", …). The string is owned by the Result (or, for exec, by the
// connection's error arena — valid until the next command).
Command_Tag :: struct {
	tag:           string,
	rows_affected: i64,
}

Cell :: struct {
	data:    []byte,
	is_null: bool,
}

Row :: struct {
	fields: []Field,
	cells:  []Cell,
}

// Result owns all rows of one query, copied out of the connection's read
// buffer into a private arena. It is independent of the connection (safe to
// keep after releasing a pooled conn); free with result_destroy. A Result
// has single ownership: destroy it once, don't copy-and-destroy-twice.
Result :: struct {
	fields: []Field,
	rows:   []Row,
	tag:    Command_Tag,
	arena:  virtual.Arena,
}

result_destroy :: proc(res: ^Result) {
	virtual.arena_destroy(&res.arena)
	res^ = {}
}

// row_cell returns the raw wire bytes of one column.
row_cell :: proc(row: Row, col: int) -> (data: []byte, is_null: bool, err: Error) {
	if col < 0 || col >= len(row.cells) {
		return nil, false, Driver_Error.Column_Out_Of_Range
	}
	cell := row.cells[col]
	return cell.data, cell.is_null, nil
}

// row_text returns a column as a string view over the Result's memory
// (text-format cells only for now; binary formats arrive with the type
// system). NULL yields ok = false.
row_text :: proc(row: Row, col: int) -> (text: string, ok: bool) {
	if col < 0 || col >= len(row.cells) {
		return "", false
	}
	cell := row.cells[col]
	if cell.is_null {
		return "", false
	}
	return string(cell.data), true
}

column_index :: proc(row: Row, name: string) -> (col: int, ok: bool) {
	for f, i in row.fields {
		if f.name == name {
			return i, true
		}
	}
	return -1, false
}

// exec runs a command and returns its tag; result rows, if any, are
// discarded. The tag string borrows the connection's error arena (valid
// until the next command).
conn_exec :: proc(conn: ^Conn, sql: string, args: ..any) -> (tag: Command_Tag, err: Error) {
	res: Result
	res, err = conn_query(conn, sql, ..args)
	if err != nil {
		return {}, err
	}
	tag = res.tag
	tag.tag, _ = strings.clone(res.tag.tag, virtual.arena_allocator(&conn.err_arena))
	result_destroy(&res)
	return tag, nil
}

// query runs sql and collects all rows into a Result. With no args it uses
// the simple protocol; with args it uses the extended protocol (Parse/Bind/
// Describe/Execute/Sync) with out-of-band parameters — never string
// interpolation. For multi-statement simple queries, the last statement's
// result set is returned.
conn_query :: proc(conn: ^Conn, sql: string, args: ..any) -> (res: Result, err: Error) {
	command_begin(conn) or_return

	if len(args) == 0 {
		write_query(&conn.writer, sql)
		if flush_err := flush(&conn.writer); flush_err != nil {
			conn.status = .Broken
			return {}, flush_err
		}
		return collect_result(conn, nil)
	}

	// Parameterized queries go through the statement cache when enabled,
	// which also buys binary result formats for well-known types.
	if stmt := cached_stmt(conn, sql) or_return; stmt != nil {
		return stmt_query(conn, stmt, ..args)
	}

	// Cache disabled: one-shot unnamed statement, all-text results.
	params, encode_err := encode_text_params(args)
	if encode_err != nil {
		return {}, encode_err
	}
	write_parse(&conn.writer, "", sql, nil)
	write_bind(&conn.writer, "", "", nil, params, nil)
	write_describe(&conn.writer, .Portal, "")
	write_execute(&conn.writer, "")
	write_sync(&conn.writer)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return {}, flush_err
	}
	return collect_result(conn, nil)
}

// query_row runs query and expects exactly one row.
conn_query_row :: proc(conn: ^Conn, sql: string, args: ..any) -> (res: Result, err: Error) {
	res = conn_query(conn, sql, ..args) or_return
	switch len(res.rows) {
	case 1:
		return res, nil
	case 0:
		result_destroy(&res)
		return {}, Driver_Error.No_Rows
	}
	result_destroy(&res)
	return {}, Driver_Error.Too_Many_Rows
}

// collect_result reads backend messages until ReadyForQuery, copying row
// data into the Result's arena. On a server error the stream is drained so
// the connection stays usable, and the error is returned. preset_fields
// (from a prepared statement, which skips Describe) seed the column
// metadata when the server won't send RowDescription.
@(private)
collect_result :: proc(conn: ^Conn, preset_fields: []Field) -> (res: Result, err: Error) {
	if arena_err := virtual.arena_init_growing(&res.arena, RESULT_ARENA_RESERVE); arena_err != nil {
		conn.status = .Broken
		return {}, arena_err
	}
	arena_alloc := virtual.arena_allocator(&res.arena)

	fields := make([dynamic]Field, arena_alloc)
	rows := make([dynamic]Row, arena_alloc)
	spans := make([dynamic]Cell_Span, context.temp_allocator)
	first_err: Error

	for f in preset_fields {
		field := f
		field.name, _ = strings.clone(f.name, arena_alloc)
		append(&fields, field)
	}

	loop: for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			result_destroy(&res)
			return {}, read_err
		}

		#partial switch kind {
		case .Row_Description:
			// A fresh result set (multi-statement queries): start over.
			clear(&fields)
			clear(&rows)
			if !parse_row_description(body, &fields) {
				first_err = protocol_broken(conn, first_err)
				continue
			}
			for &f in fields {
				f.name, _ = strings.clone(f.name, arena_alloc)
			}
		case .Data_Row:
			if first_err != nil {
				continue // draining after an error; discard rows
			}
			if !parse_data_row(body, &spans) {
				first_err = protocol_broken(conn, first_err)
				continue
			}
			body_copy := make([]byte, len(body), arena_alloc)
			copy(body_copy, body)
			cells := make([]Cell, len(spans), arena_alloc)
			for span, i in spans {
				if span.len == -1 {
					cells[i] = Cell{is_null = true}
				} else {
					cells[i] = Cell {
						data = body_copy[span.off:span.off + span.len],
					}
				}
			}
			append(&rows, Row{fields = fields[:], cells = cells})
		case .Command_Complete:
			if tag, ok := parse_command_complete(body); ok {
				res.tag.tag, _ = strings.clone(tag, arena_alloc)
				res.tag.rows_affected = tag_rows_affected(tag)
			}
		case .Empty_Query_Response, .Parse_Complete, .Bind_Complete, .Close_Complete, .No_Data, .Portal_Suspended, .Parameter_Description:
		// Nothing to record.
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				result_destroy(&res)
				return {}, Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			break loop
		case .Error_Response:
			if first_err == nil {
				first_err = conn_server_error(conn, body)
			}
		case .Notice_Response:
		// Dropped in v1.
		case .Parameter_Status:
			if ps_err := handle_parameter_status(conn, body); ps_err != nil && first_err == nil {
				first_err = ps_err
			}
		case .Notification_Response:
			if n_err := buffer_notification(conn, body); n_err != nil && first_err == nil {
				first_err = n_err
			}
		case:
			first_err = protocol_broken(conn, first_err)
			break loop
		}
	}

	if first_err != nil {
		result_destroy(&res)
		return {}, first_err
	}
	res.fields = fields[:]
	res.rows = rows[:]
	return res, nil
}

@(private = "file")
protocol_broken :: proc(conn: ^Conn, first_err: Error) -> Error {
	conn.status = .Broken
	if first_err != nil {
		return first_err
	}
	return Driver_Error.Protocol_Error
}

// tag_rows_affected extracts the trailing row count of a command tag
// ("INSERT 0 5" -> 5, "UPDATE 3" -> 3, "CREATE TABLE" -> 0).
@(private)
tag_rows_affected :: proc(tag: string) -> i64 {
	last_space := strings.last_index_byte(tag, ' ')
	if last_space < 0 {
		return 0
	}
	n, ok := strconv.parse_i64(tag[last_space + 1:])
	if !ok {
		return 0
	}
	return n
}

// encode_text_params renders query arguments in PostgreSQL text format
// (temp-allocated; consumed by write_bind before the next temp reset).
// This minimal encoder is superseded by the type registry for exotic types;
// a nil arg (or nil Maybe) becomes SQL NULL.
@(private)
encode_text_params :: proc(args: []any) -> (params: [][]byte, err: Error) {
	params = make([][]byte, len(args), context.temp_allocator)
	for arg, i in args {
		if arg == nil {
			params[i] = nil
			continue
		}
		buf: [64]u8
		text: string
		switch v in arg {
		case string:
			text = v
		case cstring:
			text = string(v)
		case bool:
			text = "true" if v else "false"
		case i8:
			text = strconv.write_int(buf[:], i64(v), 10)
		case i16:
			text = strconv.write_int(buf[:], i64(v), 10)
		case i32:
			text = strconv.write_int(buf[:], i64(v), 10)
		case i64:
			text = strconv.write_int(buf[:], v, 10)
		case int:
			text = strconv.write_int(buf[:], i64(v), 10)
		case u8:
			text = strconv.write_uint(buf[:], u64(v), 10)
		case u16:
			text = strconv.write_uint(buf[:], u64(v), 10)
		case u32:
			text = strconv.write_uint(buf[:], u64(v), 10)
		case u64:
			text = strconv.write_uint(buf[:], v, 10)
		case uint:
			text = strconv.write_uint(buf[:], u64(v), 10)
		case f32:
			text = strconv.write_float(buf[:], f64(v), 'g', -1, 32)
		case f64:
			text = strconv.write_float(buf[:], v, 'g', -1, 64)
		case []byte:
			// bytea text format: \x followed by hex.
			out := make([]byte, 2 + len(v) * 2, context.temp_allocator)
			out[0] = '\\'
			out[1] = 'x'
			hex_encode_lower(out[2:], v)
			params[i] = out
			continue
		case:
			return nil, Driver_Error.Unsupported_Type
		}
		params[i] = transmute([]byte)strings.clone(text, context.temp_allocator) or_return
	}
	return params, nil
}

// Result arenas reserve small: a query result rarely needs the default
// multi-megabyte reservation, and the smaller mmap halves per-query arena
// cost (the arena still grows on demand).
RESULT_ARENA_RESERVE :: 64 * 1024

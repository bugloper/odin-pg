package pg

import "core:strconv"
import "core:strings"

// Stmt is a server-side prepared statement. Explicit prepare pins a
// statement for hot paths; conn_query/conn_exec with args also prepare
// transparently through the per-connection LRU cache.
Stmt :: struct {
	name:       string,
	sql:        string,
	param_oids: []Oid,
	fields:     []Field, // from Describe; format is what WE will request
	cached:     bool,    // owned by the conn's cache (don't stmt_close it twice)
}

// prepare parses and describes sql on the server. The returned Stmt is
// owned by the caller: release with stmt_close.
prepare :: proc(conn: ^Conn, sql: string, name := "") -> (stmt: ^Stmt, err: Error) {
	command_begin(conn) or_return

	stmt_name := name
	buf: [24]u8
	if stmt_name == "" {
		conn.stmt_counter += 1
		n := copy(buf[:], "pgstmt_")
		num := strconv.write_int(buf[n:], i64(conn.stmt_counter), 10)
		stmt_name = string(buf[:n + len(num)])
	}

	write_parse(&conn.writer, stmt_name, sql, nil)
	write_describe(&conn.writer, .Statement, stmt_name)
	write_sync(&conn.writer)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return nil, flush_err
	}

	param_oids := make([dynamic]Oid, context.temp_allocator)
	fields := make([dynamic]Field, context.temp_allocator)
	first_err: Error

	loop: for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			return nil, read_err
		}
		#partial switch kind {
		case .Parse_Complete, .No_Data, .Close_Complete:
		case .Parameter_Description:
			if !parse_parameter_description(body, &param_oids) {
				conn.status = .Broken
				first_err = Driver_Error.Protocol_Error
			}
		case .Row_Description:
			if !parse_row_description(body, &fields) {
				conn.status = .Broken
				first_err = Driver_Error.Protocol_Error
			}
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				return nil, Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			break loop
		case .Error_Response:
			if first_err == nil {
				first_err = conn_server_error(conn, body)
			}
		case .Notice_Response, .Parameter_Status:
			if kind == .Parameter_Status {
				_ = handle_parameter_status(conn, body)
			}
		case:
			conn.status = .Broken
			return nil, Driver_Error.Protocol_Error
		}
	}
	if first_err != nil {
		return nil, first_err
	}

	// Materialize the statement with conn-owned memory.
	stmt = new(Stmt, conn.allocator) or_return
	stmt.name = strings.clone(stmt_name, conn.allocator) or_return
	stmt.sql = strings.clone(sql, conn.allocator) or_return
	stmt.param_oids = make([]Oid, len(param_oids), conn.allocator) or_return
	copy(stmt.param_oids, param_oids[:])
	stmt.fields = make([]Field, len(fields), conn.allocator) or_return
	for f, i in fields {
		stmt.fields[i] = f
		stmt.fields[i].name, _ = strings.clone(f.name, conn.allocator)
		// Request binary wire format for types our decoder handles natively.
		stmt.fields[i].format = preferred_result_format(f.type_oid)
	}
	return stmt, nil
}

// preferred_result_format picks binary for OIDs with native binary decoders;
// everything else stays text (the universal fallback).
@(private)
preferred_result_format :: proc(oid: Oid) -> Format {
	switch oid {
	case BOOL, INT2, INT4, INT8, FLOAT4, FLOAT8, BYTEA, UUID, TIMESTAMP, TIMESTAMPTZ, DATE:
		return .Binary
	}
	return .Text
}

stmt_exec :: proc(conn: ^Conn, stmt: ^Stmt, args: ..any) -> (tag: Command_Tag, err: Error) {
	res := stmt_query(conn, stmt, ..args) or_return
	tag = res.tag
	tag.tag, _ = strings.clone(res.tag.tag, conn_error_allocator(conn))
	result_destroy(&res)
	return tag, nil
}

stmt_query :: proc(conn: ^Conn, stmt: ^Stmt, args: ..any) -> (res: Result, err: Error) {
	command_begin(conn) or_return

	params, encode_err := encode_text_params(args)
	if encode_err != nil {
		return {}, encode_err
	}

	result_formats := make([]Format, len(stmt.fields), context.temp_allocator)
	for f, i in stmt.fields {
		result_formats[i] = f.format
	}

	write_bind(&conn.writer, "", stmt.name, nil, params, result_formats)
	write_execute(&conn.writer, "")
	write_sync(&conn.writer)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return {}, flush_err
	}

	// No Describe in this path: rows decode against the statement's fields.
	return collect_result(conn, stmt.fields)
}

// stmt_close releases a caller-owned prepared statement. The protocol Close
// is buffered and rides along with the next command's flush (zero extra
// round trips); the server's CloseComplete is ignored wherever it arrives.
stmt_close :: proc(conn: ^Conn, stmt: ^Stmt) {
	if stmt == nil {
		return
	}
	if stmt.cached {
		return // the cache owns it
	}
	if conn.status == .Ok {
		write_close(&conn.writer, .Statement, stmt.name)
	}
	stmt_free(conn, stmt)
}

@(private)
stmt_free :: proc(conn: ^Conn, stmt: ^Stmt) {
	delete(stmt.name, conn.allocator)
	delete(stmt.sql, conn.allocator)
	delete(stmt.param_oids, conn.allocator)
	for f in stmt.fields {
		delete(f.name, conn.allocator)
	}
	delete(stmt.fields, conn.allocator)
	free(stmt, conn.allocator)
}

// --- Per-connection LRU statement cache ---

// cached_stmt returns a prepared statement for sql, preparing and caching
// on miss and evicting the least-recently-used entry (with a deferred
// protocol Close) when full. Returns nil when caching is disabled.
@(private)
cached_stmt :: proc(conn: ^Conn, sql: string) -> (stmt: ^Stmt, err: Error) {
	cache_size := conn.cfg.statement_cache_size
	if cache_size < 0 {
		return nil, nil
	}
	if cache_size == 0 {
		cache_size = DEFAULT_STATEMENT_CACHE_SIZE
	}

	if hit, found := conn.stmt_cache[sql]; found {
		// Move to the back of the recency order.
		for s, i in conn.stmt_lru {
			if s == hit {
				ordered_remove(&conn.stmt_lru, i)
				break
			}
		}
		append(&conn.stmt_lru, hit)
		return hit, nil
	}

	stmt = prepare(conn, sql) or_return
	stmt.cached = true
	if conn.stmt_cache == nil {
		conn.stmt_cache.allocator = conn.allocator
	}
	conn.stmt_cache[stmt.sql] = stmt
	if conn.stmt_lru.allocator.procedure == nil {
		conn.stmt_lru.allocator = conn.allocator
	}
	append(&conn.stmt_lru, stmt)

	if len(conn.stmt_lru) > cache_size {
		evicted := conn.stmt_lru[0]
		ordered_remove(&conn.stmt_lru, 0)
		delete_key(&conn.stmt_cache, evicted.sql)
		if conn.status == .Ok {
			write_close(&conn.writer, .Statement, evicted.name)
		}
		stmt_free(conn, evicted)
	}
	return stmt, nil
}

@(private)
stmt_cache_destroy :: proc(conn: ^Conn) {
	for s in conn.stmt_lru {
		stmt_free(conn, s)
	}
	delete(conn.stmt_lru)
	delete(conn.stmt_cache)
	conn.stmt_lru = nil
	conn.stmt_cache = nil
}

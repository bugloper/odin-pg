package pg

import "core:mem"
import "core:mem/virtual"
import "core:strings"

// Pipeline batches extended-protocol commands so many queries share one
// network round-trip. Usage:
//
//	p := pg.pipeline_begin(conn) or_return
//	defer pg.pipeline_close(&p)
//	pg.pipeline_query(&p, "SELECT $1::int8", 1) or_return
//	pg.pipeline_query(&p, "SELECT $1::int8", 2) or_return
//	items := pg.pipeline_sync(&p) or_return
//	defer pg.pipeline_items_destroy(items)
//
// Each pipeline_query/pipeline_exec queues Parse/Bind/Describe/Execute (or
// just Bind/Execute against a cached prepared statement). pipeline_sync
// writes Sync, flushes the whole batch in one send, and returns one
// Pipeline_Item per queued command.
//
// Error semantics follow the protocol: when a command fails, the server
// discards everything after it until Sync — the failed command's item
// carries the server error and every later item is .Pipeline_Aborted.
// After sync the pipeline is reusable for another batch.

Pipeline :: struct {
	conn:   ^Conn,
	active: bool,
	// One entry per queued Execute; fields is non-nil when Describe was
	// skipped (cached prepared statement).
	queued: [dynamic]Pipeline_Queued,
}

@(private)
Pipeline_Queued :: struct {
	fields: []Field,
}

// Pipeline_Item is the outcome of one queued command after pipeline_sync.
// On success, result owns its arena (freed by pipeline_items_destroy or an
// individual result_destroy). On failure, err is set and result is empty.
Pipeline_Item :: struct {
	result: Result,
	err:    Error,
}

// pipeline_begin opens a pipeline on conn. Only one pipeline may be open at
// a time; the regular query entry points return .In_Pipeline until close.
pipeline_begin :: proc(conn: ^Conn) -> (p: Pipeline, err: Error) {
	command_begin(conn) or_return
	conn.pipeline_open = true
	p = Pipeline {
		conn   = conn,
		active = true,
	}
	p.queued.allocator = conn.allocator
	return p, nil
}

// pipeline_query queues a parameterized query; its rows arrive with
// pipeline_sync.
pipeline_query :: proc(p: ^Pipeline, sql: string, args: ..any) -> Error {
	return pipeline_queue(p, sql, args)
}

// pipeline_exec queues a command executed for effect; the Command_Tag is on
// the Pipeline_Item's result.tag after sync.
pipeline_exec :: proc(p: ^Pipeline, sql: string, args: ..any) -> Error {
	return pipeline_queue(p, sql, args)
}

@(private)
pipeline_queue :: proc(p: ^Pipeline, sql: string, args: []any) -> Error {
	if !p.active || p.conn == nil {
		return Driver_Error.Closed
	}
	conn := p.conn
	switch conn.status {
	case .Ok:
	case .Closed:
		return Driver_Error.Closed
	case .Broken:
		return Driver_Error.Broken
	}

	params := encode_text_params(args) or_return

	// Reuse a cached prepared statement when one exists so Parse/Describe
	// are skipped. Never prepare on miss here: prepare() Syncs, which would
	// split the pipeline.
	if stmt := pipeline_cached_hit(conn, sql); stmt != nil {
		result_formats := make([]Format, len(stmt.fields), context.temp_allocator)
		for f, i in stmt.fields {
			result_formats[i] = f.format
		}
		write_bind(&conn.writer, "", stmt.name, nil, params, result_formats)
		write_execute(&conn.writer, "")
		append(&p.queued, Pipeline_Queued{fields = stmt.fields})
		return nil
	}

	write_parse(&conn.writer, "", sql, nil)
	write_bind(&conn.writer, "", "", nil, params, nil)
	write_describe(&conn.writer, .Portal, "")
	write_execute(&conn.writer, "")
	append(&p.queued, Pipeline_Queued{})
	return nil
}

// pipeline_cached_hit is a statement-cache lookup that never prepares.
@(private)
pipeline_cached_hit :: proc(conn: ^Conn, sql: string) -> ^Stmt {
	if conn.cfg.statement_cache_size < 0 {
		return nil
	}
	hit, found := conn.stmt_cache[sql]
	if !found {
		return nil
	}
	for s, i in conn.stmt_lru {
		if s == hit {
			ordered_remove(&conn.stmt_lru, i)
			break
		}
	}
	append(&conn.stmt_lru, hit)
	return hit
}

// pipeline_sync sends Sync, flushes the batch, and reads back one item per
// queued command, in order. The items slice and each successful Result are
// caller-owned: free with pipeline_items_destroy. The queue is cleared, so
// the pipeline can accept another batch until pipeline_close.
pipeline_sync :: proc(p: ^Pipeline, allocator := context.allocator) -> (items: []Pipeline_Item, err: Error) {
	if !p.active || p.conn == nil {
		return nil, Driver_Error.Closed
	}
	conn := p.conn
	switch conn.status {
	case .Ok:
	case .Closed:
		return nil, Driver_Error.Closed
	case .Broken:
		return nil, Driver_Error.Broken
	}

	defer clear(&p.queued)

	virtual.arena_free_all(&conn.err_arena)
	write_sync(&conn.writer)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return nil, flush_err
	}

	items = make([]Pipeline_Item, len(p.queued), allocator) or_return
	if collect_err := collect_pipeline(conn, p.queued[:], items); collect_err != nil {
		pipeline_items_destroy(items, allocator)
		return nil, collect_err
	}
	return items, nil
}

// pipeline_items_destroy frees every successful Result and the items slice.
pipeline_items_destroy :: proc(items: []Pipeline_Item, allocator := context.allocator) {
	for &it in items {
		if it.err == nil {
			result_destroy(&it.result)
		}
	}
	delete(items, allocator)
}

// pipeline_close ends the pipeline, syncing and discarding any still-queued
// commands. Safe to call more than once (defer-friendly).
pipeline_close :: proc(p: ^Pipeline) -> Error {
	if p == nil || !p.active {
		return nil
	}
	first_err: Error

	conn := p.conn
	if len(p.queued) > 0 && conn != nil && conn.status == .Ok {
		items, sync_err := pipeline_sync(p)
		first_err = sync_err
		if sync_err == nil {
			pipeline_items_destroy(items)
		}
	}

	delete(p.queued)
	p.queued = {}
	p.active = false
	if conn != nil {
		conn.pipeline_open = false
	}
	p.conn = nil
	return first_err
}

// collect_pipeline reads until ReadyForQuery, filling items[i] for the i-th
// queued command. Per-command server errors land on their item; commands
// the server skipped afterwards get .Pipeline_Aborted. Transport/protocol
// failures mark the conn Broken and fail the whole call (the caller frees
// items).
@(private)
collect_pipeline :: proc(conn: ^Conn, queued: []Pipeline_Queued, items: []Pipeline_Item) -> Error {
	item_i := 0
	building := false
	aborted := false
	res: Result
	fields: [dynamic]Field
	rows: [dynamic]Row
	arena_alloc: mem.Allocator
	spans := make([dynamic]Cell_Span, context.temp_allocator)

	// ensure_building lazily opens the arena for the current command and
	// seeds preset fields (cached-statement path, which skips Describe).
	ensure_building :: proc(
		conn: ^Conn,
		queued: []Pipeline_Queued,
		item_i: int,
		building: ^bool,
		res: ^Result,
		fields: ^[dynamic]Field,
		rows: ^[dynamic]Row,
		arena_alloc: ^mem.Allocator,
	) -> Error {
		if building^ {
			return nil
		}
		if arena_err := virtual.arena_init_growing(&res.arena, RESULT_ARENA_RESERVE); arena_err != nil {
			conn.status = .Broken
			return arena_err
		}
		arena_alloc^ = virtual.arena_allocator(&res.arena)
		fields^ = make([dynamic]Field, arena_alloc^)
		rows^ = make([dynamic]Row, arena_alloc^)
		if item_i < len(queued) {
			for f in queued[item_i].fields {
				field := f
				field.name, _ = strings.clone(f.name, arena_alloc^)
				append(fields, field)
			}
		}
		building^ = true
		return nil
	}

	for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			if building {
				result_destroy(&res)
			}
			return read_err
		}

		#partial switch kind {
		case .Parse_Complete, .Bind_Complete, .Close_Complete, .Parameter_Description, .Portal_Suspended:
		// Inter-command protocol acknowledgements.
		case .No_Data:
			if aborted {
				continue
			}
			ensure_building(conn, queued, item_i, &building, &res, &fields, &rows, &arena_alloc) or_return
		case .Row_Description:
			if aborted {
				continue
			}
			ensure_building(conn, queued, item_i, &building, &res, &fields, &rows, &arena_alloc) or_return
			clear(&fields)
			clear(&rows)
			if !parse_row_description(body, &fields) {
				conn.status = .Broken
				result_destroy(&res)
				return Driver_Error.Protocol_Error
			}
			for &f in fields {
				f.name, _ = strings.clone(f.name, arena_alloc)
			}
		case .Data_Row:
			if aborted {
				continue
			}
			ensure_building(conn, queued, item_i, &building, &res, &fields, &rows, &arena_alloc) or_return
			if !parse_data_row(body, &spans) {
				conn.status = .Broken
				result_destroy(&res)
				return Driver_Error.Protocol_Error
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
		case .Command_Complete, .Empty_Query_Response:
			if aborted {
				continue
			}
			ensure_building(conn, queued, item_i, &building, &res, &fields, &rows, &arena_alloc) or_return
			if kind == .Command_Complete {
				if tag, ok := parse_command_complete(body); ok {
					res.tag.tag, _ = strings.clone(tag, arena_alloc)
					res.tag.rows_affected = tag_rows_affected(tag)
				}
			}
			res.fields = fields[:]
			res.rows = rows[:]
			if item_i < len(items) {
				items[item_i].result = res
				item_i += 1
			} else {
				result_destroy(&res)
			}
			res = {}
			building = false
		case .Error_Response:
			// The failed command's item gets the error; the server now
			// discards until Sync, so later commands never respond.
			se := conn_server_error(conn, body)
			if building {
				result_destroy(&res)
				res = {}
				building = false
			}
			if !aborted && item_i < len(items) {
				items[item_i].err = se
				item_i += 1
			}
			aborted = true
		case .Notice_Response:
		case .Parameter_Status:
			if ps_err := handle_parameter_status(conn, body); ps_err != nil {
				conn.status = .Broken
				return ps_err
			}
		case .Notification_Response:
			if n_err := buffer_notification(conn, body); n_err != nil {
				conn.status = .Broken
				return n_err
			}
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				if building {
					result_destroy(&res)
				}
				return Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			if building {
				// A command's responses were cut short without an error:
				// protocol violation.
				conn.status = .Broken
				result_destroy(&res)
				return Driver_Error.Protocol_Error
			}
			for item_i < len(items) {
				items[item_i].err =
					Driver_Error.Pipeline_Aborted if aborted else Driver_Error.Protocol_Error
				item_i += 1
			}
			return nil
		case:
			conn.status = .Broken
			if building {
				result_destroy(&res)
			}
			return Driver_Error.Protocol_Error
		}
	}
}

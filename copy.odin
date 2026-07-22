package pg

// COPY sub-protocol: the bulk data path. copy_in streams data INTO the
// server ("COPY t FROM STDIN"); copy_out streams data OUT ("COPY t TO
// STDOUT"). Both use the simple-query message flow with CopyData frames.

import "core:strings"

// Flush the writer once this much COPY data is buffered.
@(private)
COPY_FLUSH_THRESHOLD :: 32 * 1024

Copy_In :: struct {
	conn:   ^Conn,
	active: bool,
	format: Format, // overall format the server announced
}

// copy_in_begin starts "COPY … FROM STDIN [WITH (FORMAT …)]". Follow with
// any number of copy_in_write calls and exactly one copy_in_finish or
// copy_in_abort.
copy_in_begin :: proc(conn: ^Conn, sql: string) -> (c: Copy_In, err: Error) {
	command_begin(conn) or_return
	write_query(&conn.writer, sql)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return {}, flush_err
	}

	col_formats := make([dynamic]Format, context.temp_allocator)
	for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			return {}, read_err
		}
		#partial switch kind {
		case .Copy_In_Response:
			overall, ok := parse_copy_response(body, &col_formats)
			if !ok {
				conn.status = .Broken
				return {}, Driver_Error.Protocol_Error
			}
			return Copy_In{conn = conn, active = true, format = overall}, nil
		case .Error_Response:
			server_err := conn_server_error(conn, body)
			if drain_err := drain_until_ready(conn); drain_err != nil && conn.status == .Broken {
				return {}, drain_err
			}
			return {}, server_err
		case .Notice_Response:
		case .Parameter_Status:
			handle_parameter_status(conn, body) or_return
		case:
			// Not a COPY FROM STDIN statement after all.
			conn.status = .Broken
			return {}, Driver_Error.Protocol_Error
		}
	}
}

// copy_in_write queues one chunk (rows in text/csv format, or binary
// payload); large batches flush automatically.
copy_in_write :: proc(c: ^Copy_In, data: []byte) -> Error {
	if !c.active {
		return Driver_Error.Copy_Aborted
	}
	write_copy_data(&c.conn.writer, data)
	if len(c.conn.writer.buf) >= COPY_FLUSH_THRESHOLD {
		if err := flush(&c.conn.writer); err != nil {
			c.conn.status = .Broken
			c.active = false
			return err
		}
	}
	return nil
}

// copy_in_finish sends CopyDone and waits for the server's verdict.
copy_in_finish :: proc(c: ^Copy_In) -> (tag: Command_Tag, err: Error) {
	if !c.active {
		return {}, Driver_Error.Copy_Aborted
	}
	c.active = false
	conn := c.conn
	write_copy_done(&conn.writer)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return {}, flush_err
	}
	return copy_tail(conn)
}

// copy_in_abort cancels the COPY with CopyFail; the server answers with an
// ErrorResponse (57014-class), which is returned so callers can confirm the
// abort. The connection remains usable.
copy_in_abort :: proc(c: ^Copy_In, reason := "aborted") -> Error {
	if !c.active {
		return nil
	}
	c.active = false
	conn := c.conn
	write_copy_fail(&conn.writer, reason)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return flush_err
	}
	_, err := copy_tail(conn)
	return err
}

// copy_tail consumes messages after CopyDone/CopyFail until ReadyForQuery.
@(private = "file")
copy_tail :: proc(conn: ^Conn) -> (tag: Command_Tag, err: Error) {
	first_err: Error
	for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			return {}, read_err
		}
		#partial switch kind {
		case .Command_Complete:
			if t, ok := parse_command_complete(body); ok {
				tag.tag, _ = strings.clone(t, conn_error_allocator(conn))
				tag.rows_affected = tag_rows_affected(t)
			}
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				return {}, Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			return tag, first_err
		case .Error_Response:
			if first_err == nil {
				first_err = conn_server_error(conn, body)
			}
		case .Notice_Response:
		case .Parameter_Status:
			_ = handle_parameter_status(conn, body)
		case .Notification_Response:
			_ = buffer_notification(conn, body)
		case:
			conn.status = .Broken
			return {}, Driver_Error.Protocol_Error
		}
	}
}

// Copy_Sink receives each CopyData chunk during copy_out. The chunk borrows
// the connection's read buffer: copy what you keep.
Copy_Sink :: #type proc(chunk: []byte, user: rawptr) -> Error

// copy_out runs "COPY … TO STDOUT" and streams every data chunk to sink.
// If the sink returns an error, remaining chunks are drained and discarded,
// and that error is returned.
copy_out :: proc(conn: ^Conn, sql: string, sink: Copy_Sink, user: rawptr = nil) -> (tag: Command_Tag, err: Error) {
	command_begin(conn) or_return
	write_query(&conn.writer, sql)
	if flush_err := flush(&conn.writer); flush_err != nil {
		conn.status = .Broken
		return {}, flush_err
	}

	col_formats := make([dynamic]Format, context.temp_allocator)
	sink_err: Error
	first_err: Error
	for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			conn.status = .Broken
			return {}, read_err
		}
		#partial switch kind {
		case .Copy_Out_Response:
			if _, ok := parse_copy_response(body, &col_formats); !ok {
				conn.status = .Broken
				return {}, Driver_Error.Protocol_Error
			}
		case .Copy_Data:
			if sink_err == nil {
				sink_err = sink(body, user)
			}
		case .Copy_Done:
		case .Command_Complete:
			if t, ok := parse_command_complete(body); ok {
				tag.tag, _ = strings.clone(t, conn_error_allocator(conn))
				tag.rows_affected = tag_rows_affected(t)
			}
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				return {}, Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			if first_err != nil {
				return {}, first_err
			}
			return tag, sink_err
		case .Error_Response:
			if first_err == nil {
				first_err = conn_server_error(conn, body)
			}
		case .Notice_Response:
		case .Parameter_Status:
			_ = handle_parameter_status(conn, body)
		case .Notification_Response:
			_ = buffer_notification(conn, body)
		case:
			conn.status = .Broken
			return {}, Driver_Error.Protocol_Error
		}
	}
}

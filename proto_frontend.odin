package pg

// Frontend message builders. Each appends one complete message to the
// writer's buffer; nothing is sent until flush. Grouping several builders
// before one flush is how extended-query batching works.

// write_startup appends a StartupMessage. params are (name, value) pairs,
// e.g. {"user", "alice"}, {"database", "app"}, {"client_encoding", "UTF8"}.
write_startup :: proc(w: ^Msg_Writer, params: [][2]string) {
	off := begin_untyped_msg(w)
	put_u32(w, PROTOCOL_VERSION)
	for kv in params {
		put_cstring(w, kv[0])
		put_cstring(w, kv[1])
	}
	put_u8(w, 0)
	end_msg(w, off)
}

write_ssl_request :: proc(w: ^Msg_Writer) {
	off := begin_untyped_msg(w)
	put_u32(w, SSL_REQUEST_CODE)
	end_msg(w, off)
}

// write_cancel_request takes the secret key as bytes: 4 in protocol 3.0,
// up to 32 in 3.2 — the wire format is the same either way.
write_cancel_request :: proc(w: ^Msg_Writer, backend_pid: i32, secret_key: []byte) {
	off := begin_untyped_msg(w)
	put_u32(w, CANCEL_REQUEST_CODE)
	put_i32(w, backend_pid)
	put_bytes(w, secret_key)
	end_msg(w, off)
}

write_query :: proc(w: ^Msg_Writer, sql: string) {
	off := begin_msg(w, .Query)
	put_cstring(w, sql)
	end_msg(w, off)
}

// write_parse declares parameter OIDs; Oid(0) lets the server infer.
write_parse :: proc(w: ^Msg_Writer, stmt_name, sql: string, param_oids: []Oid) {
	off := begin_msg(w, .Parse)
	put_cstring(w, stmt_name)
	put_cstring(w, sql)
	put_i16(w, i16(len(param_oids)))
	for oid in param_oids {
		put_u32(w, u32(oid))
	}
	end_msg(w, off)
}

// write_bind binds already-encoded parameter values into a portal. A nil
// slice in params encodes SQL NULL (wire length -1). param_formats and
// result_formats follow the protocol's shorthand: empty means "all text",
// a single element means "all columns use this format".
write_bind :: proc(
	w: ^Msg_Writer,
	portal, stmt_name: string,
	param_formats: []Format,
	params: [][]byte,
	result_formats: []Format,
) {
	off := begin_msg(w, .Bind)
	put_cstring(w, portal)
	put_cstring(w, stmt_name)
	put_i16(w, i16(len(param_formats)))
	for f in param_formats {
		put_i16(w, i16(f))
	}
	put_i16(w, i16(len(params)))
	for p in params {
		if p == nil {
			put_i32(w, -1)
		} else {
			put_i32(w, i32(len(p)))
			put_bytes(w, p)
		}
	}
	put_i16(w, i16(len(result_formats)))
	for f in result_formats {
		put_i16(w, i16(f))
	}
	end_msg(w, off)
}

Describe_Kind :: enum u8 {
	Statement = 'S',
	Portal    = 'P',
}

write_describe :: proc(w: ^Msg_Writer, kind: Describe_Kind, name: string) {
	off := begin_msg(w, .Describe)
	put_u8(w, u8(kind))
	put_cstring(w, name)
	end_msg(w, off)
}

// write_execute runs a bound portal. max_rows = 0 means "all rows".
write_execute :: proc(w: ^Msg_Writer, portal: string, max_rows: i32 = 0) {
	off := begin_msg(w, .Execute)
	put_cstring(w, portal)
	put_i32(w, max_rows)
	end_msg(w, off)
}

write_sync :: proc(w: ^Msg_Writer) {
	off := begin_msg(w, .Sync)
	end_msg(w, off)
}

write_flush_msg :: proc(w: ^Msg_Writer) {
	off := begin_msg(w, .Flush)
	end_msg(w, off)
}

write_close :: proc(w: ^Msg_Writer, kind: Describe_Kind, name: string) {
	off := begin_msg(w, .Close)
	put_u8(w, u8(kind))
	put_cstring(w, name)
	end_msg(w, off)
}

// write_password carries cleartext and md5 responses (both NUL-terminated).
write_password :: proc(w: ^Msg_Writer, password: string) {
	off := begin_msg(w, .Password)
	put_cstring(w, password)
	end_msg(w, off)
}

write_sasl_initial_response :: proc(w: ^Msg_Writer, mechanism: string, data: []byte) {
	off := begin_msg(w, .Password)
	put_cstring(w, mechanism)
	put_i32(w, i32(len(data)))
	put_bytes(w, data)
	end_msg(w, off)
}

write_sasl_response :: proc(w: ^Msg_Writer, data: []byte) {
	off := begin_msg(w, .Password)
	put_bytes(w, data)
	end_msg(w, off)
}

write_copy_data :: proc(w: ^Msg_Writer, data: []byte) {
	off := begin_msg(w, .Copy_Data)
	put_bytes(w, data)
	end_msg(w, off)
}

write_copy_done :: proc(w: ^Msg_Writer) {
	off := begin_msg(w, .Copy_Done)
	end_msg(w, off)
}

write_copy_fail :: proc(w: ^Msg_Writer, reason: string) {
	off := begin_msg(w, .Copy_Fail)
	put_cstring(w, reason)
	end_msg(w, off)
}

write_terminate :: proc(w: ^Msg_Writer) {
	off := begin_msg(w, .Terminate)
	end_msg(w, off)
}

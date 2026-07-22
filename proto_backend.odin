package pg

// Backend message parsers. All operate on the body slice returned by
// read_message; every returned string/[]byte borrows that buffer and is
// invalidated by the next read_message call. Callers copy what they keep.
// All parsing is bounds-checked: ok = false means a malformed message
// (callers surface .Protocol_Error), never a panic.

// Field describes one result column, from RowDescription.
// name borrows the reader buffer until copied into a Result.
Field :: struct {
	name:      string,
	table_oid: Oid,
	column:    i16,
	type_oid:  Oid,
	type_size: i16,
	type_mod:  i32,
	format:    Format,
}

// Cell_Span locates one column's bytes inside a DataRow body.
// len == -1 means SQL NULL.
Cell_Span :: struct {
	off: i32,
	len: i32,
}

// parse_auth splits an Authentication ('R') message into its request code
// and the code-specific payload (SASL mechanism list, MD5 salt, SASL
// challenge bytes, …).
parse_auth :: proc(body: []byte) -> (code: Auth_Code, payload: []byte, ok: bool) {
	pos := 0
	raw := cursor_u32(body, &pos) or_return
	return Auth_Code(raw), body[pos:], true
}

// parse_backend_key_data returns the cancellation credentials. The secret
// key is kept as raw bytes: 4 in protocol 3.0, longer under 3.2.
parse_backend_key_data :: proc(body: []byte) -> (pid: i32, secret_key: []byte, ok: bool) {
	pos := 0
	pid = cursor_i32(body, &pos) or_return
	return pid, body[pos:], true
}

parse_ready_for_query :: proc(body: []byte) -> (status: Txn_Status, ok: bool) {
	if len(body) != 1 {
		return nil, false
	}
	switch Txn_Status(body[0]) {
	case .Idle, .In_Txn, .Failed_Txn:
		return Txn_Status(body[0]), true
	}
	return nil, false
}

parse_parameter_status :: proc(body: []byte) -> (name, value: string, ok: bool) {
	pos := 0
	name = cursor_cstr(body, &pos) or_return
	value = cursor_cstr(body, &pos) or_return
	return name, value, true
}

// parse_row_description fills the caller's reusable field array.
parse_row_description :: proc(body: []byte, fields: ^[dynamic]Field) -> (ok: bool) {
	pos := 0
	count := cursor_i16(body, &pos) or_return
	if count < 0 {
		return false
	}
	clear(fields)
	for _ in 0 ..< count {
		f: Field
		f.name = cursor_cstr(body, &pos) or_return
		f.table_oid = Oid(cursor_u32(body, &pos) or_return)
		f.column = cursor_i16(body, &pos) or_return
		f.type_oid = Oid(cursor_u32(body, &pos) or_return)
		f.type_size = cursor_i16(body, &pos) or_return
		f.type_mod = cursor_i32(body, &pos) or_return
		f.format = Format(cursor_i16(body, &pos) or_return)
		append(fields, f)
	}
	return true
}

// parse_data_row fills the caller's reusable span table with each column's
// location in body; cell bytes are not copied (lazy decode).
parse_data_row :: proc(body: []byte, spans: ^[dynamic]Cell_Span) -> (ok: bool) {
	pos := 0
	count := cursor_i16(body, &pos) or_return
	if count < 0 {
		return false
	}
	clear(spans)
	for _ in 0 ..< count {
		length := cursor_i32(body, &pos) or_return
		if length == -1 {
			append(spans, Cell_Span{off = i32(pos), len = -1})
			continue
		}
		if length < 0 || pos + int(length) > len(body) {
			return false
		}
		append(spans, Cell_Span{off = i32(pos), len = length})
		pos += int(length)
	}
	return true
}

parse_command_complete :: proc(body: []byte) -> (tag: string, ok: bool) {
	pos := 0
	tag = cursor_cstr(body, &pos) or_return
	return tag, true
}

// Error_Fields carries a decoded ErrorResponse/NoticeResponse with all
// strings borrowing the message body.
Error_Fields :: struct {
	severity:       string, // V (non-localized) preferred, falling back to S
	code:           string,
	message:        string,
	detail:         string,
	hint:           string,
	position:       string,
	internal_pos:   string,
	internal_query: string,
	where_ctx:      string,
	schema:         string,
	table:          string,
	column:         string,
	data_type:      string,
	constraint:     string,
	file:           string,
	line:           string,
	routine:        string,
}

// parse_error_fields decodes the field list shared by ErrorResponse ('E')
// and NoticeResponse ('N'): repeated (field-type byte, cstring) pairs
// terminated by a zero byte. Unknown field types are skipped, as the
// protocol requires.
parse_error_fields :: proc(body: []byte) -> (fields: Error_Fields, ok: bool) {
	pos := 0
	localized_severity := ""
	for {
		kind := cursor_u8(body, &pos) or_return
		if kind == 0 {
			break
		}
		value := cursor_cstr(body, &pos) or_return
		switch kind {
		case 'S':
			localized_severity = value
		case 'V':
			fields.severity = value
		case 'C':
			fields.code = value
		case 'M':
			fields.message = value
		case 'D':
			fields.detail = value
		case 'H':
			fields.hint = value
		case 'P':
			fields.position = value
		case 'p':
			fields.internal_pos = value
		case 'q':
			fields.internal_query = value
		case 'W':
			fields.where_ctx = value
		case 's':
			fields.schema = value
		case 't':
			fields.table = value
		case 'c':
			fields.column = value
		case 'd':
			fields.data_type = value
		case 'n':
			fields.constraint = value
		case 'F':
			fields.file = value
		case 'L':
			fields.line = value
		case 'R':
			fields.routine = value
		}
	}
	if fields.severity == "" {
		fields.severity = localized_severity
	}
	return fields, true
}

parse_notification :: proc(body: []byte) -> (pid: i32, channel, payload: string, ok: bool) {
	pos := 0
	pid = cursor_i32(body, &pos) or_return
	channel = cursor_cstr(body, &pos) or_return
	payload = cursor_cstr(body, &pos) or_return
	return pid, channel, payload, true
}

// parse_copy_response decodes CopyInResponse/CopyOutResponse/CopyBothResponse:
// the overall format plus per-column format codes.
parse_copy_response :: proc(
	body: []byte,
	col_formats: ^[dynamic]Format,
) -> (
	overall: Format,
	ok: bool,
) {
	pos := 0
	raw := cursor_u8(body, &pos) or_return
	count := cursor_i16(body, &pos) or_return
	if count < 0 {
		return nil, false
	}
	clear(col_formats)
	for _ in 0 ..< count {
		f := cursor_i16(body, &pos) or_return
		append(col_formats, Format(f))
	}
	return Format(i16(raw)), true
}

// parse_parameter_description fills the OIDs of a described statement's
// parameters.
parse_parameter_description :: proc(body: []byte, oids: ^[dynamic]Oid) -> (ok: bool) {
	pos := 0
	count := cursor_i16(body, &pos) or_return
	if count < 0 {
		return false
	}
	clear(oids)
	for _ in 0 ..< count {
		oid := cursor_u32(body, &pos) or_return
		append(oids, Oid(oid))
	}
	return true
}

// parse_negotiate_protocol_version decodes the server's downgrade offer:
// the newest minor protocol version it supports and the startup options it
// did not recognize.
parse_negotiate_protocol_version :: proc(
	body: []byte,
) -> (
	minor: i32,
	unsupported_options: int,
	ok: bool,
) {
	pos := 0
	minor = cursor_i32(body, &pos) or_return
	count := cursor_i32(body, &pos) or_return
	if count < 0 {
		return 0, 0, false
	}
	for _ in 0 ..< count {
		_ = cursor_cstr(body, &pos) or_return
	}
	return minor, int(count), true
}

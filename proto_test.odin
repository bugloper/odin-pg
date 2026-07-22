package pg

import "core:encoding/endian"
import "core:testing"
import "core:time"

// --- Mock stream ---
//
// Feeds a scripted byte sequence to the reader in chunks of at most
// `chunk` bytes, exercising short reads and messages split across reads.
// Captures everything written for round-trip assertions.

Mock_Stream :: struct {
	input:   []byte,
	pos:     int,
	chunk:   int, // max bytes per read; 0 means "everything available"
	written: [dynamic]u8,
}

mock_stream :: proc(ms: ^Mock_Stream) -> Stream {
	return Stream{data = ms, impl = &_mock_vtable}
}

@(private = "file")
_mock_vtable := Stream_VTable {
	read = proc(data: rawptr, buf: []byte) -> (n: int, err: Error) {
		ms := (^Mock_Stream)(data)
		if ms.pos >= len(ms.input) {
			return 0, nil // clean EOF
		}
		n = len(buf)
		if remaining := len(ms.input) - ms.pos; n > remaining {
			n = remaining
		}
		if ms.chunk > 0 && n > ms.chunk {
			n = ms.chunk
		}
		copy(buf, ms.input[ms.pos:ms.pos + n])
		ms.pos += n
		return n, nil
	},
	write = proc(data: rawptr, buf: []byte) -> Error {
		ms := (^Mock_Stream)(data)
		append(&ms.written, ..buf)
		return nil
	},
	set_deadline = proc(data: rawptr, read_timeout, write_timeout: time.Duration) -> Error {
		return nil
	},
	close = proc(data: rawptr) {},
}

// --- Fixture helpers ---

@(private = "file")
frame :: proc(kind: u8, body: []byte, allocator := context.allocator) -> []byte {
	out := make([dynamic]u8, 0, 5 + len(body), allocator)
	append(&out, kind)
	length: [4]u8
	endian.put_i32(length[:], .Big, i32(4 + len(body)))
	append(&out, ..length[:])
	append(&out, ..body)
	return out[:]
}

// --- Reader framing tests ---

@(test)
test_read_message_whole_and_split :: proc(t: ^testing.T) {
	// ReadyForQuery('Z') with body "I", followed by CommandComplete.
	input := make([dynamic]u8, context.temp_allocator)
	append(&input, ..frame('Z', {'I'}, context.temp_allocator))
	append(&input, ..frame('C', {'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}, context.temp_allocator))

	for chunk in ([]int{0, 1, 2, 3}) {
		ms := Mock_Stream {
			input = input[:],
			chunk = chunk,
		}
		defer delete(ms.written)
		r: Msg_Reader
		msg_reader_init(&r, mock_stream(&ms))
		defer msg_reader_destroy(&r)

		kind, body, err := read_message(&r)
		testing.expect_value(t, err, nil)
		testing.expect_value(t, kind, Backend_Msg.Ready_For_Query)
		status, ok := parse_ready_for_query(body)
		testing.expect(t, ok)
		testing.expect_value(t, status, Txn_Status.Idle)

		kind, body, err = read_message(&r)
		testing.expect_value(t, err, nil)
		testing.expect_value(t, kind, Backend_Msg.Command_Complete)
		tag, tag_ok := parse_command_complete(body)
		testing.expect(t, tag_ok)
		testing.expect_value(t, tag, "SELECT 1")
	}
}

@(test)
test_read_message_empty_body :: proc(t: ^testing.T) {
	ms := Mock_Stream {
		input = frame('1', {}, context.temp_allocator), // ParseComplete
	}
	defer delete(ms.written)
	r: Msg_Reader
	msg_reader_init(&r, mock_stream(&ms))
	defer msg_reader_destroy(&r)

	kind, body, err := read_message(&r)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, kind, Backend_Msg.Parse_Complete)
	testing.expect_value(t, len(body), 0)
}

@(test)
test_read_message_rejects_bad_lengths :: proc(t: ^testing.T) {
	// Length < 4 is invalid (it counts itself).
	bad := []u8{'Z', 0, 0, 0, 3}
	ms := Mock_Stream{input = bad}
	defer delete(ms.written)
	r: Msg_Reader
	msg_reader_init(&r, mock_stream(&ms))
	defer msg_reader_destroy(&r)
	_, _, err := read_message(&r)
	testing.expect_value(t, err, Error(Driver_Error.Protocol_Error))

	// Oversized length is rejected before any allocation.
	huge: [5]u8
	huge[0] = 'D'
	endian.put_u32(huge[1:], .Big, u32(MAX_MESSAGE_SIZE) + 5)
	ms2 := Mock_Stream{input = huge[:]}
	defer delete(ms2.written)
	r2: Msg_Reader
	msg_reader_init(&r2, mock_stream(&ms2))
	defer msg_reader_destroy(&r2)
	_, _, err2 := read_message(&r2)
	testing.expect_value(t, err2, Error(Driver_Error.Message_Too_Large))
}

@(test)
test_read_message_truncated :: proc(t: ^testing.T) {
	// Header promises 8 body bytes; stream ends after 3.
	input := []u8{'D', 0, 0, 0, 12, 1, 2, 3}
	ms := Mock_Stream{input = input}
	defer delete(ms.written)
	r: Msg_Reader
	msg_reader_init(&r, mock_stream(&ms))
	defer msg_reader_destroy(&r)
	_, _, err := read_message(&r)
	testing.expect_value(t, err, Error(Driver_Error.Broken))
}

@(test)
test_read_ssl_response :: proc(t: ^testing.T) {
	ms := Mock_Stream{input = {'S', 'N', 'E'}}
	defer delete(ms.written)
	r: Msg_Reader
	msg_reader_init(&r, mock_stream(&ms))
	defer msg_reader_destroy(&r)

	willing, err := read_ssl_response(&r)
	testing.expect_value(t, err, nil)
	testing.expect(t, willing)

	willing, err = read_ssl_response(&r)
	testing.expect_value(t, err, nil)
	testing.expect(t, !willing)

	_, err = read_ssl_response(&r)
	testing.expect_value(t, err, Error(Driver_Error.Protocol_Error))
}

// --- Backend parser tests ---

@(test)
test_parse_auth :: proc(t: ^testing.T) {
	body := []u8{0, 0, 0, 10, 'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0, 0}
	code, payload, ok := parse_auth(body)
	testing.expect(t, ok)
	testing.expect_value(t, code, Auth_Code.SASL)
	testing.expect_value(t, len(payload), 15)

	_, _, ok = parse_auth([]u8{0, 0})
	testing.expect(t, !ok)
}

@(test)
test_parse_backend_key_data :: proc(t: ^testing.T) {
	body := []u8{0, 0, 0x30, 0x39, 0xDE, 0xAD, 0xBE, 0xEF}
	pid, key, ok := parse_backend_key_data(body)
	testing.expect(t, ok)
	testing.expect_value(t, pid, i32(12345))
	testing.expect_value(t, len(key), 4)
	testing.expect_value(t, key[0], u8(0xDE))
}

@(test)
test_parse_parameter_status :: proc(t: ^testing.T) {
	body := []u8{'T', 'i', 'm', 'e', 'Z', 'o', 'n', 'e', 0, 'U', 'T', 'C', 0}
	name, value, ok := parse_parameter_status(body)
	testing.expect(t, ok)
	testing.expect_value(t, name, "TimeZone")
	testing.expect_value(t, value, "UTC")

	// Missing terminator on the value.
	_, _, ok = parse_parameter_status(body[:len(body) - 1])
	testing.expect(t, !ok)
}

@(test)
test_parse_row_description :: proc(t: ^testing.T) {
	body := make([dynamic]u8, context.temp_allocator)
	two: [2]u8
	four: [4]u8
	endian.put_i16(two[:], .Big, 1)
	append(&body, ..two[:])
	append(&body, 'i', 'd', 0)
	endian.put_u32(four[:], .Big, 0) // table oid
	append(&body, ..four[:])
	endian.put_i16(two[:], .Big, 0) // column attnum
	append(&body, ..two[:])
	endian.put_u32(four[:], .Big, u32(INT8)) // type oid
	append(&body, ..four[:])
	endian.put_i16(two[:], .Big, 8) // type size
	append(&body, ..two[:])
	endian.put_i32(four[:], .Big, -1) // type mod
	append(&body, ..four[:])
	endian.put_i16(two[:], .Big, 1) // format = binary
	append(&body, ..two[:])

	fields := make([dynamic]Field, context.temp_allocator)
	ok := parse_row_description(body[:], &fields)
	testing.expect(t, ok)
	testing.expect_value(t, len(fields), 1)
	testing.expect_value(t, fields[0].name, "id")
	testing.expect_value(t, fields[0].type_oid, INT8)
	testing.expect_value(t, fields[0].format, Format.Binary)

	// Truncated: promises 1 field, body ends early.
	ok = parse_row_description(body[:8], &fields)
	testing.expect(t, !ok)
}

@(test)
test_parse_data_row :: proc(t: ^testing.T) {
	body := make([dynamic]u8, context.temp_allocator)
	two: [2]u8
	four: [4]u8
	endian.put_i16(two[:], .Big, 3)
	append(&body, ..two[:])
	endian.put_i32(four[:], .Big, 2) // col 0: 2 bytes
	append(&body, ..four[:])
	append(&body, '4', '2')
	endian.put_i32(four[:], .Big, -1) // col 1: NULL
	append(&body, ..four[:])
	endian.put_i32(four[:], .Big, 0) // col 2: empty string
	append(&body, ..four[:])

	spans := make([dynamic]Cell_Span, context.temp_allocator)
	ok := parse_data_row(body[:], &spans)
	testing.expect(t, ok)
	testing.expect_value(t, len(spans), 3)
	testing.expect_value(t, string(body[spans[0].off:spans[0].off + spans[0].len]), "42")
	testing.expect_value(t, spans[1].len, i32(-1))
	testing.expect_value(t, spans[2].len, i32(0))

	// Column length pointing past the end of the body.
	endian.put_i32(four[:], .Big, 99)
	copy(body[2:6], four[:])
	ok = parse_data_row(body[:], &spans)
	testing.expect(t, !ok)
}

@(test)
test_parse_error_fields :: proc(t: ^testing.T) {
	body := make([dynamic]u8, context.temp_allocator)
	append_field :: proc(b: ^[dynamic]u8, kind: u8, value: string) {
		append(b, kind)
		append(b, value)
		append(b, 0)
	}
	append_field(&body, 'S', "FEHLER") // localized
	append_field(&body, 'V', "ERROR")
	append_field(&body, 'C', "23505")
	append_field(&body, 'M', "duplicate key")
	append_field(&body, 'n', "users_pkey")
	append_field(&body, 'X', "unknown field is skipped")
	append(&body, 0)

	fields, ok := parse_error_fields(body[:])
	testing.expect(t, ok)
	testing.expect_value(t, fields.severity, "ERROR")
	testing.expect_value(t, fields.code, "23505")
	testing.expect_value(t, fields.message, "duplicate key")
	testing.expect_value(t, fields.constraint, "users_pkey")

	// Missing zero terminator.
	_, ok = parse_error_fields(body[:len(body) - 1])
	testing.expect(t, !ok)
}

@(test)
test_parse_notification :: proc(t: ^testing.T) {
	body := make([dynamic]u8, context.temp_allocator)
	four: [4]u8
	endian.put_i32(four[:], .Big, 4242)
	append(&body, ..four[:])
	append(&body, "jobs")
	append(&body, 0)
	append(&body, "job_1")
	append(&body, 0)

	pid, channel, payload, ok := parse_notification(body[:])
	testing.expect(t, ok)
	testing.expect_value(t, pid, i32(4242))
	testing.expect_value(t, channel, "jobs")
	testing.expect_value(t, payload, "job_1")
}

// --- Frontend builder round-trips ---

@(private = "file")
writer_for :: proc(ms: ^Mock_Stream) -> Msg_Writer {
	w: Msg_Writer
	msg_writer_init(&w, mock_stream(ms))
	return w
}

@(test)
test_write_startup_roundtrip :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	write_startup(&w, {{"user", "alice"}, {"database", "app"}})
	testing.expect_value(t, flush(&w), nil)

	out := ms.written[:]
	length, _ := endian.get_i32(out[0:4], .Big)
	testing.expect_value(t, int(length), len(out))
	version, _ := endian.get_u32(out[4:8], .Big)
	testing.expect_value(t, version, PROTOCOL_VERSION)
	testing.expect_value(t, string(out[8:len(out) - 1]), "user\x00alice\x00database\x00app\x00")
	testing.expect_value(t, out[len(out) - 1], u8(0))
}

@(test)
test_write_query_roundtrip :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	write_query(&w, "SELECT 1")
	testing.expect_value(t, flush(&w), nil)

	out := ms.written[:]
	testing.expect_value(t, out[0], u8(Frontend_Msg.Query))
	length, _ := endian.get_i32(out[1:5], .Big)
	testing.expect_value(t, int(length), len(out) - 1)
	testing.expect_value(t, string(out[5:]), "SELECT 1\x00")
}

@(test)
test_write_extended_batch :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	write_parse(&w, "", "SELECT $1::int8", {INT8})
	write_bind(&w, "", "", {.Binary}, {{0, 0, 0, 0, 0, 0, 0, 42}}, {.Binary})
	write_describe(&w, .Portal, "")
	write_execute(&w, "")
	write_sync(&w)
	testing.expect_value(t, flush(&w), nil)

	// One send; verify the message sequence by walking the frames.
	out := ms.written[:]
	kinds := make([dynamic]u8, context.temp_allocator)
	pos := 0
	for pos < len(out) {
		append(&kinds, out[pos])
		length, _ := endian.get_i32(out[pos + 1:pos + 5], .Big)
		pos += 1 + int(length)
	}
	testing.expect_value(t, pos, len(out))
	expected := []u8{'P', 'B', 'D', 'E', 'S'}
	testing.expect_value(t, len(kinds), len(expected))
	for k, i in expected {
		testing.expect_value(t, kinds[i], k)
	}
}

@(test)
test_write_bind_null_param :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	write_bind(&w, "", "", nil, {nil}, nil)
	testing.expect_value(t, flush(&w), nil)

	out := ms.written[:]
	// portal "" (1 NUL) + stmt "" (1 NUL) + 0 param formats (2) at offset 5.
	pos := 5 + 1 + 1 + 2
	count, _ := endian.get_i16(out[pos:pos + 2], .Big)
	testing.expect_value(t, count, i16(1))
	null_len, _ := endian.get_i32(out[pos + 2:pos + 6], .Big)
	testing.expect_value(t, null_len, i32(-1))
}

@(test)
test_write_cancel_request :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	key := []u8{0xCA, 0xFE, 0xBA, 0xBE}
	write_cancel_request(&w, 12345, key)
	testing.expect_value(t, flush(&w), nil)

	out := ms.written[:]
	testing.expect_value(t, len(out), 16)
	length, _ := endian.get_i32(out[0:4], .Big)
	testing.expect_value(t, int(length), 16)
	code, _ := endian.get_u32(out[4:8], .Big)
	testing.expect_value(t, code, CANCEL_REQUEST_CODE)
	pid, _ := endian.get_i32(out[8:12], .Big)
	testing.expect_value(t, pid, i32(12345))
}

@(test)
test_write_sasl_messages :: proc(t: ^testing.T) {
	ms: Mock_Stream
	defer delete(ms.written)
	w := writer_for(&ms)
	defer msg_writer_destroy(&w)

	initial := []u8{'n', ',', ','}
	write_sasl_initial_response(&w, "SCRAM-SHA-256", initial)
	testing.expect_value(t, flush(&w), nil)

	out := ms.written[:]
	testing.expect_value(t, out[0], u8(Frontend_Msg.Password))
	testing.expect_value(t, string(out[5:19]), "SCRAM-SHA-256\x00")
	data_len, _ := endian.get_i32(out[19:23], .Big)
	testing.expect_value(t, data_len, i32(3))
	testing.expect_value(t, string(out[23:26]), "n,,")
}

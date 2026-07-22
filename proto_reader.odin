package pg

import "core:encoding/endian"
import "core:mem"

// Msg_Reader reads length-prefixed backend messages through one reusable
// fill buffer: each refill drains everything the socket has ready, so a
// typical query response (RowDescription + DataRows + CommandComplete +
// ReadyForQuery) costs one or two recv syscalls instead of two per message.
// The buffer grows to the high-water mark and is then reused, so the steady
// state performs no allocations. Returned body slices borrow the buffer and
// are invalidated by the next read_message call.
Msg_Reader :: struct {
	stream:    Stream,
	buf:       [dynamic]u8, // storage; valid data is buf[start:end]
	start:     int,
	end:       int,
	allocator: mem.Allocator,
}

@(private)
READER_INITIAL_SIZE :: 8 * 1024

msg_reader_init :: proc(r: ^Msg_Reader, stream: Stream, allocator := context.allocator) {
	r.stream = stream
	r.buf = make([dynamic]u8, READER_INITIAL_SIZE, allocator)
	r.start = 0
	r.end = 0
	r.allocator = allocator
}

msg_reader_destroy :: proc(r: ^Msg_Reader) {
	delete(r.buf)
	r.buf = nil
	r.start = 0
	r.end = 0
}

// reader_refill ensures at least `need` contiguous bytes are buffered at
// r.start, compacting and growing as required. Each recv takes everything
// available, not just what was asked for.
@(private)
reader_refill :: proc(r: ^Msg_Reader, need: int) -> Error {
	if r.end - r.start >= need {
		return nil
	}
	if r.start > 0 {
		copy(r.buf[:], r.buf[r.start:r.end])
		r.end -= r.start
		r.start = 0
	}
	if need > len(r.buf) {
		if resize_err := resize(&r.buf, max(need, len(r.buf) * 2)); resize_err != nil {
			return resize_err
		}
	}
	for r.end < need {
		n := stream_read(r.stream, r.buf[r.end:]) or_return
		if n == 0 {
			return Driver_Error.Broken
		}
		r.end += n
	}
	return nil
}

// read_message reads one backend message: a 1-byte type, an i32be length
// (which counts itself but not the type byte), and the body. The body slice
// borrows r.buf and is invalidated by the next call.
read_message :: proc(r: ^Msg_Reader) -> (kind: Backend_Msg, body: []byte, err: Error) {
	reader_refill(r, 5) or_return
	kind_byte := r.buf[r.start]
	length, _ := endian.get_u32(r.buf[r.start + 1:r.start + 5], .Big)
	if length < 4 || length > MAX_MESSAGE_SIZE {
		return nil, nil, Driver_Error.Message_Too_Large if length > MAX_MESSAGE_SIZE else Driver_Error.Protocol_Error
	}

	total := 1 + int(length)
	reader_refill(r, total) or_return
	body = r.buf[r.start + 5:r.start + total]
	r.start += total
	return Backend_Msg(kind_byte), body, nil
}

// read_ssl_response reads the single-byte server answer to SSLRequest:
// 'S' (willing) or 'N' (unwilling). Anything else is a protocol error —
// notably an ErrorResponse from a pre-3.0 server. (The server sends nothing
// after 'S' until our TLS ClientHello, so buffering cannot swallow
// handshake bytes.)
read_ssl_response :: proc(r: ^Msg_Reader) -> (willing: bool, err: Error) {
	reader_refill(r, 1) or_return
	b := r.buf[r.start]
	r.start += 1
	switch b {
	case 'S':
		return true, nil
	case 'N':
		return false, nil
	}
	return false, Driver_Error.Protocol_Error
}

// --- Bounds-checked body cursor helpers ---
//
// All parsing of message bodies goes through these so a malicious or corrupt
// server can never cause an out-of-bounds panic; failures surface as
// ok = false, which parsers translate to .Protocol_Error.

@(private)
cursor_u8 :: proc(body: []byte, pos: ^int) -> (v: u8, ok: bool) {
	if pos^ + 1 > len(body) {
		return 0, false
	}
	v = body[pos^]
	pos^ += 1
	return v, true
}

@(private)
cursor_i16 :: proc(body: []byte, pos: ^int) -> (v: i16, ok: bool) {
	if pos^ + 2 > len(body) {
		return 0, false
	}
	v, _ = endian.get_i16(body[pos^:pos^ + 2], .Big)
	pos^ += 2
	return v, true
}

@(private)
cursor_i32 :: proc(body: []byte, pos: ^int) -> (v: i32, ok: bool) {
	if pos^ + 4 > len(body) {
		return 0, false
	}
	v, _ = endian.get_i32(body[pos^:pos^ + 4], .Big)
	pos^ += 4
	return v, true
}

@(private)
cursor_u32 :: proc(body: []byte, pos: ^int) -> (v: u32, ok: bool) {
	if pos^ + 4 > len(body) {
		return 0, false
	}
	v, _ = endian.get_u32(body[pos^:pos^ + 4], .Big)
	pos^ += 4
	return v, true
}

// cursor_cstr returns the string up to (not including) the next NUL,
// borrowing body's bytes, and advances past the NUL.
@(private)
cursor_cstr :: proc(body: []byte, pos: ^int) -> (s: string, ok: bool) {
	for i := pos^; i < len(body); i += 1 {
		if body[i] == 0 {
			s = string(body[pos^:i])
			pos^ = i + 1
			return s, true
		}
	}
	return "", false
}

@(private)
cursor_bytes :: proc(body: []byte, pos: ^int, n: int) -> (b: []byte, ok: bool) {
	if n < 0 || pos^ + n > len(body) {
		return nil, false
	}
	b = body[pos^:pos^ + n]
	pos^ += n
	return b, true
}

package pg

import "core:encoding/endian"
import "core:mem"

// Msg_Writer builds frontend messages into one reusable buffer and sends
// them with a single stream write on flush, so an extended-query batch
// (Parse + Bind + Describe + Execute + Sync) costs one syscall.
Msg_Writer :: struct {
	stream:    Stream,
	buf:       [dynamic]u8,
	allocator: mem.Allocator,
}

msg_writer_init :: proc(w: ^Msg_Writer, stream: Stream, allocator := context.allocator) {
	w.stream = stream
	w.buf = make([dynamic]u8, 0, 512, allocator)
	w.allocator = allocator
}

msg_writer_destroy :: proc(w: ^Msg_Writer) {
	delete(w.buf)
	w.buf = nil
}

// begin_msg appends the type byte and reserves the 4 length bytes,
// returning their offset for end_msg to back-patch.
@(private)
begin_msg :: proc(w: ^Msg_Writer, kind: Frontend_Msg) -> (len_off: int) {
	append(&w.buf, u8(kind))
	len_off = len(w.buf)
	append(&w.buf, 0, 0, 0, 0)
	return len_off
}

// begin_untyped_msg reserves only the 4 length bytes — for StartupMessage,
// SSLRequest, and CancelRequest, which carry no type byte.
@(private)
begin_untyped_msg :: proc(w: ^Msg_Writer) -> (len_off: int) {
	len_off = len(w.buf)
	append(&w.buf, 0, 0, 0, 0)
	return len_off
}

// end_msg back-patches the i32be length, which counts itself but not the
// type byte.
@(private)
end_msg :: proc(w: ^Msg_Writer, len_off: int) {
	length := i32(len(w.buf) - len_off)
	endian.put_i32(w.buf[len_off:len_off + 4], .Big, length)
}

@(private)
put_u8 :: proc(w: ^Msg_Writer, v: u8) {
	append(&w.buf, v)
}

@(private)
put_i16 :: proc(w: ^Msg_Writer, v: i16) {
	b: [2]u8
	endian.put_i16(b[:], .Big, v)
	append(&w.buf, ..b[:])
}

@(private)
put_i32 :: proc(w: ^Msg_Writer, v: i32) {
	b: [4]u8
	endian.put_i32(b[:], .Big, v)
	append(&w.buf, ..b[:])
}

@(private)
put_u32 :: proc(w: ^Msg_Writer, v: u32) {
	b: [4]u8
	endian.put_u32(b[:], .Big, v)
	append(&w.buf, ..b[:])
}

// put_cstring appends the string's bytes plus a NUL terminator.
@(private)
put_cstring :: proc(w: ^Msg_Writer, s: string) {
	append(&w.buf, s)
	append(&w.buf, 0)
}

@(private)
put_bytes :: proc(w: ^Msg_Writer, b: []byte) {
	append(&w.buf, ..b)
}

// flush sends everything buffered in one stream write and clears the buffer
// for reuse (capacity is retained).
flush :: proc(w: ^Msg_Writer) -> Error {
	if len(w.buf) == 0 {
		return nil
	}
	err := stream_write(w.stream, w.buf[:])
	clear(&w.buf)
	return err
}

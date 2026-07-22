package pg

import "core:net"
import "core:time"

// Stream abstracts the transport under a connection so plaintext TCP, TLS,
// and in-memory mocks (for tests) are interchangeable. The codec layer
// (proto_*.odin) talks only to this vtable, never to core:net.
Stream :: struct {
	data: rawptr,
	impl: ^Stream_VTable,
}

Stream_VTable :: struct {
	// read fills any prefix of buf; n == 0 with nil err means the peer
	// closed the connection cleanly.
	read:         proc(data: rawptr, buf: []byte) -> (n: int, err: Error),
	// write sends all of buf (looping internally if needed).
	write:        proc(data: rawptr, buf: []byte) -> Error,
	// set_deadline installs per-operation timeouts; 0 means no timeout.
	set_deadline: proc(data: rawptr, read_timeout, write_timeout: time.Duration) -> Error,
	close:        proc(data: rawptr),
}

stream_read :: proc(s: Stream, buf: []byte) -> (n: int, err: Error) {
	return s.impl.read(s.data, buf)
}

stream_write :: proc(s: Stream, buf: []byte) -> Error {
	return s.impl.write(s.data, buf)
}

stream_set_deadline :: proc(s: Stream, read_timeout, write_timeout: time.Duration) -> Error {
	return s.impl.set_deadline(s.data, read_timeout, write_timeout)
}

stream_close :: proc(s: Stream) {
	s.impl.close(s.data)
}

// read_full reads exactly len(buf) bytes, looping over short reads.
// A clean peer close mid-message surfaces as .Broken.
stream_read_full :: proc(s: Stream, buf: []byte) -> Error {
	buf := buf
	for len(buf) > 0 {
		n := stream_read(s, buf) or_return
		if n == 0 {
			return .Broken
		}
		buf = buf[n:]
	}
	return nil
}

// --- Plaintext TCP implementation ---

TCP_Stream :: struct {
	socket: net.TCP_Socket,
}

tcp_stream :: proc(ts: ^TCP_Stream) -> Stream {
	return Stream{data = ts, impl = &_tcp_vtable}
}

@(private = "file")
_tcp_vtable := Stream_VTable {
	read = proc(data: rawptr, buf: []byte) -> (n: int, err: Error) {
		ts := (^TCP_Stream)(data)
		read, recv_err := net.recv_tcp(ts.socket, buf)
		if recv_err != nil {
			// Deadline expiry surfaces as ETIMEDOUT on some platforms and
			// EAGAIN/EWOULDBLOCK (SO_RCVTIMEO semantics) on others.
			if recv_err == .Timeout || recv_err == .Would_Block {
				return read, Driver_Error.Read_Timeout
			}
			return read, net.Network_Error(recv_err)
		}
		return read, nil
	},
	write = proc(data: rawptr, buf: []byte) -> Error {
		ts := (^TCP_Stream)(data)
		// net.send_tcp already loops until the whole buffer is sent.
		_, send_err := net.send_tcp(ts.socket, buf)
		if send_err != nil {
			if send_err == .Timeout || send_err == .Would_Block {
				return Driver_Error.Write_Timeout
			}
			return net.Network_Error(send_err)
		}
		return nil
	},
	set_deadline = proc(data: rawptr, read_timeout, write_timeout: time.Duration) -> Error {
		ts := (^TCP_Stream)(data)
		if err := net.set_option(ts.socket, .Receive_Timeout, read_timeout); err != nil {
			return net.Network_Error(err)
		}
		if err := net.set_option(ts.socket, .Send_Timeout, write_timeout); err != nil {
			return net.Network_Error(err)
		}
		return nil
	},
	close = proc(data: rawptr) {
		ts := (^TCP_Stream)(data)
		net.close(ts.socket)
	},
}

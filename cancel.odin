package pg


// cancel asks the server to abort whatever the connection is currently
// executing, using the BackendKeyData credentials on a dedicated side
// connection (the busy connection itself cannot be used). It is safe to
// call from another thread while conn is blocked in a query: it only reads
// fields that are immutable after connect. Cancellation is a request — the
// query may still complete; the canceled query surfaces SQLSTATE 57014 on
// the original connection.
cancel :: proc(conn: ^Conn) -> Error {
	if conn == nil || len(conn.backend_key) == 0 {
		return Driver_Error.Closed
	}

	host := conn.cfg.host if conn.cfg.host != "" else "localhost"
	port := conn.cfg.port if conn.cfg.port != 0 else DEFAULT_PORT

	timeout := conn.cfg.connect_timeout if conn.cfg.connect_timeout != 0 else DEFAULT_CONNECT_TIMEOUT
	socket, is_unix := dial_socket(host, port, timeout) or_return

	tcp := TCP_Stream {
		socket = socket,
	}
	stream := tcp_stream(&tcp)
	defer stream_close(stream)

	stream_set_deadline(stream, timeout, timeout) or_return

	// Mirror the main connection's encryption: some pg_hba setups
	// (hostssl) only accept cancel requests over TLS. Never on unix sockets.
	if conn.tls_active && conn.cfg.tls.factory != nil && !is_unix {
		w: Msg_Writer
		msg_writer_init(&w, stream, context.temp_allocator)
		write_ssl_request(&w)
		flush(&w) or_return
		r: Msg_Reader
		msg_reader_init(&r, stream, context.temp_allocator)
		willing := read_ssl_response(&r) or_return
		if willing {
			server_name := conn.cfg.tls.server_name if conn.cfg.tls.server_name != "" else conn.cfg.host
			tls := conn.cfg.tls
			stream = tls.factory(socket, &tls, server_name) or_return
		}
	}

	w: Msg_Writer
	msg_writer_init(&w, stream, context.temp_allocator)
	write_cancel_request(&w, conn.backend_pid, conn.backend_key[:])
	flush(&w) or_return

	// The server processes the request and closes the connection without
	// replying; wait for EOF so the request isn't lost to a fast close.
	waste: [16]u8
	for {
		n, read_err := stream_read(stream, waste[:])
		if read_err != nil || n == 0 {
			break
		}
	}
	return nil
}

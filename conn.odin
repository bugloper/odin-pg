package pg

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:time"

Conn_Status :: enum u8 {
	Ok,
	Closed,
	// Broken marks a connection whose protocol state is unrecoverable
	// (I/O error, protocol violation); pools destroy these on release.
	Broken,
}

Notification :: struct {
	backend_pid: i32,
	channel:     string,
	payload:     string,
}

Conn :: struct {
	tcp:           TCP_Stream,
	stream:        Stream,
	tls_active:    bool,
	reader:        Msg_Reader,
	writer:        Msg_Writer,
	status:        Conn_Status,
	txn_status:    Txn_Status,

	// Server-reported ParameterStatus values (server_version, TimeZone,
	// client_encoding, integer_datetimes, …), live-updated.
	params:        map[string]string,

	// Cancellation credentials from BackendKeyData. The key is raw bytes:
	// 4 under protocol 3.0, longer under 3.2.
	backend_pid:   i32,
	backend_key:   [dynamic]u8,

	// Buffered NotificationResponse messages (drained by the listener API).
	notifications: [dynamic]Notification,

	// Prepared-statement LRU cache (stmt.odin).
	stmt_counter:  int,
	stmt_cache:    map[string]^Stmt,
	stmt_lru:      [dynamic]^Stmt,

	// True while a Pipeline is open on this connection; blocks normal
	// query/exec/prepare entry points until pipeline_close.
	pipeline_open: bool,

	// True when connected over a unix-domain socket (no keepalive, no TLS).
	unix_socket:   bool,

	// Owned copy of the connect-time configuration (needed again for
	// cancel()'s side connection).
	cfg:           Config,

	// Set when the connection becomes ready; pools enforce max lifetime
	// against it.
	created_at:    time.Tick,

	// err_arena holds ^Server_Error values returned from this connection;
	// it is reset at the start of each command, which is what bounds their
	// lifetime.
	err_arena:     virtual.Arena,

	allocator:     mem.Allocator,
}

connect_dsn :: proc(dsn: string, allocator := context.allocator) -> (conn: ^Conn, err: Error) {
	cfg := parse_dsn(dsn, allocator) or_return
	defer config_destroy(&cfg)
	return connect(cfg, allocator)
}

// connect dials, negotiates TLS if configured, authenticates, and waits for
// ReadyForQuery. On failure involving a server ErrorResponse, the returned
// ^Server_Error is allocated from `allocator` and owned by the caller
// (release with server_error_destroy) — unlike errors from a live
// connection, which borrow the connection's arena.
connect :: proc(cfg: Config, allocator := context.allocator) -> (conn: ^Conn, err: Error) {
	conn = new(Conn, allocator) or_return
	conn.allocator = allocator
	conn.status = .Closed // flipped to .Ok only on full success

	// NOTE: not a defer — Odin defers cannot rewrite return values, so the
	// cleanup-on-error must happen before returning.
	if setup_err := conn_setup(conn, cfg); setup_err != nil {
		conn_destroy(conn)
		return nil, setup_err
	}
	return conn, nil
}

@(private)
conn_setup :: proc(conn: ^Conn, cfg: Config) -> Error {
	allocator := conn.allocator
	config_clone(&conn.cfg, cfg, allocator) or_return

	host := conn.cfg.host if conn.cfg.host != "" else "localhost"
	port := conn.cfg.port if conn.cfg.port != 0 else DEFAULT_PORT
	connect_timeout := conn.cfg.connect_timeout if conn.cfg.connect_timeout != 0 else DEFAULT_CONNECT_TIMEOUT

	socket, is_unix := dial_socket(host, port, connect_timeout) or_return
	conn.unix_socket = is_unix
	conn.tcp = TCP_Stream {
		socket = socket,
	}
	conn.stream = tcp_stream(&conn.tcp)

	if conn.cfg.tcp_keep_alive && !is_unix {
		_ = net.set_option(socket, .Keep_Alive, true)
	}

	msg_reader_init(&conn.reader, conn.stream, allocator)
	msg_writer_init(&conn.writer, conn.stream, allocator)
	conn.params.allocator = allocator
	conn.backend_key = make([dynamic]u8, 0, 4, allocator)
	conn.notifications.allocator = allocator
	if arena_err := virtual.arena_init_growing(&conn.err_arena, RESULT_ARENA_RESERVE); arena_err != nil {
		return arena_err
	}

	// Apply I/O deadlines for the whole startup exchange.
	stream_set_deadline(conn.stream, connect_timeout, connect_timeout) or_return

	negotiate_tls(conn) or_return
	startup(conn) or_return

	// Startup done: switch to the configured steady-state deadlines.
	stream_set_deadline(conn.stream, conn.cfg.read_timeout, conn.cfg.write_timeout) or_return

	conn.status = .Ok
	conn.created_at = time.tick_now()
	return nil
}

// conn_close terminates gracefully: Terminate message, socket close, frees.
conn_close :: proc(conn: ^Conn) {
	if conn == nil {
		return
	}
	if conn.status == .Ok {
		write_terminate(&conn.writer)
		_ = flush(&conn.writer)
	}
	conn_destroy(conn)
}

@(private)
conn_destroy :: proc(conn: ^Conn) {
	if conn.stream.impl != nil {
		stream_close(conn.stream)
	}
	msg_reader_destroy(&conn.reader)
	msg_writer_destroy(&conn.writer)
	for key, value in conn.params {
		delete(key, conn.allocator)
		delete(value, conn.allocator)
	}
	delete(conn.params)
	delete(conn.backend_key)
	clear_notifications(conn)
	delete(conn.notifications)
	stmt_cache_destroy(conn)
	config_destroy(&conn.cfg)
	virtual.arena_destroy(&conn.err_arena)
	free(conn, conn.allocator)
}

// server_parameter looks up a live ParameterStatus value, e.g.
// "server_version", "TimeZone", "integer_datetimes".
server_parameter :: proc(conn: ^Conn, name: string) -> (value: string, ok: bool) {
	return conn.params[name]
}

backend_pid :: proc(conn: ^Conn) -> i32 {
	return conn.backend_pid
}

// --- Startup: TLS negotiation, StartupMessage, authentication ---

@(private)
negotiate_tls :: proc(conn: ^Conn) -> Error {
	if conn.cfg.tls.mode == .Disable {
		return nil
	}
	if conn.unix_socket {
		// Like libpq, TLS is never negotiated over unix-domain sockets;
		// the socket directory's filesystem permissions are the boundary.
		return nil
	}

	write_ssl_request(&conn.writer)
	flush(&conn.writer) or_return
	willing := read_ssl_response(&conn.reader) or_return

	if !willing {
		if conn.cfg.tls.mode == .Prefer {
			return nil // plaintext fallback
		}
		return Driver_Error.TLS_Refused
	}

	if conn.cfg.tls.factory == nil {
		// TLS wanted and offered, but no implementation is wired in.
		// Import odin-pg/openssl and set Config.tls = openssl.tls_config(…).
		return Driver_Error.TLS_Not_Available
	}

	server_name := conn.cfg.tls.server_name if conn.cfg.tls.server_name != "" else conn.cfg.host
	tls_stream := conn.cfg.tls.factory(conn.tcp.socket, &conn.cfg.tls, server_name) or_return
	conn.stream = tls_stream
	conn.tls_active = true
	conn.reader.stream = tls_stream
	conn.writer.stream = tls_stream
	return nil
}

@(private)
startup :: proc(conn: ^Conn) -> Error {
	user := conn.cfg.user
	database := conn.cfg.database if conn.cfg.database != "" else user

	params := make([dynamic][2]string, 0, 4 + len(conn.cfg.runtime_params), context.temp_allocator)
	append(&params, [2]string{"user", user})
	append(&params, [2]string{"database", database})
	append(&params, [2]string{"client_encoding", "UTF8"})
	if conn.cfg.app_name != "" {
		append(&params, [2]string{"application_name", conn.cfg.app_name})
	}
	for key, value in conn.cfg.runtime_params {
		append(&params, [2]string{key, value})
	}

	write_startup(&conn.writer, params[:])
	flush(&conn.writer) or_return

	authenticate(conn) or_return

	// Drain until ReadyForQuery, collecting BackendKeyData and parameters.
	for {
		kind, body, err := read_message(&conn.reader)
		if err != nil {
			return err
		}
		#partial switch kind {
		case .Backend_Key_Data:
			pid, key, ok := parse_backend_key_data(body)
			if !ok {
				return Driver_Error.Protocol_Error
			}
			conn.backend_pid = pid
			clear(&conn.backend_key)
			append(&conn.backend_key, ..key)
		case .Parameter_Status:
			handle_parameter_status(conn, body) or_return
		case .Notice_Response:
			// Startup notices are dropped in v1.
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				return Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			return nil
		case .Error_Response:
			return startup_server_error(conn, body)
		case .Negotiate_Protocol_Version:
			// We requested 3.0, the wire baseline; a server that cannot
			// even do that is not something we can talk to.
			return Driver_Error.Protocol_Error
		case:
			return Driver_Error.Protocol_Error
		}
	}
}

@(private)
authenticate :: proc(conn: ^Conn) -> Error {
	for {
		kind, body, err := read_message(&conn.reader)
		if err != nil {
			return err
		}
		#partial switch kind {
		case .Error_Response:
			return startup_server_error(conn, body)
		case .Notice_Response:
			continue
		case .Authentication:
		// handled below
		case:
			return Driver_Error.Protocol_Error
		}

		code, payload, ok := parse_auth(body)
		if !ok {
			return Driver_Error.Protocol_Error
		}
		switch code {
		case .Ok:
			return nil
		case .Cleartext_Password:
			if !conn.tls_active && !conn.cfg.allow_cleartext_auth {
				return Driver_Error.Cleartext_Refused
			}
			write_password(&conn.writer, conn.cfg.password)
			flush(&conn.writer) or_return
		case .MD5_Password:
			if len(payload) != 4 {
				return Driver_Error.Protocol_Error
			}
			out: [MD5_RESPONSE_LEN]u8
			response := md5_auth_response(&out, conn.cfg.user, conn.cfg.password, payload)
			write_password(&conn.writer, response)
			flush(&conn.writer) or_return
		case .SASL:
			auth_sasl(conn, payload) or_return
			// Loop continues: the server sends AuthenticationOk next.
		case .Kerberos_V5, .GSS, .GSS_Continue, .SSPI, .SASL_Continue, .SASL_Final:
			return Driver_Error.Auth_Method_Unsupported
		case:
			return Driver_Error.Auth_Method_Unsupported
		}
	}
}

// auth_sasl runs the SCRAM-SHA-256 exchange (SCRAM-SHA-256-PLUS is not
// offered in v1 — it requires TLS channel binding data).
@(private)
auth_sasl :: proc(conn: ^Conn, mechanisms: []byte) -> Error {
	found := false
	pos := 0
	for {
		mech, ok := cursor_cstr(mechanisms, &pos)
		if !ok || mech == "" {
			break
		}
		if mech == "SCRAM-SHA-256" {
			found = true
		}
	}
	if !found {
		return Driver_Error.SASL_Mechanism_Unsupported
	}

	scram: Scram
	scram_init(&scram, conn.allocator)
	defer scram_destroy(&scram)

	first := scram_client_first(&scram) or_return
	write_sasl_initial_response(&conn.writer, "SCRAM-SHA-256", first)
	flush(&conn.writer) or_return

	server_first := expect_sasl_payload(conn, .SASL_Continue) or_return
	client_final := scram_handle_server_first(&scram, server_first, conn.cfg.password) or_return
	write_sasl_response(&conn.writer, client_final)
	flush(&conn.writer) or_return

	server_final := expect_sasl_payload(conn, .SASL_Final) or_return
	return scram_handle_server_final(&scram, server_final)
}

@(private)
expect_sasl_payload :: proc(conn: ^Conn, expected: Auth_Code) -> (payload: []byte, err: Error) {
	for {
		kind, body, read_err := read_message(&conn.reader)
		if read_err != nil {
			return nil, read_err
		}
		#partial switch kind {
		case .Error_Response:
			return nil, startup_server_error(conn, body)
		case .Notice_Response:
			continue
		case .Authentication:
			code, rest, ok := parse_auth(body)
			if !ok || code != expected {
				return nil, Driver_Error.Protocol_Error
			}
			return rest, nil
		case:
			return nil, Driver_Error.Protocol_Error
		}
	}
}

// startup_server_error materializes an ErrorResponse received before the
// connection is usable; it is owned by the caller's allocator because the
// connection is about to be destroyed.
@(private)
startup_server_error :: proc(conn: ^Conn, body: []byte) -> Error {
	fields, ok := parse_error_fields(body)
	if !ok {
		return Driver_Error.Protocol_Error
	}
	se, alloc_err := server_error_from_fields(fields, conn.allocator)
	if alloc_err != nil {
		return alloc_err
	}
	return se
}

@(private)
handle_parameter_status :: proc(conn: ^Conn, body: []byte) -> Error {
	name, value, ok := parse_parameter_status(body)
	if !ok {
		return Driver_Error.Protocol_Error
	}
	if old_key, old_value, found := map_entry(conn.params, name); found {
		delete(old_value, conn.allocator)
		conn.params[old_key] = strings.clone(value, conn.allocator) or_return
	} else {
		key_copy := strings.clone(name, conn.allocator) or_return
		value_copy := strings.clone(value, conn.allocator) or_return
		conn.params[key_copy] = value_copy
	}
	return nil
}

@(private)
map_entry :: proc(m: map[string]string, key: string) -> (stored_key: string, value: string, found: bool) {
	for k, v in m {
		if k == key {
			return k, v, true
		}
	}
	return "", "", false
}

@(private)
clear_notifications :: proc(conn: ^Conn) {
	for n in conn.notifications {
		delete(n.channel, conn.allocator)
		delete(n.payload, conn.allocator)
	}
	clear(&conn.notifications)
}

// config_clone deep-copies cfg into dst with allocator (used so a Conn
// keeps its own copy for reconnects/cancel side connections).
@(private)
config_clone :: proc(dst: ^Config, src: Config, allocator: mem.Allocator) -> Error {
	dst^ = src
	dst.allocator = allocator
	dst.host = strings.clone(src.host, allocator) or_return
	dst.user = strings.clone(src.user, allocator) or_return
	dst.password = strings.clone(src.password, allocator) or_return
	dst.database = strings.clone(src.database, allocator) or_return
	dst.app_name = strings.clone(src.app_name, allocator) or_return
	dst.tls.ca_file = strings.clone(src.tls.ca_file, allocator) or_return
	dst.tls.cert_file = strings.clone(src.tls.cert_file, allocator) or_return
	dst.tls.key_file = strings.clone(src.tls.key_file, allocator) or_return
	dst.tls.server_name = strings.clone(src.tls.server_name, allocator) or_return
	dst.runtime_params = make(map[string]string, allocator)
	for key, value in src.runtime_params {
		key_copy := strings.clone(key, allocator) or_return
		value_copy := strings.clone(value, allocator) or_return
		dst.runtime_params[key_copy] = value_copy
	}
	return nil
}

// ping runs an empty simple query ("SELECT 1" without result decoding) to
// verify the connection is alive; pools use it for health checks.
ping :: proc(conn: ^Conn) -> Error {
	if conn.status != .Ok {
		return Driver_Error.Closed
	}
	write_query(&conn.writer, "SELECT 1")
	if err := flush(&conn.writer); err != nil {
		conn.status = .Broken
		return err
	}
	return drain_until_ready(conn)
}

// drain_until_ready consumes messages until ReadyForQuery, remembering the
// first ErrorResponse seen. This is both the tail of every command and the
// recovery path that makes the connection reusable after a server error.
@(private)
drain_until_ready :: proc(conn: ^Conn) -> Error {
	first_err: Error
	for {
		kind, body, err := read_message(&conn.reader)
		if err != nil {
			conn.status = .Broken
			return err
		}
		#partial switch kind {
		case .Ready_For_Query:
			status, ok := parse_ready_for_query(body)
			if !ok {
				conn.status = .Broken
				return Driver_Error.Protocol_Error
			}
			conn.txn_status = status
			return first_err
		case .Error_Response:
			if first_err == nil {
				first_err = conn_server_error(conn, body)
			}
		case .Parameter_Status:
			if err2 := handle_parameter_status(conn, body); err2 != nil && first_err == nil {
				first_err = err2
			}
		case .Notification_Response:
			if err2 := buffer_notification(conn, body); err2 != nil && first_err == nil {
				first_err = err2
			}
		case:
		// Row data, command tags, etc. are discarded while draining.
		}
	}
}

// conn_server_error materializes an ErrorResponse into the connection's
// error arena (valid until the next command starts).
@(private)
conn_server_error :: proc(conn: ^Conn, body: []byte) -> Error {
	fields, ok := parse_error_fields(body)
	if !ok {
		conn.status = .Broken
		return Driver_Error.Protocol_Error
	}
	se, alloc_err := server_error_from_fields(fields, virtual.arena_allocator(&conn.err_arena))
	if alloc_err != nil {
		return alloc_err
	}
	return se
}

@(private)
buffer_notification :: proc(conn: ^Conn, body: []byte) -> Error {
	pid, channel, payload, ok := parse_notification(body)
	if !ok {
		conn.status = .Broken
		return Driver_Error.Protocol_Error
	}
	channel_copy := strings.clone(channel, conn.allocator) or_return
	payload_copy := strings.clone(payload, conn.allocator) or_return
	append(&conn.notifications, Notification{backend_pid = pid, channel = channel_copy, payload = payload_copy})
	return nil
}

// command_begin resets per-command state; every query entry point calls it.
@(private)
command_begin :: proc(conn: ^Conn) -> Error {
	switch conn.status {
	case .Ok:
	case .Closed:
		return Driver_Error.Closed
	case .Broken:
		return Driver_Error.Broken
	}
	if conn.pipeline_open {
		return Driver_Error.In_Pipeline
	}
	virtual.arena_free_all(&conn.err_arena)
	return nil
}

// conn_error_allocator allocates values that live until the next command
// (Server_Error fields, exec tags).
@(private)
conn_error_allocator :: proc(conn: ^Conn) -> mem.Allocator {
	return virtual.arena_allocator(&conn.err_arena)
}

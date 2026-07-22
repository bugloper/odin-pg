package pg

// LISTEN/NOTIFY. A Listener owns a dedicated connection (notifications are
// delivered per-connection, and mixing them with a busy query connection —
// or a transaction-mode external pooler — is a foot-gun). It remembers its
// channels so listener_reconnect can restore them after a network drop.

import "core:mem"
import "core:strings"
import "core:time"

Listener :: struct {
	conn:      ^Conn,
	channels:  [dynamic]string, // owned copies, for reconnect
	current:   Notification, // last handed-out notification (owned here)
	cfg:       Config, // owned copy, for reconnect
	allocator: mem.Allocator,
}

listener_create :: proc(cfg: Config, allocator := context.allocator) -> (l: ^Listener, err: Error) {
	l = new(Listener, allocator) or_return
	l.allocator = allocator
	l.channels.allocator = allocator
	if clone_err := config_clone(&l.cfg, cfg, allocator); clone_err != nil {
		free(l, allocator)
		return nil, clone_err
	}
	conn, conn_err := connect(l.cfg, allocator)
	if conn_err != nil {
		config_destroy(&l.cfg)
		free(l, allocator)
		return nil, conn_err
	}
	l.conn = conn
	return l, nil
}

listener_create_dsn :: proc(dsn: string, allocator := context.allocator) -> (l: ^Listener, err: Error) {
	cfg := parse_dsn(dsn, allocator) or_return
	defer config_destroy(&cfg)
	return listener_create(cfg, allocator)
}

listen :: proc(l: ^Listener, channel: string) -> Error {
	sql := strings.concatenate({"LISTEN ", quote_ident(channel)}, context.temp_allocator)
	_, err := conn_exec(l.conn, sql)
	if err != nil {
		return err
	}
	for existing in l.channels {
		if existing == channel {
			return nil
		}
	}
	channel_copy := strings.clone(channel, l.allocator) or_return
	append(&l.channels, channel_copy)
	return nil
}

unlisten :: proc(l: ^Listener, channel: string) -> Error {
	sql := strings.concatenate({"UNLISTEN ", quote_ident(channel)}, context.temp_allocator)
	_, err := conn_exec(l.conn, sql)
	if err != nil {
		return err
	}
	for existing, i in l.channels {
		if existing == channel {
			delete(existing, l.allocator)
			ordered_remove(&l.channels, i)
			break
		}
	}
	return nil
}

// next_notification blocks until a notification arrives, timeout elapses
// (.Read_Timeout; 0 = wait forever), or the connection fails. The returned
// Notification is valid until the next call on this listener.
//
// Caveat: a timeout that fires while a message is partially received leaves
// the stream mid-message and the connection is marked broken — use
// listener_reconnect. Whole-message delivery is the overwhelmingly common
// case, so plain timeouts (no traffic at all) do NOT break the connection.
next_notification :: proc(l: ^Listener, timeout: time.Duration = 0) -> (n: Notification, err: Error) {
	free_current(l)

	// Already buffered (e.g. arrived during a listen() round trip)?
	if len(l.conn.notifications) > 0 {
		return take_front(l), nil
	}

	if l.conn.status != .Ok {
		return {}, Driver_Error.Broken
	}

	stream_set_deadline(l.conn.stream, timeout, l.cfg.write_timeout) or_return
	defer _ = stream_set_deadline(l.conn.stream, l.cfg.read_timeout, l.cfg.write_timeout)

	for {
		kind, body, read_err := read_message(&l.conn.reader)
		if read_err != nil {
			if read_err == Error(Driver_Error.Read_Timeout) {
				// No traffic at all: benign. (Partial-message timeouts are
				// indistinguishable here; the next read will fail fast and
				// mark the conn broken.)
				return {}, Driver_Error.Read_Timeout
			}
			l.conn.status = .Broken
			return {}, read_err
		}
		#partial switch kind {
		case .Notification_Response:
			buffer_notification(l.conn, body) or_return
			return take_front(l), nil
		case .Notice_Response:
		case .Parameter_Status:
			_ = handle_parameter_status(l.conn, body)
		case .Error_Response:
			// Async server error (e.g. shutdown): connection is done.
			server_err := conn_server_error(l.conn, body)
			l.conn.status = .Broken
			return {}, server_err
		case:
			l.conn.status = .Broken
			return {}, Driver_Error.Protocol_Error
		}
	}
}

// listener_reconnect dials a fresh connection and re-issues every LISTEN.
// Notifications sent while disconnected are lost (NOTIFY is fire-and-forget);
// reconcile from application state after reconnecting.
listener_reconnect :: proc(l: ^Listener) -> Error {
	if l.conn != nil {
		conn_close(l.conn)
		l.conn = nil
	}
	conn := connect(l.cfg, l.allocator) or_return
	l.conn = conn
	for channel in l.channels {
		sql := strings.concatenate({"LISTEN ", quote_ident(channel)}, context.temp_allocator)
		if _, err := conn_exec(l.conn, sql); err != nil {
			return err
		}
	}
	return nil
}

listener_close :: proc(l: ^Listener) {
	if l == nil {
		return
	}
	free_current(l)
	if l.conn != nil {
		conn_close(l.conn)
	}
	for channel in l.channels {
		delete(channel, l.allocator)
	}
	delete(l.channels)
	config_destroy(&l.cfg)
	free(l, l.allocator)
}

@(private = "file")
take_front :: proc(l: ^Listener) -> Notification {
	n := l.conn.notifications[0]
	ordered_remove(&l.conn.notifications, 0)
	l.current = n // strings owned by conn.allocator; freed on next call
	return n
}

@(private = "file")
free_current :: proc(l: ^Listener) {
	if l.current.channel != "" || l.current.payload != "" {
		delete(l.current.channel, l.conn.allocator)
		delete(l.current.payload, l.conn.allocator)
	}
	l.current = {}
}

// quote_ident double-quotes a SQL identifier, escaping embedded quotes —
// LISTEN/UNLISTEN take identifiers, which cannot be bound as parameters.
@(private)
quote_ident :: proc(ident: string, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	strings.write_byte(&sb, '"')
	for c in transmute([]byte)ident {
		if c == '"' {
			strings.write_byte(&sb, '"')
		}
		strings.write_byte(&sb, c)
	}
	strings.write_byte(&sb, '"')
	return strings.to_string(sb)
}

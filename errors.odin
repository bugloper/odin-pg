package pg

import "core:mem"
import "core:net"
import "core:strconv"
import "core:strings"

// Error is the single error type returned across the public API. `err == nil`
// and `or_return` compose across all variants.
Error :: union #shared_nil {
	Driver_Error,
	^Server_Error,
	net.Network_Error,
	mem.Allocator_Error,
}

// Driver_Error covers driver/client-side conditions: everything that goes
// wrong without the server having sent an ErrorResponse.
Driver_Error :: enum u8 {
	None = 0,

	// Transport / lifecycle.
	Connect_Timeout,
	Read_Timeout,
	Write_Timeout,
	Closed,
	Broken,
	Protocol_Error,
	Message_Too_Large,

	// TLS.
	TLS_Refused,
	TLS_Failed,
	TLS_Not_Available,

	// Authentication.
	Auth_Failed,
	Auth_Method_Unsupported,
	Cleartext_Refused,
	SASL_Mechanism_Unsupported,

	// Pool.
	Pool_Exhausted,
	Pool_Closed,

	// Results / scanning.
	No_Rows,
	Too_Many_Rows,
	Null_Value,
	Column_Out_Of_Range,
	No_Such_Column,
	Type_Mismatch,
	Unsupported_Type,
	Out_Of_Range,

	// Transactions.
	Not_In_Transaction,
	In_Failed_Transaction,

	// Pipeline.
	In_Pipeline, // conn has an open pipeline; regular queries are blocked
	Pipeline_Aborted, // an earlier command in the batch failed; this one was skipped

	// Misc.
	Copy_Aborted,
	Cancelled,
	Invalid_DSN,
	Invalid_Config,
}

Severity :: enum u8 {
	Unknown,
	Log,
	Debug,
	Info,
	Notice,
	Warning,
	Error,
	Fatal,
	Panic,
}

// Server_Error is a fully parsed PostgreSQL ErrorResponse (or NoticeResponse).
//
// Lifetime: a ^Server_Error returned from a connection borrows that
// connection's error arena and is valid only until the next command runs on
// the same connection. Use server_error_clone to keep it longer.
Server_Error :: struct {
	severity:       Severity,
	code:           [5]u8, // SQLSTATE, e.g. "23505"
	message:        string,
	detail:         string,
	hint:           string,
	position:       int,
	internal_query: string,
	where_ctx:      string,
	schema:         string,
	table:          string,
	column:         string,
	data_type:      string,
	constraint:     string,
	file:           string,
	line:           int,
	routine:        string,
}

// server_error_from_fields materializes a parsed ErrorResponse, cloning all
// strings into allocator (a connection's error arena, or a caller allocator
// for errors that must outlive the connection).
server_error_from_fields :: proc(fields: Error_Fields, allocator := context.allocator) -> (se: ^Server_Error, err: mem.Allocator_Error) {
	se = new(Server_Error, allocator) or_return

	switch fields.severity {
	case "LOG":
		se.severity = .Log
	case "DEBUG":
		se.severity = .Debug
	case "INFO":
		se.severity = .Info
	case "NOTICE":
		se.severity = .Notice
	case "WARNING":
		se.severity = .Warning
	case "ERROR":
		se.severity = .Error
	case "FATAL":
		se.severity = .Fatal
	case "PANIC":
		se.severity = .Panic
	case:
		se.severity = .Unknown
	}

	copy(se.code[:], fields.code)
	se.message = strings.clone(fields.message, allocator) or_return
	se.detail = strings.clone(fields.detail, allocator) or_return
	se.hint = strings.clone(fields.hint, allocator) or_return
	se.internal_query = strings.clone(fields.internal_query, allocator) or_return
	se.where_ctx = strings.clone(fields.where_ctx, allocator) or_return
	se.schema = strings.clone(fields.schema, allocator) or_return
	se.table = strings.clone(fields.table, allocator) or_return
	se.column = strings.clone(fields.column, allocator) or_return
	se.data_type = strings.clone(fields.data_type, allocator) or_return
	se.constraint = strings.clone(fields.constraint, allocator) or_return
	se.file = strings.clone(fields.file, allocator) or_return
	se.routine = strings.clone(fields.routine, allocator) or_return
	se.position, _ = strconv.parse_int(fields.position)
	se.line, _ = strconv.parse_int(fields.line)
	return se, nil
}

// server_error_destroy frees a Server_Error that was allocated with an
// individual allocator (e.g. one returned from a failed connect). Never call
// it on errors borrowed from a live connection's arena.
server_error_destroy :: proc(se: ^Server_Error, allocator := context.allocator) {
	if se == nil {
		return
	}
	delete(se.message, allocator)
	delete(se.detail, allocator)
	delete(se.hint, allocator)
	delete(se.internal_query, allocator)
	delete(se.where_ctx, allocator)
	delete(se.schema, allocator)
	delete(se.table, allocator)
	delete(se.column, allocator)
	delete(se.data_type, allocator)
	delete(se.constraint, allocator)
	delete(se.file, allocator)
	delete(se.routine, allocator)
	free(se, allocator)
}

// sqlstate extracts the 5-character SQLSTATE code if err is a server error.
sqlstate :: proc(err: Error) -> (code: string, ok: bool) {
	se, is_server := err.(^Server_Error)
	if !is_server || se == nil {
		return "", false
	}
	return string(se.code[:]), true
}

is_unique_violation :: proc(err: Error) -> bool {
	code, ok := sqlstate(err)
	return ok && code == "23505"
}

is_foreign_key_violation :: proc(err: Error) -> bool {
	code, ok := sqlstate(err)
	return ok && code == "23503"
}

is_serialization_failure :: proc(err: Error) -> bool {
	code, ok := sqlstate(err)
	return ok && code == "40001"
}

is_deadlock :: proc(err: Error) -> bool {
	code, ok := sqlstate(err)
	return ok && code == "40P01"
}

is_query_canceled :: proc(err: Error) -> bool {
	code, ok := sqlstate(err)
	return ok && code == "57014"
}

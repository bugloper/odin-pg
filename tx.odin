package pg

import "core:strconv"
import "core:strings"

Tx_Iso :: enum u8 {
	Default,
	Read_Committed,
	Repeatable_Read,
	Serializable,
}

Tx_Options :: struct {
	iso:        Tx_Iso,
	read_only:  bool,
	deferrable: bool, // only meaningful with Serializable + read_only
}

// Tx is a live transaction handle. rollback after commit is a no-op, so the
// canonical shape is:
//
//	tx := pg.begin(conn) or_return
//	defer pg.rollback(&tx)
//	pg.exec(&tx, "…") or_return
//	pg.commit(&tx) or_return
//
// Nested begin(&tx) maps to SAVEPOINTs.
Tx :: struct {
	conn:  ^Conn,
	done:  bool,
	depth: int, // 0 = top-level; >0 = savepoint
}

// Public entry points dispatch on ^Conn vs ^Tx.
exec :: proc {
	conn_exec,
	tx_exec,
}
query :: proc {
	conn_query,
	tx_query,
}
query_row :: proc {
	conn_query_row,
	tx_query_row,
}
begin :: proc {
	conn_begin,
	tx_begin,
}

conn_begin :: proc(conn: ^Conn, opts := Tx_Options{}) -> (tx: Tx, err: Error) {
	sql := begin_sql(opts)
	_, err = conn_exec(conn, sql)
	if err != nil {
		return {}, err
	}
	return Tx{conn = conn}, nil
}

// tx_begin opens a nested transaction as a savepoint.
tx_begin :: proc(parent: ^Tx, opts := Tx_Options{}) -> (tx: Tx, err: Error) {
	if parent.done {
		return {}, Driver_Error.Not_In_Transaction
	}
	// Isolation cannot change mid-transaction; reject rather than ignore.
	if opts != {} {
		return {}, Driver_Error.Invalid_Config
	}
	depth := parent.depth + 1
	buf: [48]u8
	_, err = conn_exec(parent.conn, savepoint_sql(buf[:], "SAVEPOINT pg_sp_", depth))
	if err != nil {
		return {}, err
	}
	return Tx{conn = parent.conn, depth = depth}, nil
}

commit :: proc(tx: ^Tx) -> Error {
	if tx.done {
		return Driver_Error.Not_In_Transaction
	}
	tx.done = true
	buf: [64]u8
	sql := tx.depth == 0 ? "COMMIT" : savepoint_sql(buf[:], "RELEASE SAVEPOINT pg_sp_", tx.depth)
	_, err := conn_exec(tx.conn, sql)
	return err
}

// rollback aborts the transaction (or rolls back to this savepoint). It is
// a no-op after commit/rollback, so it is always safe to defer.
rollback :: proc(tx: ^Tx) -> Error {
	if tx.done {
		return nil
	}
	tx.done = true
	buf: [64]u8
	sql := tx.depth == 0 ? "ROLLBACK" : savepoint_sql(buf[:], "ROLLBACK TO SAVEPOINT pg_sp_", tx.depth)
	_, err := conn_exec(tx.conn, sql)
	return err
}

tx_exec :: proc(tx: ^Tx, sql: string, args: ..any) -> (tag: Command_Tag, err: Error) {
	if tx.done {
		return {}, Driver_Error.Not_In_Transaction
	}
	return conn_exec(tx.conn, sql, ..args)
}

tx_query :: proc(tx: ^Tx, sql: string, args: ..any) -> (res: Result, err: Error) {
	if tx.done {
		return {}, Driver_Error.Not_In_Transaction
	}
	return conn_query(tx.conn, sql, ..args)
}

tx_query_row :: proc(tx: ^Tx, sql: string, args: ..any) -> (res: Result, err: Error) {
	if tx.done {
		return {}, Driver_Error.Not_In_Transaction
	}
	return conn_query_row(tx.conn, sql, ..args)
}

@(private = "file")
begin_sql :: proc(opts: Tx_Options) -> string {
	if opts == {} {
		return "BEGIN"
	}
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "BEGIN ISOLATION LEVEL ")
	switch opts.iso {
	case .Default, .Read_Committed:
		strings.write_string(&sb, "READ COMMITTED")
	case .Repeatable_Read:
		strings.write_string(&sb, "REPEATABLE READ")
	case .Serializable:
		strings.write_string(&sb, "SERIALIZABLE")
	}
	if opts.read_only {
		strings.write_string(&sb, " READ ONLY")
	}
	if opts.deferrable {
		strings.write_string(&sb, " DEFERRABLE")
	}
	return strings.to_string(sb)
}

@(private = "file")
savepoint_sql :: proc(buf: []byte, prefix: string, depth: int) -> string {
	n := copy(buf, prefix)
	num := strconv.write_int(buf[n:], i64(depth), 10)
	return string(buf[:n + len(num)])
}

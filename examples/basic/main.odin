// A runnable tour of odin-pg. Point it at any PostgreSQL server:
//
//	docker compose -f tests/docker-compose.yml up -d --wait pg-scram
//	PG_DSN="postgres://odin:odin_pg_test@localhost:5435/odin_pg_test" \
//	  odin run examples/basic
package basic

import "core:fmt"
import "core:os"

import pg "../.."

main :: proc() {
	dsn := os.get_env("PG_DSN", context.allocator)
	if dsn == "" {
		fmt.eprintln("set PG_DSN, e.g. postgres://user:pass@localhost:5432/db")
		os.exit(1)
	}

	conn, err := pg.connect_dsn(dsn)
	if err != nil {
		fmt.eprintfln("connect: %v", err)
		os.exit(1)
	}
	defer pg.conn_close(conn)
	version, _ := pg.server_parameter(conn, "server_version")
	fmt.printfln("connected to PostgreSQL %s (backend pid %d)", version, pg.backend_pid(conn))

	// Schema + data inside a transaction.
	{
		tx, tx_err := pg.begin(conn)
		if tx_err != nil {
			fmt.eprintfln("begin: %v", tx_err)
			os.exit(1)
		}
		defer pg.rollback(&tx)
		_, _ = pg.exec(
			&tx,
			"CREATE TEMP TABLE fruit (id int8 PRIMARY KEY, name text NOT NULL, price numeric)",
		)
		tag, ins_err := pg.exec(
			&tx,
			"INSERT INTO fruit VALUES ($1,$2,$3), ($4,$5,$6), ($7,$8,NULL)",
			1,
			"apple",
			0.5,
			2,
			"banana",
			0.25,
			3,
			"quince",
		)
		if ins_err != nil {
			fmt.eprintfln("insert: %v", ins_err)
			os.exit(1)
		}
		fmt.printfln("inserted %d rows", tag.rows_affected)
		if commit_err := pg.commit(&tx); commit_err != nil {
			fmt.eprintfln("commit: %v", commit_err)
			os.exit(1)
		}
	}

	// Parameterized query with typed scanning.
	Fruit :: struct {
		id:    i64,
		name:  string,
		price: Maybe(f64),
	}
	res, q_err := pg.query(
		conn,
		"SELECT id, name, price::float8 AS price FROM fruit WHERE id >= $1 ORDER BY id",
		1,
	)
	if q_err != nil {
		if code, ok := pg.sqlstate(q_err); ok {
			fmt.eprintfln("server error %s: %v", code, q_err)
		} else {
			fmt.eprintfln("query: %v", q_err)
		}
		os.exit(1)
	}
	defer pg.result_destroy(&res)

	for row in res.rows {
		f: Fruit
		if scan_err := pg.scan_struct(row, &f, context.temp_allocator); scan_err != nil {
			fmt.eprintfln("scan: %v", scan_err)
			os.exit(1)
		}
		if price, has_price := f.price.?; has_price {
			fmt.printfln("  #%d %-8s $%.2f", f.id, f.name, price)
		} else {
			fmt.printfln("  #%d %-8s (no price)", f.id, f.name)
		}
	}

	// Arrays and exact numerics.
	res2, _ := pg.query(conn, "SELECT ARRAY[1,2,3]::int8[], 19.99::numeric")
	defer pg.result_destroy(&res2)
	ids, _ := pg.get(res2.rows[0], []i64, 0, context.temp_allocator)
	price, _ := pg.get(res2.rows[0], pg.Numeric, 1, context.temp_allocator)
	fmt.printfln("array %v, numeric %s", ids, pg.numeric_to_string(price, context.temp_allocator))
}

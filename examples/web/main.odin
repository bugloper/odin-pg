// A JSON HTTP API on laytan/odin-http backed by an odin-pg connection pool.
//
// Setup (odin-http is not vendored; clone it next to this example):
//
//	git clone --depth 1 https://github.com/laytan/odin-http examples/vendor/odin-http
//	docker compose -f tests/docker-compose.yml up -d --wait pg-scram
//	PG_DSN="postgres://odin:odin_pg_test@localhost:5435/odin_pg_test" \
//	  odin run examples/web
//
// Try it:
//
// curl localhost:8080/
// curl localhost:8080/todos
// curl -X POST localhost:8080/todos -d '{"title": "write an Odin driver"}'
// curl -X POST localhost:8080/todos/1/done
// curl -X DELETE localhost:8080/todos/1
//
// Note: odin-http handlers run on its (single-threaded) event loop, so the
// blocking database calls below serialize requests. That keeps the example
// simple; the pool still matters — it reconnects broken sessions and is
// ready if you spread handlers across threads.
package web_example

import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:net"
import "core:os"
import "core:strconv"

import pg "../.."
import http "../vendor/odin-http"

pool: ^pg.Pool

Todo :: struct {
	id:    i64,
	title: string,
	done:  bool,
}

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	dsn := os.get_env("PG_DSN", context.allocator)
	if dsn == "" {
		fmt.eprintln("set PG_DSN, e.g. postgres://odin:odin_pg_test@localhost:5435/odin_pg_test")
		os.exit(1)
	}

	cfg, cfg_err := pg.parse_dsn(dsn)
	if cfg_err != nil {
		fmt.eprintfln("bad PG_DSN: %v", cfg_err)
		os.exit(1)
	}
	defer pg.config_destroy(&cfg)

	pool_err: pg.Error
	pool, pool_err = pg.pool_create(pg.Pool_Config{conn_config = cfg, max_conns = 8})
	if pool_err != nil {
		fmt.eprintfln("pool_create: %v", pool_err)
		os.exit(1)
	}
	defer pg.pool_close(pool)

	if _, err := pg.pool_exec(
		pool,
		`CREATE TABLE IF NOT EXISTS todos (
			id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			title text    NOT NULL,
			done  boolean NOT NULL DEFAULT false
		)`,
	); err != nil {
		fmt.eprintfln("schema init: %v", err)
		os.exit(1)
	}

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.route_get(&router, "/", http.handler(handle_index))
	http.route_get(&router, "/todos", http.handler(handle_list))
	http.route_post(&router, "/todos", http.handler(handle_create))
	http.route_post(&router, "/todos/(%d+)/done", http.handler(handle_mark_done))
	http.route_delete(&router, "/todos/(%d+)", http.handler(handle_delete))

	server: http.Server
	http.server_shutdown_on_interrupt(&server)

	fmt.println("listening on http://127.0.0.1:8080")
	err := http.listen_and_serve(
		&server,
		http.router_handler(&router),
		net.Endpoint{address = net.IP4_Loopback, port = 8080},
	)
	fmt.printfln("server stopped: %v", err)
}

// GET / — service health straight from the database.
handle_index :: proc(req: ^http.Request, res: ^http.Response) {
	result, err := pg.pool_query(pool, "SELECT current_database(), version()")
	if err != nil {
		respond_db_error(res, err)
		return
	}
	defer pg.result_destroy(&result)

	database, _ := pg.row_text(result.rows[0], 0)
	version, _ := pg.row_text(result.rows[0], 1)
	Info :: struct {
		database: string,
		version:  string,
	}
	_ = http.respond_json(res, Info{database = database, version = version})
}

// GET /todos — every row, scanned into structs, marshalled to JSON.
handle_list :: proc(req: ^http.Request, res: ^http.Response) {
	result, err := pg.pool_query(pool, "SELECT id, title, done FROM todos ORDER BY id")
	if err != nil {
		respond_db_error(res, err)
		return
	}
	defer pg.result_destroy(&result)

	todos := make([dynamic]Todo, 0, len(result.rows), context.temp_allocator)
	for row in result.rows {
		todo: Todo
		if scan_err := pg.scan_struct(row, &todo, context.temp_allocator); scan_err != nil {
			respond_db_error(res, scan_err)
			return
		}
		append(&todos, todo)
	}
	_ = http.respond_json(res, todos[:])
}

// POST /todos — JSON body {"title": "..."}; parameters are bound, never
// interpolated.
handle_create :: proc(req: ^http.Request, res: ^http.Response) {
	http.body(req, 4096, res, proc(res_ptr: rawptr, body: http.Body, body_err: http.Body_Error) {
		res := (^http.Response)(res_ptr)
		if body_err != nil {
			http.respond(res, http.body_error_status(body_err))
			return
		}

		payload: struct {
			title: string,
		}
		if json.unmarshal(transmute([]byte)body, &payload, allocator = context.temp_allocator) !=
			   nil ||
		   payload.title == "" {
			respond_error(res, .Unprocessable_Content, "body must be JSON: {\"title\": \"…\"}")
			return
		}

		result, err := pg.pool_query(
			pool,
			"INSERT INTO todos (title) VALUES ($1) RETURNING id, title, done",
			payload.title,
		)
		if err != nil {
			respond_db_error(res, err)
			return
		}
		defer pg.result_destroy(&result)

		todo: Todo
		if scan_err := pg.scan_struct(result.rows[0], &todo, context.temp_allocator);
		   scan_err != nil {
			respond_db_error(res, scan_err)
			return
		}
		_ = http.respond_json(res, todo, .Created)
	})
}

// POST /todos/:id/done
handle_mark_done :: proc(req: ^http.Request, res: ^http.Response) {
	id, id_ok := strconv.parse_i64(req.url_params[0])
	if !id_ok {
		respond_error(res, .Bad_Request, "invalid id")
		return
	}

	tag, err := pg.pool_exec(pool, "UPDATE todos SET done = true WHERE id = $1", id)
	if err != nil {
		respond_db_error(res, err)
		return
	}
	if tag.rows_affected == 0 {
		respond_error(res, .Not_Found, "no such todo")
		return
	}
	http.respond(res, http.Status.No_Content)
}

// DELETE /todos/:id
handle_delete :: proc(req: ^http.Request, res: ^http.Response) {
	id, id_ok := strconv.parse_i64(req.url_params[0])
	if !id_ok {
		respond_error(res, .Bad_Request, "invalid id")
		return
	}

	tag, err := pg.pool_exec(pool, "DELETE FROM todos WHERE id = $1", id)
	if err != nil {
		respond_db_error(res, err)
		return
	}
	if tag.rows_affected == 0 {
		respond_error(res, .Not_Found, "no such todo")
		return
	}
	http.respond(res, http.Status.No_Content)
}

respond_error :: proc(res: ^http.Response, status: http.Status, message: string) {
	Error_Body :: struct {
		error: string,
	}
	_ = http.respond_json(res, Error_Body{error = message}, status)
}

// respond_db_error surfaces the SQLSTATE for server errors and hides
// driver/network detail behind a 500.
respond_db_error :: proc(res: ^http.Response, err: pg.Error) {
	if code, ok := pg.sqlstate(err); ok {
		log.errorf("database error %s: %v", code, err)
		respond_error(
			res,
			.Internal_Server_Error,
			fmt.tprintf("database error (SQLSTATE %s)", code),
		)
		return
	}
	log.errorf("database error: %v", err)
	respond_error(res, .Internal_Server_Error, "database unavailable")
}

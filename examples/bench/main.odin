// Throughput micro-benchmark for odin-pg. Point it at a local server:
//
//	docker compose -f tests/docker-compose.yml up -d --wait pg-scram
//	PG_DSN="postgres://odin:odin_pg_test@localhost:5435/odin_pg_test" \
//	  odin run examples/bench -o:speed
//
// Measures round-trip-bound workloads (localhost), so it primarily reflects
// protocol overhead: message encoding, syscalls per query, decode cost.
package bench

import "core:fmt"
import "core:os"
import "core:sync"
import "core:thread"
import "core:time"

import pg "../.."

ITERS :: 5_000
POOL_WORKERS :: 8
POOL_ITERS_PER_WORKER :: 1_000

main :: proc() {
	// dsn := os.get_env("PG_DSN", context.allocator)
	dsn := "host=/tmp user=nimayonten dbname=odin_pg_db"
	if dsn == "" {
		fmt.eprintln("set PG_DSN")
		os.exit(1)
	}

	conn, err := pg.connect_dsn(dsn)
	if err != nil {
		fmt.eprintfln("connect: %v", err)
		os.exit(1)
	}
	defer pg.conn_close(conn)

	// 1. Simple protocol, no params.
	bench("simple query      (SELECT 1)", ITERS, proc(conn: ^pg.Conn, i: int) -> pg.Error {
			res := pg.query(conn, "SELECT 1") or_return
			pg.result_destroy(&res)
			return nil
		}, conn)

	// 2. Extended protocol + statement cache + binary results.
	bench("extended cached   (SELECT $1::int8)", ITERS, proc(conn: ^pg.Conn, i: int) -> pg.Error {
			res := pg.query(conn, "SELECT $1::int8", i) or_return
			v, get_err := pg.get(res.rows[0], i64, 0)
			assert(get_err == nil && v == i64(i))
			pg.result_destroy(&res)
			return nil
		}, conn)

	// 3. Pipelined batches of 50.
	{
		BATCH :: 50
		p, _ := pg.pipeline_begin(conn)
		start := time.tick_now()
		total := 0
		for total < ITERS {
			for _ in 0 ..< BATCH {
				if pg.pipeline_query(&p, "SELECT $1::int8", total) != nil {
					fmt.eprintln("pipeline queue failed")
					os.exit(1)
				}
				total += 1
			}
			items, sync_err := pg.pipeline_sync(&p)
			if sync_err != nil {
				fmt.eprintfln("pipeline sync: %v", sync_err)
				os.exit(1)
			}
			pg.pipeline_items_destroy(items)
		}
		report(
			"pipelined x50     (SELECT $1::int8)",
			total,
			time.tick_diff(start, time.tick_now()),
		)
		pg.pipeline_close(&p)
	}

	// 4. Pool under concurrency.
	{
		cfg, _ := pg.parse_dsn(dsn)
		defer pg.config_destroy(&cfg)
		pool, pool_err := pg.pool_create(
			pg.Pool_Config{conn_config = cfg, max_conns = POOL_WORKERS},
		)
		if pool_err != nil {
			fmt.eprintfln("pool: %v", pool_err)
			os.exit(1)
		}
		defer pg.pool_close(pool)

		Job :: struct {
			pool: ^pg.Pool,
			wg:   sync.Wait_Group,
		}
		job := Job {
			pool = pool,
		}
		sync.wait_group_add(&job.wg, POOL_WORKERS)
		start := time.tick_now()
		workers: [POOL_WORKERS]^thread.Thread
		for i in 0 ..< POOL_WORKERS {
			workers[i] = thread.create_and_start_with_poly_data(&job, proc(job: ^Job) {
				defer sync.wait_group_done(&job.wg)
				for n in 0 ..< POOL_ITERS_PER_WORKER {
					res, q_err := pg.pool_query(job.pool, "SELECT $1::int8", n)
					if q_err == nil {
						pg.result_destroy(&res)
					}
				}
			})
		}
		sync.wait_group_wait(&job.wg)
		report(
			fmt.tprintf("pool %d workers    (SELECT $1::int8)", POOL_WORKERS),
			POOL_WORKERS * POOL_ITERS_PER_WORKER,
			time.tick_diff(start, time.tick_now()),
		)
		for w in workers {
			thread.destroy(w)
		}
	}
}

bench :: proc(
	name: string,
	iters: int,
	body: proc(conn: ^pg.Conn, i: int) -> pg.Error,
	conn: ^pg.Conn,
) {
	start := time.tick_now()
	for i in 0 ..< iters {
		if err := body(conn, i); err != nil {
			fmt.eprintfln("%s failed: %v", name, err)
			os.exit(1)
		}
	}
	report(name, iters, time.tick_diff(start, time.tick_now()))
}

report :: proc(name: string, iters: int, elapsed: time.Duration) {
	per := elapsed / time.Duration(iters)
	rate := f64(iters) / time.duration_seconds(elapsed)
	fmt.printfln("%-40s %8d iters  %10v/op  %10.0f ops/s", name, iters, per, rate)
}

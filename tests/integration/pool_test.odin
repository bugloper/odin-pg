package pg_integration_tests

import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import pg "../.."

@(private = "file")
pool_or_skip :: proc(t: ^testing.T, max_conns: int, acquire_timeout := time.Duration(0)) -> ^pg.Pool {
	testing.set_fail_timeout(t, 120_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return nil
	}
	cfg, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&cfg)

	pool, pool_err := pg.pool_create(
		pg.Pool_Config{conn_config = cfg, max_conns = max_conns, acquire_timeout = acquire_timeout},
	)
	testing.expectf(t, pool_err == nil, "pool_create failed: %v", pool_err)
	return pool
}

@(test)
test_pool_basic :: proc(t: ^testing.T) {
	pool := pool_or_skip(t, 4)
	if pool == nil {
		return
	}
	defer pg.pool_close(pool)

	res, err := pg.pool_query(pool, "SELECT $1::int8", 7)
	testing.expect_value(t, err, nil)
	defer pg.result_destroy(&res)
	v, _ := pg.get(res.rows[0], i64, 0)
	testing.expect_value(t, v, i64(7))

	// Conn reuse: same backend PID for sequential acquires.
	c1, _ := pg.pool_acquire(pool)
	pid1 := pg.backend_pid(c1)
	pg.pool_release(pool, c1)
	c2, _ := pg.pool_acquire(pool)
	pid2 := pg.backend_pid(c2)
	pg.pool_release(pool, c2)
	testing.expect_value(t, pid1, pid2)
}

@(test)
test_pool_transaction_reset :: proc(t: ^testing.T) {
	pool := pool_or_skip(t, 2)
	if pool == nil {
		return
	}
	defer pg.pool_close(pool)

	// Leave a transaction open, release, and verify the next acquire gets
	// an idle (rolled-back) session.
	conn, err := pg.pool_acquire(pool)
	testing.expect_value(t, err, nil)
	_, _ = pg.exec(conn, "BEGIN")
	pg.pool_release(pool, conn)

	conn2, err2 := pg.pool_acquire(pool)
	testing.expect_value(t, err2, nil)
	defer pg.pool_release(pool, conn2)
	res, q_err := pg.query(conn2, "SELECT 1")
	testing.expect_value(t, q_err, nil)
	pg.result_destroy(&res)
}

@(test)
test_pool_exhaustion_timeout :: proc(t: ^testing.T) {
	pool := pool_or_skip(t, 1, 300 * time.Millisecond)
	if pool == nil {
		return
	}
	defer pg.pool_close(pool)

	conn, err := pg.pool_acquire(pool)
	testing.expect_value(t, err, nil)

	started := time.tick_now()
	_, exhausted := pg.pool_acquire(pool)
	waited := time.tick_diff(started, time.tick_now())
	testing.expect_value(t, exhausted, pg.Error(pg.Driver_Error.Pool_Exhausted))
	testing.expect(t, waited >= 250 * time.Millisecond)

	pg.pool_release(pool, conn)
}

@(private = "file")
Stress :: struct {
	pool:     ^pg.Pool,
	failures: int, // atomic
	wg:       sync.Wait_Group,
}

@(test)
test_pool_stress :: proc(t: ^testing.T) {
	pool := pool_or_skip(t, 4)
	if pool == nil {
		return
	}
	defer pg.pool_close(pool)

	WORKERS :: 12
	PER_WORKER :: 25

	stress := Stress {
		pool = pool,
	}
	sync.wait_group_add(&stress.wg, WORKERS)

	workers: [WORKERS]^thread.Thread
	for i in 0 ..< WORKERS {
		workers[i] = thread.create_and_start_with_poly_data(&stress, proc(s: ^Stress) {
			defer sync.wait_group_done(&s.wg)
			for n in 0 ..< PER_WORKER {
				res, err := pg.pool_query(s.pool, "SELECT $1::int8 * 2", n)
				if err != nil {
					sync.atomic_add(&s.failures, 1)
					continue
				}
				v, get_err := pg.get(res.rows[0], i64, 0)
				if get_err != nil || v != i64(n * 2) {
					sync.atomic_add(&s.failures, 1)
				}
				pg.result_destroy(&res)
			}
		})
	}
	sync.wait_group_wait(&stress.wg)
	for w in workers {
		thread.destroy(w)
	}

	testing.expect_value(t, sync.atomic_load(&stress.failures), 0)
	// Invariant: never more connections than max_conns.
	testing.expect(t, pool.total <= 4)
}

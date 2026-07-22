package pg

import "core:mem"
import "core:sync"
import "core:thread"
import "core:time"

Pool_Config :: struct {
	conn_config:           Config,
	min_conns:             int, // pre-warmed/maintained floor; default 0
	max_conns:             int, // default 8
	acquire_timeout:       time.Duration, // default 30s
	max_conn_lifetime:     time.Duration, // default 1h
	max_conn_idle:         time.Duration, // default 15min
	health_check_interval: time.Duration, // reaper cadence; default 30s
	ping_on_acquire_after: time.Duration, // ping conns idle longer than this; default 1min
}

DEFAULT_MAX_CONNS :: 8
DEFAULT_ACQUIRE_TIMEOUT :: 30 * time.Second
DEFAULT_MAX_CONN_LIFETIME :: time.Hour
DEFAULT_MAX_CONN_IDLE :: 15 * time.Minute
DEFAULT_HEALTH_CHECK_INTERVAL :: 30 * time.Second
DEFAULT_PING_AFTER :: time.Minute

// Pool is a thread-safe connection pool. Acquire/release from any thread;
// individual Conns remain single-threaded while checked out.
Pool :: struct {
	mu:          sync.Mutex,
	cond:        sync.Cond, // signaled on release / retire / close
	idle:        [dynamic]^Pooled, // LIFO: cache-warm conns first
	total:       int, // idle + checked out + being created
	closed:      bool,
	cfg:         Pool_Config,
	reaper:      ^thread.Thread,
	reaper_stop: sync.Sema,
	allocator:   mem.Allocator,
}

Pooled :: struct {
	conn:       ^Conn,
	idle_since: time.Tick,
}

pool_create :: proc(cfg: Pool_Config, allocator := context.allocator) -> (pool: ^Pool, err: Error) {
	pool = new(Pool, allocator) or_return
	pool.allocator = allocator
	pool.cfg = cfg
	if pool.cfg.max_conns <= 0 {
		pool.cfg.max_conns = DEFAULT_MAX_CONNS
	}
	if pool.cfg.min_conns < 0 {
		pool.cfg.min_conns = 0
	}
	if pool.cfg.min_conns > pool.cfg.max_conns {
		pool.cfg.min_conns = pool.cfg.max_conns
	}
	if pool.cfg.acquire_timeout == 0 {
		pool.cfg.acquire_timeout = DEFAULT_ACQUIRE_TIMEOUT
	}
	if pool.cfg.max_conn_lifetime == 0 {
		pool.cfg.max_conn_lifetime = DEFAULT_MAX_CONN_LIFETIME
	}
	if pool.cfg.max_conn_idle == 0 {
		pool.cfg.max_conn_idle = DEFAULT_MAX_CONN_IDLE
	}
	if pool.cfg.health_check_interval == 0 {
		pool.cfg.health_check_interval = DEFAULT_HEALTH_CHECK_INTERVAL
	}
	if pool.cfg.ping_on_acquire_after == 0 {
		pool.cfg.ping_on_acquire_after = DEFAULT_PING_AFTER
	}
	pool.idle.allocator = allocator

	// The pool keeps its own copy of the connection config: the pool (and
	// its reaper thread) outlives the caller's Config.
	own_cfg: Config
	if clone_err := config_clone(&own_cfg, cfg.conn_config, allocator); clone_err != nil {
		free(pool, allocator)
		return nil, clone_err
	}
	pool.cfg.conn_config = own_cfg

	// Eagerly satisfy min_conns so startup failures surface immediately.
	for _ in 0 ..< pool.cfg.min_conns {
		conn, conn_err := connect(pool.cfg.conn_config, allocator)
		if conn_err != nil {
			pool_close(pool)
			return nil, conn_err
		}
		pooled := new(Pooled, allocator)
		pooled^ = Pooled {
			conn       = conn,
			idle_since = time.tick_now(),
		}
		append(&pool.idle, pooled)
		pool.total += 1
	}

	pool.reaper = thread.create_and_start_with_poly_data(pool, reaper_main, context)
	return pool, nil
}

// pool_acquire hands out a healthy connection, waiting up to
// acquire_timeout when the pool is at max_conns and everything is checked
// out. Callers must return it with pool_release.
pool_acquire :: proc(pool: ^Pool) -> (conn: ^Conn, err: Error) {
	deadline := time.tick_now()
	remaining := pool.cfg.acquire_timeout

	sync.mutex_lock(&pool.mu)
	for {
		if pool.closed {
			sync.mutex_unlock(&pool.mu)
			return nil, Driver_Error.Pool_Closed
		}

		// 1. Reuse an idle connection (newest first: still cache-warm and
		// its statement cache is hottest).
		if len(pool.idle) > 0 {
			pooled := pop(&pool.idle)
			now := time.tick_now()
			if time.tick_diff(pooled.conn.created_at, now) > pool.cfg.max_conn_lifetime {
				pool.total -= 1
				sync.mutex_unlock(&pool.mu)
				retire(pool, pooled)
				sync.mutex_lock(&pool.mu)
				continue
			}
			needs_ping := time.tick_diff(pooled.idle_since, now) > pool.cfg.ping_on_acquire_after
			sync.mutex_unlock(&pool.mu)
			if needs_ping {
				if ping(pooled.conn) != nil {
					sync.mutex_lock(&pool.mu)
					pool.total -= 1
					sync.cond_signal(&pool.cond)
					sync.mutex_unlock(&pool.mu)
					retire(pool, pooled)
					sync.mutex_lock(&pool.mu)
					continue
				}
			}
			conn = pooled.conn
			free(pooled, pool.allocator)
			return conn, nil
		}

		// 2. Room to grow: create outside the lock (dial + auth is slow).
		if pool.total < pool.cfg.max_conns {
			pool.total += 1
			sync.mutex_unlock(&pool.mu)
			new_conn, conn_err := connect(pool.cfg.conn_config, pool.allocator)
			if conn_err != nil {
				sync.mutex_lock(&pool.mu)
				pool.total -= 1
				sync.cond_signal(&pool.cond)
				sync.mutex_unlock(&pool.mu)
				return nil, conn_err
			}
			sync.mutex_lock(&pool.mu)
			if pool.closed {
				pool.total -= 1
				sync.mutex_unlock(&pool.mu)
				conn_close(new_conn)
				return nil, Driver_Error.Pool_Closed
			}
			sync.mutex_unlock(&pool.mu)
			return new_conn, nil
		}

		// 3. Saturated: wait for a release.
		elapsed := time.tick_diff(deadline, time.tick_now())
		remaining = pool.cfg.acquire_timeout - elapsed
		if remaining <= 0 || !sync.cond_wait_with_timeout(&pool.cond, &pool.mu, remaining) {
			sync.mutex_unlock(&pool.mu)
			return nil, Driver_Error.Pool_Exhausted
		}
	}
}

// pool_release returns a connection. Broken connections are destroyed;
// healthy ones are reset (open transactions rolled back, pending
// notifications cleared) and go back on the idle stack.
pool_release :: proc(pool: ^Pool, conn: ^Conn) {
	if conn == nil {
		return
	}

	healthy := conn.status == .Ok
	if healthy && conn.txn_status != .Idle {
		if _, rollback_err := conn_exec(conn, "ROLLBACK"); rollback_err != nil {
			healthy = false
		}
	}
	if healthy {
		clear_notifications(conn)
	}

	sync.mutex_lock(&pool.mu)
	if !healthy || pool.closed {
		pool.total -= 1
		sync.cond_signal(&pool.cond)
		sync.mutex_unlock(&pool.mu)
		conn_close(conn)
		return
	}
	pooled := new(Pooled, pool.allocator)
	pooled^ = Pooled {
		conn       = conn,
		idle_since = time.tick_now(),
	}
	append(&pool.idle, pooled)
	sync.cond_signal(&pool.cond)
	sync.mutex_unlock(&pool.mu)
}

pool_close :: proc(pool: ^Pool) {
	if pool == nil {
		return
	}
	sync.mutex_lock(&pool.mu)
	if pool.closed {
		sync.mutex_unlock(&pool.mu)
		return
	}
	pool.closed = true
	sync.mutex_unlock(&pool.mu)

	if pool.reaper != nil {
		sync.sema_post(&pool.reaper_stop)
		thread.join(pool.reaper)
		thread.destroy(pool.reaper)
		pool.reaper = nil
	}

	sync.mutex_lock(&pool.mu)
	for len(pool.idle) > 0 {
		pooled := pop(&pool.idle)
		pool.total -= 1
		sync.mutex_unlock(&pool.mu)
		retire(pool, pooled)
		sync.mutex_lock(&pool.mu)
	}
	sync.cond_broadcast(&pool.cond)
	// Wait for checked-out connections to come home via pool_release.
	for pool.total > 0 {
		sync.cond_wait_with_timeout(&pool.cond, &pool.mu, time.Second)
	}
	sync.mutex_unlock(&pool.mu)

	delete(pool.idle)
	config_destroy(&pool.cfg.conn_config)
	free(pool, pool.allocator)
}

// Passthroughs: acquire → run → release. Safe because a Result owns its
// memory independently of the connection.
pool_exec :: proc(pool: ^Pool, sql: string, args: ..any) -> (tag: Command_Tag, err: Error) {
	conn := pool_acquire(pool) or_return
	defer pool_release(pool, conn)
	tag, err = conn_exec(conn, sql, ..args)
	if err == nil {
		// The tag string borrows the conn's error arena; copy to temp so it
		// survives the release.
		tag.tag, _ = clone_to_temp(tag.tag)
	}
	return tag, err
}

pool_query :: proc(pool: ^Pool, sql: string, args: ..any) -> (res: Result, err: Error) {
	conn := pool_acquire(pool) or_return
	defer pool_release(pool, conn)
	return conn_query(conn, sql, ..args)
}

pool_query_row :: proc(pool: ^Pool, sql: string, args: ..any) -> (res: Result, err: Error) {
	conn := pool_acquire(pool) or_return
	defer pool_release(pool, conn)
	return conn_query_row(conn, sql, ..args)
}

@(private = "file")
clone_to_temp :: proc(s: string) -> (out: string, err: mem.Allocator_Error) {
	buf := make([]byte, len(s), context.temp_allocator) or_return
	copy(buf, s)
	return string(buf), nil
}

@(private = "file")
retire :: proc(pool: ^Pool, pooled: ^Pooled) {
	conn_close(pooled.conn)
	free(pooled, pool.allocator)
}

// reaper_main wakes every health_check_interval to retire idle connections
// past max_conn_idle / max_conn_lifetime (keeping min_conns) and to top the
// pool back up to min_conns. A sema post means "shut down".
@(private = "file")
reaper_main :: proc(pool: ^Pool) {
	for {
		if sync.sema_wait_with_timeout(&pool.reaper_stop, pool.cfg.health_check_interval) {
			return // shutdown
		}

		// Retire expired idle connections.
		now := time.tick_now()
		expired := make([dynamic]^Pooled, context.temp_allocator)
		sync.mutex_lock(&pool.mu)
		if pool.closed {
			sync.mutex_unlock(&pool.mu)
			return
		}
		for i := 0; i < len(pool.idle); {
			pooled := pool.idle[i]
			too_idle := time.tick_diff(pooled.idle_since, now) > pool.cfg.max_conn_idle
			too_old := time.tick_diff(pooled.conn.created_at, now) > pool.cfg.max_conn_lifetime
			if (too_idle || too_old) && pool.total > pool.cfg.min_conns {
				append(&expired, pooled)
				ordered_remove(&pool.idle, i)
				pool.total -= 1
				sync.cond_signal(&pool.cond)
			} else {
				i += 1
			}
		}
		missing := pool.cfg.min_conns - pool.total
		if missing > 0 {
			pool.total += missing // reserve before connecting outside the lock
		}
		sync.mutex_unlock(&pool.mu)

		for pooled in expired {
			retire(pool, pooled)
		}

		// Top up to min_conns.
		for _ in 0 ..< missing {
			conn, err := connect(pool.cfg.conn_config, pool.allocator)
			sync.mutex_lock(&pool.mu)
			if err != nil || pool.closed {
				pool.total -= 1
				sync.cond_signal(&pool.cond)
				sync.mutex_unlock(&pool.mu)
				if conn != nil {
					conn_close(conn)
				}
				continue
			}
			pooled := new(Pooled, pool.allocator)
			pooled^ = Pooled {
				conn       = conn,
				idle_since = time.tick_now(),
			}
			append(&pool.idle, pooled)
			sync.cond_signal(&pool.cond)
			sync.mutex_unlock(&pool.mu)
		}

		free_all(context.temp_allocator)
	}
}

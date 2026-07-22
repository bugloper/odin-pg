// Integration tests: exercise the public pg API against live PostgreSQL
// servers (tests/docker-compose.yml). Each test is gated on its server's
// DSN environment variable and silently passes when unset, so `odin test`
// still works without Docker:
//
//	docker compose -f tests/docker-compose.yml up -d --wait
//	PG_TEST_DSN="postgres://odin:odin_pg_test@localhost:5432/odin_pg_test" \
//	PG_TEST_DSN_MD5="postgres://odin:odin_pg_test@localhost:5434/odin_pg_test" \
//	  odin test tests/integration
package pg_integration_tests

import "core:log"
import "core:os"
import "core:testing"

import pg "../.."

@(private)
dsn_from_env :: proc(t: ^testing.T, name: string) -> (dsn: string, ok: bool) {
	dsn = os.get_env(name, context.temp_allocator)
	if dsn == "" {
		log.warnf("%s not set; skipping integration test", name)
		return "", false
	}
	return dsn, true
}

@(test)
test_connect_scram :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000) // 30s
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}

	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "connect failed: %v", err)
	if err != nil {
		return
	}
	defer pg.conn_close(conn)

	testing.expect(t, pg.backend_pid(conn) > 0)
	version, has_version := pg.server_parameter(conn, "server_version")
	testing.expect(t, has_version)
	testing.expectf(t, len(version) > 0, "empty server_version")
	encoding, _ := pg.server_parameter(conn, "client_encoding")
	testing.expect_value(t, encoding, "UTF8")

	ping_err := pg.ping(conn)
	testing.expectf(t, ping_err == nil, "ping failed: %v", ping_err)
}

@(test)
test_connect_md5 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN_MD5")
	if !ok {
		return
	}

	conn, err := pg.connect_dsn(dsn)
	testing.expectf(t, err == nil, "md5 connect failed: %v", err)
	if err != nil {
		return
	}
	defer pg.conn_close(conn)
	testing.expect_value(t, pg.ping(conn), nil)
}

@(test)
test_connect_bad_password :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}

	parsed, parse_err := pg.parse_dsn(dsn)
	testing.expect_value(t, parse_err, nil)
	defer pg.config_destroy(&parsed)

	// Hand-built config borrowing the parsed fields (connect copies what it
	// keeps); hand-built configs are not config_destroy'd.
	cfg := parsed
	cfg.allocator = {}
	cfg.password = "wrong_password"

	conn, err := pg.connect(cfg)
	testing.expect(t, conn == nil)
	se, is_server_err := err.(^pg.Server_Error)
	testing.expectf(t, is_server_err, "expected server error, got: %v", err)
	if is_server_err {
		// 28P01 invalid_password
		testing.expect_value(t, string(se.code[:]), "28P01")
		pg.server_error_destroy(se)
	}
}

@(test)
test_connect_bad_database :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30_000_000_000)
	dsn, ok := dsn_from_env(t, "PG_TEST_DSN")
	if !ok {
		return
	}

	parsed, parse_err := pg.parse_dsn(dsn)
	testing.expect_value(t, parse_err, nil)
	defer pg.config_destroy(&parsed)

	cfg := parsed
	cfg.allocator = {}
	cfg.database = "no_such_db"

	conn, err := pg.connect(cfg)
	testing.expect(t, conn == nil)
	se, is_server_err := err.(^pg.Server_Error)
	testing.expectf(t, is_server_err, "expected server error, got: %v", err)
	if is_server_err {
		// 3D000 invalid_catalog_name
		testing.expect_value(t, string(se.code[:]), "3D000")
		pg.server_error_destroy(se)
	}
}

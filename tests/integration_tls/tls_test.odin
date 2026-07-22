// TLS integration tests. This package is separate from tests/integration so
// that suite never links OpenSSL — which is itself the property under test:
// importing odin-pg/openssl is what opts a binary into libssl.
//
//	docker compose -f tests/docker-compose.yml up -d --wait pg-tls
//	docker compose -f tests/docker-compose.yml exec pg-tls \
//	  cat /var/lib/postgresql/server.crt > /tmp/odin-pg-server.crt
//	PG_TEST_DSN_TLS="postgres://odin:odin_pg_test@localhost:5436/odin_pg_test" \
//	PG_TEST_TLS_CERT=/tmp/odin-pg-server.crt \
//	  odin test tests/integration_tls
package pg_integration_tls_tests

import "core:log"
import "core:os"
import "core:testing"

import pg "../.."
import pg_ssl "../../openssl"

@(private)
tls_env :: proc(t: ^testing.T) -> (dsn: string, ok: bool) {
	testing.set_fail_timeout(t, 60_000_000_000)
	dsn = os.get_env("PG_TEST_DSN_TLS", context.temp_allocator)
	if dsn == "" {
		log.warn("PG_TEST_DSN_TLS not set; skipping TLS integration test")
		return "", false
	}
	return dsn, true
}

@(test)
test_tls_require :: proc(t: ^testing.T) {
	dsn, ok := tls_env(t)
	if !ok {
		return
	}

	parsed, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&parsed)
	cfg := parsed
	cfg.allocator = {}
	cfg.tls = pg_ssl.tls_config(.Require)

	conn, conn_err := pg.connect(cfg)
	testing.expectf(t, conn_err == nil, "TLS connect failed: %v", conn_err)
	if conn_err != nil {
		return
	}
	defer pg.conn_close(conn)

	// Full query flow over the encrypted stream, and the server must agree
	// this session uses SSL.
	res, q_err := pg.query(conn, "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
	testing.expect_value(t, q_err, nil)
	defer pg.result_destroy(&res)
	ssl_active, _ := pg.row_text(res.rows[0], 0)
	testing.expect_value(t, ssl_active, "t")
	tls_version, _ := pg.row_text(res.rows[0], 1)
	testing.expectf(t, len(tls_version) > 0, "no TLS version reported")
	log.infof("TLS session established: %s", tls_version)
}

@(test)
test_tls_verify_full_untrusted_fails :: proc(t: ^testing.T) {
	dsn, ok := tls_env(t)
	if !ok {
		return
	}

	parsed, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&parsed)
	cfg := parsed
	cfg.allocator = {}
	// Self-signed server cert + system trust store: must be rejected.
	cfg.tls = pg_ssl.tls_config(.Verify_Full)

	conn, conn_err := pg.connect(cfg)
	testing.expect(t, conn == nil)
	testing.expect_value(t, conn_err, pg.Error(pg.Driver_Error.TLS_Failed))
}

@(test)
test_tls_verify_full_with_pinned_cert :: proc(t: ^testing.T) {
	dsn, ok := tls_env(t)
	if !ok {
		return
	}
	cert := os.get_env("PG_TEST_TLS_CERT", context.temp_allocator)
	if cert == "" {
		log.warn("PG_TEST_TLS_CERT not set; skipping verify-full success test")
		return
	}

	parsed, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&parsed)
	cfg := parsed
	cfg.allocator = {}
	cfg.tls = pg_ssl.tls_config(.Verify_Full, ca_file = cert)

	conn, conn_err := pg.connect(cfg)
	testing.expectf(t, conn_err == nil, "verify-full connect failed: %v", conn_err)
	if conn_err != nil {
		return
	}
	defer pg.conn_close(conn)
	testing.expect_value(t, pg.ping(conn), nil)
}

@(test)
test_tls_not_available_without_factory :: proc(t: ^testing.T) {
	dsn, ok := tls_env(t)
	if !ok {
		return
	}

	parsed, err := pg.parse_dsn(dsn)
	testing.expect_value(t, err, nil)
	defer pg.config_destroy(&parsed)
	cfg := parsed
	cfg.allocator = {}
	cfg.tls.mode = .Require
	cfg.tls.factory = nil

	conn, conn_err := pg.connect(cfg)
	testing.expect(t, conn == nil)
	testing.expect_value(t, conn_err, pg.Error(pg.Driver_Error.TLS_Not_Available))
}

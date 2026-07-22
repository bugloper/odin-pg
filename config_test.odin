package pg

import "core:testing"
import "core:time"

@(test)
test_parse_dsn_url :: proc(t: ^testing.T) {
	cfg, err := parse_dsn("postgres://alice:s%40cret@db.example.com:5433/app?sslmode=verify-full&connect_timeout=5&search_path=public")
	testing.expect_value(t, err, nil)
	defer config_destroy(&cfg)

	testing.expect_value(t, cfg.host, "db.example.com")
	testing.expect_value(t, cfg.port, 5433)
	testing.expect_value(t, cfg.user, "alice")
	testing.expect_value(t, cfg.password, "s@cret")
	testing.expect_value(t, cfg.database, "app")
	testing.expect_value(t, cfg.tls.mode, TLS_Mode.Verify_Full)
	testing.expect_value(t, cfg.connect_timeout, 5 * time.Second)
	testing.expect_value(t, cfg.runtime_params["search_path"], "public")
}

@(test)
test_parse_dsn_url_minimal :: proc(t: ^testing.T) {
	cfg, err := parse_dsn("postgresql://localhost")
	testing.expect_value(t, err, nil)
	defer config_destroy(&cfg)

	testing.expect_value(t, cfg.host, "localhost")
	testing.expect_value(t, cfg.port, 0) // default applied at connect time
	testing.expect_value(t, cfg.user, "")
	testing.expect_value(t, cfg.tls.mode, TLS_Mode.Disable)
}

@(test)
test_parse_dsn_kv :: proc(t: ^testing.T) {
	cfg, err := parse_dsn("host=localhost port=5432 user=odin password=odin_pg_test dbname=odin_pg_test sslmode=prefer")
	testing.expect_value(t, err, nil)
	defer config_destroy(&cfg)

	testing.expect_value(t, cfg.host, "localhost")
	testing.expect_value(t, cfg.port, 5432)
	testing.expect_value(t, cfg.user, "odin")
	testing.expect_value(t, cfg.password, "odin_pg_test")
	testing.expect_value(t, cfg.database, "odin_pg_test")
	testing.expect_value(t, cfg.tls.mode, TLS_Mode.Prefer)
}

@(test)
test_parse_dsn_invalid :: proc(t: ^testing.T) {
	bad := []string{
		"",
		"postgres://host:notaport/db",
		"postgres://host:99999/db",
		"host=localhost sslmode=bogus",
		"host=localhost =oops",
		"postgres://h?keynovalue",
	}
	for dsn in bad {
		cfg, err := parse_dsn(dsn)
		testing.expectf(t, err != nil, "expected error for %q", dsn)
		config_destroy(&cfg)
	}
}

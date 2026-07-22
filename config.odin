package pg

import "core:mem"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:time"

TLS_Mode :: enum u8 {
	Disable,
	Prefer,
	Require,
	Verify_CA,
	Verify_Full,
}

// TLS_Stream_Factory upgrades a connected socket to TLS. The core package
// never provides one — importing the odin-pg/openssl subpackage (or any
// user implementation) and assigning it to TLS_Config.factory is what makes
// TLS available, which also makes libssl linkage strictly opt-in.
TLS_Stream_Factory :: #type proc(
	socket: net.TCP_Socket,
	cfg: ^TLS_Config,
	server_name: string,
) -> (
	stream: Stream,
	err: Error,
)

TLS_Config :: struct {
	mode:        TLS_Mode,
	factory:     TLS_Stream_Factory,
	ca_file:     string,
	cert_file:   string, // client certificate auth
	key_file:    string,
	server_name: string, // SNI/verification override; defaults to Config.host
}

Config :: struct {
	host:                 string, // TCP only in v1
	port:                 int, // 0 -> 5432
	user:                 string,
	password:             string,
	database:             string, // "" -> same as user
	app_name:             string,
	runtime_params:       map[string]string, // extra StartupMessage parameters
	connect_timeout:      time.Duration, // 0 -> 10s
	read_timeout:         time.Duration, // per-recv deadline; 0 = none
	write_timeout:        time.Duration,
	tcp_keep_alive:       bool, // set by default_config
	tls:                  TLS_Config,
	allow_cleartext_auth: bool, // refuse AuthenticationCleartextPassword unless true or TLS active
	statement_cache_size: int, // 0 -> 128; negative disables automatic caching

	// Set by parse_dsn so config_destroy frees with the right allocator;
	// zero for hand-built configs (whose strings we don't own).
	allocator:            mem.Allocator,
}

DEFAULT_PORT :: 5432
DEFAULT_CONNECT_TIMEOUT :: 10 * time.Second
DEFAULT_STATEMENT_CACHE_SIZE :: 128

default_config :: proc() -> Config {
	return Config{tcp_keep_alive = true}
}

// parse_dsn accepts both URL DSNs
//
//	postgres://user:pass@host:5432/db?sslmode=require&connect_timeout=10
//
// and keyword/value DSNs
//
//	host=localhost port=5432 user=alice dbname=app sslmode=disable
//
// Every string in the returned Config is a copy owned by allocator; release
// with config_destroy. (Do not call config_destroy on hand-built configs
// whose strings you don't own.)
parse_dsn :: proc(dsn: string, allocator := context.allocator) -> (cfg: Config, err: Error) {
	cfg = default_config()
	cfg.allocator = allocator
	cfg.runtime_params.allocator = allocator

	trimmed := strings.trim_space(dsn)
	if trimmed == "" {
		return cfg, Driver_Error.Invalid_DSN
	}

	if strings.has_prefix(trimmed, "postgres://") || strings.has_prefix(trimmed, "postgresql://") {
		err = parse_url_dsn(&cfg, trimmed, allocator)
	} else {
		err = parse_kv_dsn(&cfg, trimmed, allocator)
	}
	if err != nil {
		// Not a defer: Odin defers run after the return values are copied,
		// so cleanup must happen inline to hand back a zeroed Config.
		config_destroy(&cfg)
		return {}, err
	}
	return cfg, nil
}

// config_destroy releases a Config produced by parse_dsn. It is a no-op for
// hand-built configs (which own no allocations).
config_destroy :: proc(cfg: ^Config) {
	if cfg.allocator.procedure == nil {
		cfg^ = {}
		return
	}
	allocator := cfg.allocator
	delete(cfg.host, allocator)
	delete(cfg.user, allocator)
	delete(cfg.password, allocator)
	delete(cfg.database, allocator)
	delete(cfg.app_name, allocator)
	delete(cfg.tls.ca_file, allocator)
	delete(cfg.tls.cert_file, allocator)
	delete(cfg.tls.key_file, allocator)
	delete(cfg.tls.server_name, allocator)
	for key, value in cfg.runtime_params {
		delete(key, allocator)
		delete(value, allocator)
	}
	delete(cfg.runtime_params)
	cfg^ = {}
}

@(private = "file")
parse_url_dsn :: proc(cfg: ^Config, dsn: string, allocator: mem.Allocator) -> Error {
	rest := dsn[strings.index(dsn, "://") + 3:]

	// Split off ?query first.
	query := ""
	if q := strings.index_byte(rest, '?'); q >= 0 {
		query = rest[q + 1:]
		rest = rest[:q]
	}

	// userinfo@
	if at := strings.last_index_byte(rest, '@'); at >= 0 {
		userinfo := rest[:at]
		rest = rest[at + 1:]
		if colon := strings.index_byte(userinfo, ':'); colon >= 0 {
			set_decoded(&cfg.user, userinfo[:colon], allocator) or_return
			set_decoded(&cfg.password, userinfo[colon + 1:], allocator) or_return
		} else {
			set_decoded(&cfg.user, userinfo, allocator) or_return
		}
	}

	// /database
	if slash := strings.index_byte(rest, '/'); slash >= 0 {
		set_decoded(&cfg.database, rest[slash + 1:], allocator) or_return
		rest = rest[:slash]
	}

	// host[:port] — no IPv6 bracket syntax in v1.
	if colon := strings.last_index_byte(rest, ':'); colon >= 0 {
		port, ok := strconv.parse_int(rest[colon + 1:])
		if !ok || port <= 0 || port > 65535 {
			return Driver_Error.Invalid_DSN
		}
		cfg.port = port
		rest = rest[:colon]
	}
	set_decoded(&cfg.host, rest, allocator) or_return

	// Query parameters.
	for query != "" {
		pair := query
		if amp := strings.index_byte(query, '&'); amp >= 0 {
			pair = query[:amp]
			query = query[amp + 1:]
		} else {
			query = ""
		}
		if pair == "" {
			continue
		}
		eq := strings.index_byte(pair, '=')
		if eq < 0 {
			return Driver_Error.Invalid_DSN
		}
		apply_param(cfg, pair[:eq], pair[eq + 1:], allocator) or_return
	}
	return nil
}

@(private = "file")
parse_kv_dsn :: proc(cfg: ^Config, dsn: string, allocator: mem.Allocator) -> Error {
	rest := dsn
	for rest != "" {
		rest = strings.trim_left_space(rest)
		if rest == "" {
			break
		}
		token := rest
		if sp := strings.index_byte(rest, ' '); sp >= 0 {
			token = rest[:sp]
			rest = rest[sp + 1:]
		} else {
			rest = ""
		}
		eq := strings.index_byte(token, '=')
		if eq <= 0 {
			return Driver_Error.Invalid_DSN
		}
		key := token[:eq]
		value := token[eq + 1:]
		if key == "dbname" {
			key = "database"
		}
		apply_param(cfg, key, value, allocator) or_return
	}
	return nil
}

// apply_param routes one DSN parameter (URL query key or kv key) into the
// config; unknown keys become StartupMessage runtime parameters.
@(private = "file")
apply_param :: proc(cfg: ^Config, key, raw_value: string, allocator: mem.Allocator) -> Error {
	value, decode_ok := net.percent_decode(raw_value, context.temp_allocator)
	if !decode_ok {
		return Driver_Error.Invalid_DSN
	}

	switch key {
	case "host":
		return set_string(&cfg.host, value, allocator)
	case "port":
		port, ok := strconv.parse_int(value)
		if !ok || port <= 0 || port > 65535 {
			return Driver_Error.Invalid_DSN
		}
		cfg.port = port
	case "user":
		return set_string(&cfg.user, value, allocator)
	case "password":
		return set_string(&cfg.password, value, allocator)
	case "database":
		return set_string(&cfg.database, value, allocator)
	case "application_name":
		return set_string(&cfg.app_name, value, allocator)
	case "connect_timeout":
		seconds, ok := strconv.parse_int(value)
		if !ok || seconds < 0 {
			return Driver_Error.Invalid_DSN
		}
		cfg.connect_timeout = time.Duration(seconds) * time.Second
	case "sslmode":
		switch value {
		case "disable":
			cfg.tls.mode = .Disable
		case "allow", "prefer":
			cfg.tls.mode = .Prefer
		case "require":
			cfg.tls.mode = .Require
		case "verify-ca":
			cfg.tls.mode = .Verify_CA
		case "verify-full":
			cfg.tls.mode = .Verify_Full
		case:
			return Driver_Error.Invalid_DSN
		}
	case "sslrootcert":
		return set_string(&cfg.tls.ca_file, value, allocator)
	case "sslcert":
		return set_string(&cfg.tls.cert_file, value, allocator)
	case "sslkey":
		return set_string(&cfg.tls.key_file, value, allocator)
	case:
		key_copy := strings.clone(key, allocator) or_return
		value_copy := strings.clone(value, allocator) or_return
		cfg.runtime_params[key_copy] = value_copy
	}
	return nil
}

@(private = "file")
set_string :: proc(dst: ^string, value: string, allocator: mem.Allocator) -> Error {
	delete(dst^, allocator)
	dst^ = strings.clone(value, allocator) or_return
	return nil
}

// set_decoded percent-decodes a URL component before storing it.
@(private = "file")
set_decoded :: proc(dst: ^string, raw: string, allocator: mem.Allocator) -> Error {
	value, ok := net.percent_decode(raw, context.temp_allocator)
	if !ok {
		return Driver_Error.Invalid_DSN
	}
	return set_string(dst, value, allocator)
}

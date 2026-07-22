package pg

// Adversarial-input tests: every backend parser must reject arbitrary bytes
// with ok=false or a clean error — never a panic or out-of-bounds access.
// The test runner seeds core:math/rand per test (override with
// -define:ODIN_TEST_RANDOM_SEED=n to reproduce a failure).

import "core:math/rand"
import "core:testing"

@(test)
test_fuzz_backend_parsers :: proc(t: ^testing.T) {
	fields := make([dynamic]Field, context.temp_allocator)
	spans := make([dynamic]Cell_Span, context.temp_allocator)
	oids := make([dynamic]Oid, context.temp_allocator)
	formats := make([dynamic]Format, context.temp_allocator)
	buf: [512]u8

	for _ in 0 ..< 20_000 {
		n := rand.int_max(len(buf) + 1)
		body := buf[:n]
		for i in 0 ..< n {
			body[i] = u8(rand.int_max(256))
		}

		_, _, _ = parse_auth(body)
		_, _, _ = parse_backend_key_data(body)
		_, _ = parse_ready_for_query(body)
		_, _, _ = parse_parameter_status(body)
		_ = parse_row_description(body, &fields)
		_ = parse_data_row(body, &spans)
		_, _ = parse_command_complete(body)
		_, _ = parse_error_fields(body)
		_, _, _, _ = parse_notification(body)
		_, _ = parse_copy_response(body, &formats)
		_ = parse_parameter_description(body, &oids)
		_, _, _ = parse_negotiate_protocol_version(body)
	}
}

@(test)
test_fuzz_scram_server_messages :: proc(t: ^testing.T) {
	buf: [256]u8
	for _ in 0 ..< 5_000 {
		n := rand.int_max(len(buf) + 1)
		msg := buf[:n]
		for i in 0 ..< n {
			msg[i] = u8(rand.int_max(256))
		}

		s: Scram
		scram_init(&s)
		_, _ = scram_client_first(&s)
		if _, err := scram_handle_server_first(&s, msg, "password"); err == nil {
			_ = scram_handle_server_final(&s, msg)
		}
		scram_destroy(&s)
	}
}

@(test)
test_fuzz_dsn_parser :: proc(t: ^testing.T) {
	buf: [128]u8
	for _ in 0 ..< 5_000 {
		n := rand.int_max(len(buf) + 1)
		for i in 0 ..< n {
			buf[i] = u8(rand.int_max(128)) // ASCII-ish, more parser paths hit
		}
		cfg, err := parse_dsn(string(buf[:n]), context.temp_allocator)
		if err == nil {
			config_destroy(&cfg)
		}
	}
}

@(test)
test_fuzz_array_and_numeric_text :: proc(t: ^testing.T) {
	field := Field {
		type_oid = TEXT_ARRAY,
	}
	buf: [128]u8
	chars := "{}\",\\N U L0123456789.-"
	for _ in 0 ..< 10_000 {
		n := rand.int_max(len(buf) + 1)
		for i in 0 ..< n {
			buf[i] = chars[rand.int_max(len(chars))]
		}
		_, arr_err := decode_array([]Maybe(string), buf[:n], field, false, context.temp_allocator)
		_ = arr_err
		_, num_err := parse_numeric_text(string(buf[:n]), context.temp_allocator)
		_ = num_err
		_, ts_err := parse_timestamp_text(string(buf[:n]))
		_ = ts_err
	}
}

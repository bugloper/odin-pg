package pg

// SCRAM-SHA-256 client state machine (RFC 5802 / RFC 7677), free of any I/O
// so it is testable against the RFC vectors. The connection layer shuttles
// its messages inside SASLInitialResponse / SASLResponse and feeds back the
// server's AuthenticationSASLContinue / AuthenticationSASLFinal payloads.
//
// Channel binding: we advertise "n,," (no channel binding); the
// SCRAM-SHA-256-PLUS mechanism is not offered in v1.

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:crypto/pbkdf2"
import "core:encoding/base64"
import "core:mem"
import "core:strconv"

// Minimum iteration count we accept from the server; RFC 7677 mandates at
// least 4096 and a lower value indicates a downgrade attack or a
// misconfigured server.
SCRAM_MIN_ITERATIONS :: 4096

@(private)
GS2_HEADER :: "n,,"
// base64("n,,") — the c= attribute of client-final when not channel-binding.
@(private)
GS2_HEADER_B64 :: "biws"

Scram :: struct {
	state:             Scram_State,
	allocator:         mem.Allocator,
	nonce:             [dynamic]u8, // our nonce (printable ASCII)
	client_first_bare: [dynamic]u8, // kept for AuthMessage
	server_first:      [dynamic]u8, // kept for AuthMessage
	out:               [dynamic]u8, // message returned to the caller
	salted_password:   [32]u8,
	server_signature:  [32]u8,
}

Scram_State :: enum u8 {
	Initial,
	Awaiting_Server_First,
	Awaiting_Server_Final,
	Done,
	Failed,
}

// scram_init prepares the state machine. test_nonce overrides the random
// client nonce and exists only so unit tests can drive the RFC vectors.
scram_init :: proc(s: ^Scram, allocator := context.allocator, test_nonce := "") {
	s.state = .Initial
	s.allocator = allocator
	s.nonce = make([dynamic]u8, 0, 32, allocator)
	s.client_first_bare = make([dynamic]u8, 0, 64, allocator)
	s.server_first = make([dynamic]u8, 0, 128, allocator)
	s.out = make([dynamic]u8, 0, 256, allocator)

	if test_nonce != "" {
		append(&s.nonce, test_nonce)
	} else {
		raw: [18]u8
		crypto.rand_bytes(raw[:])
		resize(&s.nonce, base64.encoded_len(raw[:]))
		_, _ = base64.encode_into_buf(s.nonce[:], raw[:])
	}
}

scram_destroy :: proc(s: ^Scram) {
	delete(s.nonce)
	delete(s.client_first_bare)
	delete(s.server_first)
	delete(s.out)
	mem.zero_explicit(&s.salted_password, size_of(s.salted_password))
	s^ = {}
}

// scram_client_first returns the SASLInitialResponse payload:
// "n,,n=,r=<nonce>". The username is left empty per PostgreSQL convention
// (the server takes it from the startup message).
scram_client_first :: proc(s: ^Scram) -> (msg: []byte, err: Error) {
	if s.state != .Initial {
		s.state = .Failed
		return nil, Driver_Error.Protocol_Error
	}
	clear(&s.client_first_bare)
	append(&s.client_first_bare, "n=,r=")
	append(&s.client_first_bare, ..s.nonce[:])

	clear(&s.out)
	append(&s.out, GS2_HEADER)
	append(&s.out, ..s.client_first_bare[:])
	s.state = .Awaiting_Server_First
	return s.out[:], nil
}

// scram_handle_server_first consumes the AuthenticationSASLContinue payload
// ("r=…,s=…,i=…") and returns the client-final message with the proof.
scram_handle_server_first :: proc(
	s: ^Scram,
	server_first: []byte,
	password: string,
) -> (
	client_final: []byte,
	err: Error,
) {
	if s.state != .Awaiting_Server_First {
		s.state = .Failed
		return nil, Driver_Error.Protocol_Error
	}
	s.state = .Failed // upgraded back to .Awaiting_Server_Final on success

	combined_nonce, salt_b64, iter_str: string
	ok: bool
	if combined_nonce, ok = scram_attr(string(server_first), 'r'); !ok {
		return nil, Driver_Error.Protocol_Error
	}
	if salt_b64, ok = scram_attr(string(server_first), 's'); !ok {
		return nil, Driver_Error.Protocol_Error
	}
	if iter_str, ok = scram_attr(string(server_first), 'i'); !ok {
		return nil, Driver_Error.Protocol_Error
	}

	// The server's nonce must extend ours, and iterations must not be
	// suspiciously low.
	if len(combined_nonce) <= len(s.nonce) ||
	   string(combined_nonce[:len(s.nonce)]) != string(s.nonce[:]) {
		return nil, Driver_Error.Auth_Failed
	}
	iterations, iter_ok := strconv.parse_uint(iter_str)
	if !iter_ok || iterations < SCRAM_MIN_ITERATIONS || iterations > 1 << 24 {
		return nil, Driver_Error.Auth_Failed
	}

	salt, salt_err := base64.decode(salt_b64, allocator = s.allocator)
	if salt_err != nil {
		return nil, Driver_Error.Protocol_Error
	}
	defer delete(salt, s.allocator)

	// Keep a copy of server-first for the AuthMessage.
	clear(&s.server_first)
	append(&s.server_first, ..server_first)

	pbkdf2.derive(.SHA256, transmute([]byte)password, salt, u32(iterations), s.salted_password[:])

	client_key: [32]u8
	hmac.sum(.SHA256, client_key[:], transmute([]byte)string("Client Key"), s.salted_password[:])
	stored_key: [32]u8
	hash.hash_bytes_to_buffer(.SHA256, client_key[:], stored_key[:])

	// client-final-without-proof.
	clear(&s.out)
	append(&s.out, "c=")
	append(&s.out, GS2_HEADER_B64)
	append(&s.out, ",r=")
	append(&s.out, combined_nonce)

	// AuthMessage = client-first-bare , server-first , client-final-without-proof.
	auth_message := make(
		[dynamic]u8,
		0,
		len(s.client_first_bare) + len(s.server_first) + len(s.out) + 2,
		s.allocator,
	)
	defer delete(auth_message)
	append(&auth_message, ..s.client_first_bare[:])
	append(&auth_message, ',')
	append(&auth_message, ..s.server_first[:])
	append(&auth_message, ',')
	append(&auth_message, ..s.out[:])

	client_signature: [32]u8
	hmac.sum(.SHA256, client_signature[:], auth_message[:], stored_key[:])
	proof: [32]u8
	for i in 0 ..< 32 {
		proof[i] = client_key[i] ~ client_signature[i]
	}

	server_key: [32]u8
	hmac.sum(.SHA256, server_key[:], transmute([]byte)string("Server Key"), s.salted_password[:])
	hmac.sum(.SHA256, s.server_signature[:], auth_message[:], server_key[:])

	mem.zero_explicit(&client_key, size_of(client_key))
	mem.zero_explicit(&stored_key, size_of(stored_key))
	mem.zero_explicit(&server_key, size_of(server_key))

	append(&s.out, ",p=")
	proof_off := len(s.out)
	resize(&s.out, proof_off + base64.encoded_len(proof[:]))
	_, _ = base64.encode_into_buf(s.out[proof_off:], proof[:])

	s.state = .Awaiting_Server_Final
	return s.out[:], nil
}

// scram_handle_server_final consumes the AuthenticationSASLFinal payload
// ("v=…") and authenticates the *server* by checking its signature.
scram_handle_server_final :: proc(s: ^Scram, server_final: []byte) -> Error {
	if s.state != .Awaiting_Server_Final {
		s.state = .Failed
		return Driver_Error.Protocol_Error
	}
	s.state = .Failed

	if v, has_err := scram_attr(string(server_final), 'e'); has_err {
		_ = v
		return Driver_Error.Auth_Failed
	}
	v_b64, ok := scram_attr(string(server_final), 'v')
	if !ok {
		return Driver_Error.Protocol_Error
	}
	sig, sig_err := base64.decode(v_b64, allocator = s.allocator)
	if sig_err != nil {
		return Driver_Error.Protocol_Error
	}
	defer delete(sig, s.allocator)

	if crypto.compare_constant_time(sig, s.server_signature[:]) != 1 {
		return Driver_Error.Auth_Failed
	}
	s.state = .Done
	return nil
}

// scram_attr finds a "x=value" attribute in a comma-separated SCRAM message
// and returns its value.
@(private)
scram_attr :: proc(msg: string, name: u8) -> (value: string, ok: bool) {
	rest := msg
	for len(rest) > 0 {
		attr := rest
		if comma := index_byte(rest, ','); comma >= 0 {
			attr = rest[:comma]
			rest = rest[comma + 1:]
		} else {
			rest = ""
		}
		if len(attr) >= 2 && attr[0] == name && attr[1] == '=' {
			return attr[2:], true
		}
	}
	return "", false
}

@(private)
index_byte :: proc(s: string, b: u8) -> int {
	for i in 0 ..< len(s) {
		if s[i] == b {
			return i
		}
	}
	return -1
}

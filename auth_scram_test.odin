package pg

import "core:testing"

// RFC 7677 §3 example exchange (username "user", password "pencil").
// PostgreSQL sends an empty username in client-first ("n=,"), so for the
// vector test we splice the RFC's "n=user" via the same code path the
// server would see; instead we verify against a transcript captured with
// the empty-username convention below, plus the RFC's own derivations.

RFC_NONCE :: "rOprNGfwEbeRWgbNEkqO"
RFC_SERVER_FIRST :: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"

@(test)
test_scram_client_first :: proc(t: ^testing.T) {
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)

	msg, err := scram_client_first(&s)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, string(msg), "n,,n=,r=rOprNGfwEbeRWgbNEkqO")
}

@(test)
test_scram_rfc7677_vector :: proc(t: ^testing.T) {
	// With the RFC's username in client-first-bare, the full RFC 7677
	// transcript must reproduce bit-for-bit.
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)

	_, err := scram_client_first(&s)
	testing.expect_value(t, err, nil)
	// Substitute the RFC's client-first-bare (n=user instead of n=).
	clear(&s.client_first_bare)
	append(&s.client_first_bare, "n=user,r=")
	append(&s.client_first_bare, RFC_NONCE)

	client_final, first_err := scram_handle_server_first(&s, transmute([]byte)string(RFC_SERVER_FIRST), "pencil")
	testing.expect_value(t, first_err, nil)
	testing.expect_value(
		t,
		string(client_final),
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
	)

	final_err := scram_handle_server_final(
		&s,
		transmute([]byte)string("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
	)
	testing.expect_value(t, final_err, nil)
	testing.expect_value(t, s.state, Scram_State.Done)
}

@(test)
test_scram_rejects_tampered_server_signature :: proc(t: ^testing.T) {
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)

	_, _ = scram_client_first(&s)
	clear(&s.client_first_bare)
	append(&s.client_first_bare, "n=user,r=")
	append(&s.client_first_bare, RFC_NONCE)
	_, err := scram_handle_server_first(&s, transmute([]byte)string(RFC_SERVER_FIRST), "pencil")
	testing.expect_value(t, err, nil)

	// Flip one character of the valid signature.
	tampered := scram_handle_server_final(
		&s,
		transmute([]byte)string("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
	)
	testing.expect_value(t, tampered, Error(Driver_Error.Auth_Failed))
	testing.expect_value(t, s.state, Scram_State.Failed)
}

@(test)
test_scram_rejects_server_error :: proc(t: ^testing.T) {
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)

	_, _ = scram_client_first(&s)
	_, err := scram_handle_server_first(&s, transmute([]byte)string(RFC_SERVER_FIRST), "pencil")
	testing.expect_value(t, err, nil)

	e := scram_handle_server_final(&s, transmute([]byte)string("e=other-error"))
	testing.expect_value(t, e, Error(Driver_Error.Auth_Failed))
}

@(test)
test_scram_rejects_nonce_mismatch :: proc(t: ^testing.T) {
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)
	_, _ = scram_client_first(&s)

	// Server nonce does not extend the client nonce.
	bad := "r=XXXXNGfwEbeRWgbNEkqO%hvYD,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	_, err := scram_handle_server_first(&s, transmute([]byte)string(bad), "pencil")
	testing.expect_value(t, err, Error(Driver_Error.Auth_Failed))
}

@(test)
test_scram_rejects_low_iterations :: proc(t: ^testing.T) {
	s: Scram
	scram_init(&s, test_nonce = RFC_NONCE)
	defer scram_destroy(&s)
	_, _ = scram_client_first(&s)

	bad := "r=rOprNGfwEbeRWgbNEkqO%hvYD,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1024"
	_, err := scram_handle_server_first(&s, transmute([]byte)string(bad), "pencil")
	testing.expect_value(t, err, Error(Driver_Error.Auth_Failed))
}

@(test)
test_scram_random_nonce_is_generated :: proc(t: ^testing.T) {
	s1, s2: Scram
	scram_init(&s1)
	scram_init(&s2)
	defer scram_destroy(&s1)
	defer scram_destroy(&s2)

	testing.expect_value(t, len(s1.nonce), 24) // base64 of 18 bytes
	testing.expect(t, string(s1.nonce[:]) != string(s2.nonce[:]))
}

// package pg_openssl provides TLS for odin-pg via minimal libssl/libcrypto
// bindings (OpenSSL 1.1.1+ / 3.x ABI). The core pg package never imports
// this — importing it is what links OpenSSL into your program:
//
//	import pg "odin-pg"
//	import pg_ssl "odin-pg/openssl"
//
//	cfg.tls = pg_ssl.tls_config(.Verify_Full, ca_file = "root.crt")
//
// On macOS the Homebrew openssl@3 keg is linked by default; override with
// -define:ODIN_PG_OPENSSL_DIR=/path/to/lib if yours lives elsewhere.
package pg_openssl

import "core:c"

when ODIN_OS == .Darwin {
	// Homebrew's openssl@3 keg location per architecture. If yours differs,
	// build with: -extra-linker-flags:"-L/path/to/openssl/lib"
	when ODIN_ARCH == .arm64 {
		@(extra_linker_flags = "-L/opt/homebrew/opt/openssl@3/lib")
		foreign import libssl "system:ssl"
		@(extra_linker_flags = "-L/opt/homebrew/opt/openssl@3/lib")
		foreign import libcrypto "system:crypto"
	} else {
		@(extra_linker_flags = "-L/usr/local/opt/openssl@3/lib")
		foreign import libssl "system:ssl"
		@(extra_linker_flags = "-L/usr/local/opt/openssl@3/lib")
		foreign import libcrypto "system:crypto"
	}
} else when ODIN_OS == .Windows {
	foreign import libssl "system:libssl.lib"
	foreign import libcrypto "system:libcrypto.lib"
} else {
	foreign import libssl "system:ssl"
	foreign import libcrypto "system:crypto"
}

SSL_CTX :: distinct rawptr
SSL :: distinct rawptr
SSL_METHOD :: distinct rawptr

SSL_VERIFY_NONE :: c.int(0)
SSL_VERIFY_PEER :: c.int(1)
SSL_FILETYPE_PEM :: c.int(1)

// SSL_get_error results.
SSL_ERROR_NONE :: c.int(0)
SSL_ERROR_ZERO_RETURN :: c.int(6)
SSL_ERROR_WANT_READ :: c.int(2)
SSL_ERROR_WANT_WRITE :: c.int(3)
SSL_ERROR_SYSCALL :: c.int(5)

// SSL_ctrl command for SNI.
SSL_CTRL_SET_TLSEXT_HOSTNAME :: c.int(55)
TLSEXT_NAMETYPE_HOST_NAME :: c.long(0)

X509_V_OK :: c.long(0)

@(default_calling_convention = "c")
foreign libssl {
	TLS_client_method :: proc() -> SSL_METHOD ---
	SSL_CTX_new :: proc(method: SSL_METHOD) -> SSL_CTX ---
	SSL_CTX_free :: proc(ctx: SSL_CTX) ---
	SSL_CTX_set_verify :: proc(ctx: SSL_CTX, mode: c.int, callback: rawptr) ---
	SSL_CTX_set_default_verify_paths :: proc(ctx: SSL_CTX) -> c.int ---
	SSL_CTX_load_verify_locations :: proc(ctx: SSL_CTX, ca_file, ca_path: cstring) -> c.int ---
	SSL_CTX_use_certificate_chain_file :: proc(ctx: SSL_CTX, file: cstring) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: SSL_CTX, file: cstring, file_type: c.int) -> c.int ---
	SSL_new :: proc(ctx: SSL_CTX) -> SSL ---
	SSL_free :: proc(ssl: SSL) ---
	SSL_set_fd :: proc(ssl: SSL, fd: c.int) -> c.int ---
	SSL_set1_host :: proc(ssl: SSL, hostname: cstring) -> c.int ---
	SSL_ctrl :: proc(ssl: SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_connect :: proc(ssl: SSL) -> c.int ---
	SSL_read :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_write :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_get_error :: proc(ssl: SSL, ret: c.int) -> c.int ---
	SSL_get_verify_result :: proc(ssl: SSL) -> c.long ---
	SSL_shutdown :: proc(ssl: SSL) -> c.int ---
}

@(default_calling_convention = "c")
foreign libcrypto {
	ERR_get_error :: proc() -> c.ulong ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]u8, len: c.size_t) ---
	ERR_clear_error :: proc() ---
}

// set_sni_hostname wraps the SSL_ctrl invocation behind the
// SSL_set_tlsext_host_name macro.
set_sni_hostname :: proc(ssl: SSL, hostname: cstring) -> bool {
	return(
		SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME, rawptr(hostname)) ==
		1 \
	)
}

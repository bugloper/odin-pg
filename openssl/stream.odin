package pg_openssl

import "core:c"
import "core:mem"
import "core:net"
import "core:strings"
import "core:time"

import pg ".."

// tls_config builds a pg.TLS_Config wired to this OpenSSL implementation.
tls_config :: proc(
	mode: pg.TLS_Mode,
	ca_file := "",
	cert_file := "",
	key_file := "",
	server_name := "",
) -> pg.TLS_Config {
	return pg.TLS_Config {
		mode = mode,
		factory = tls_stream_factory,
		ca_file = ca_file,
		cert_file = cert_file,
		key_file = key_file,
		server_name = server_name,
	}
}

TLS_Stream :: struct {
	ctx:       SSL_CTX,
	ssl:       SSL,
	socket:    net.TCP_Socket,
	allocator: mem.Allocator,
}

// tls_stream_factory upgrades a connected TCP socket to TLS according to
// cfg.mode. Matches pg.TLS_Stream_Factory.
tls_stream_factory :: proc(
	socket: net.TCP_Socket,
	cfg: ^pg.TLS_Config,
	server_name: string,
) -> (
	stream: pg.Stream,
	err: pg.Error,
) {
	ERR_clear_error()

	ctx := SSL_CTX_new(TLS_client_method())
	if ctx == nil {
		return {}, pg.Driver_Error.TLS_Failed
	}

	verify := cfg.mode == .Verify_CA || cfg.mode == .Verify_Full
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER if verify else SSL_VERIFY_NONE, nil)
	if verify {
		ok: c.int
		if cfg.ca_file != "" {
			ca, _ := strings.clone_to_cstring(cfg.ca_file, context.temp_allocator)
			ok = SSL_CTX_load_verify_locations(ctx, ca, nil)
		} else {
			ok = SSL_CTX_set_default_verify_paths(ctx)
		}
		if ok != 1 {
			SSL_CTX_free(ctx)
			return {}, pg.Driver_Error.TLS_Failed
		}
	}

	if cfg.cert_file != "" && cfg.key_file != "" {
		cert, _ := strings.clone_to_cstring(cfg.cert_file, context.temp_allocator)
		key, _ := strings.clone_to_cstring(cfg.key_file, context.temp_allocator)
		if SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
		   SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 {
			SSL_CTX_free(ctx)
			return {}, pg.Driver_Error.TLS_Failed
		}
	}

	ssl := SSL_new(ctx)
	if ssl == nil {
		SSL_CTX_free(ctx)
		return {}, pg.Driver_Error.TLS_Failed
	}

	host_c, _ := strings.clone_to_cstring(server_name, context.temp_allocator)
	_ = set_sni_hostname(ssl, host_c) // SNI is best-effort
	if cfg.mode == .Verify_Full {
		if SSL_set1_host(ssl, host_c) != 1 {
			cleanup(ssl, ctx)
			return {}, pg.Driver_Error.TLS_Failed
		}
	}

	// NOTE: SSL_set_fd narrows to c.int; fine on unix, documented-best-effort
	// for 64-bit Windows SOCKET values.
	if SSL_set_fd(ssl, c.int(socket)) != 1 {
		cleanup(ssl, ctx)
		return {}, pg.Driver_Error.TLS_Failed
	}
	if SSL_connect(ssl) != 1 {
		cleanup(ssl, ctx)
		return {}, pg.Driver_Error.TLS_Failed
	}
	if verify && SSL_get_verify_result(ssl) != X509_V_OK {
		cleanup(ssl, ctx)
		return {}, pg.Driver_Error.TLS_Failed
	}

	ts, alloc_err := new(TLS_Stream)
	if alloc_err != nil {
		cleanup(ssl, ctx)
		return {}, alloc_err
	}
	ts^ = TLS_Stream {
		ctx       = ctx,
		ssl       = ssl,
		socket    = socket,
		allocator = context.allocator,
	}
	return pg.Stream{data = ts, impl = &_tls_vtable}, nil
}

@(private = "file")
cleanup :: proc(ssl: SSL, ctx: SSL_CTX) {
	if ssl != nil {
		SSL_free(ssl)
	}
	if ctx != nil {
		SSL_CTX_free(ctx)
	}
}

@(private = "file")
_tls_vtable := pg.Stream_VTable {
	read = proc(data: rawptr, buf: []byte) -> (n: int, err: pg.Error) {
		ts := (^TLS_Stream)(data)
		if len(buf) == 0 {
			return 0, nil
		}
		ret := SSL_read(ts.ssl, raw_data(buf), c.int(min(len(buf), int(max(c.int)))))
		if ret > 0 {
			return int(ret), nil
		}
		switch SSL_get_error(ts.ssl, ret) {
		case SSL_ERROR_ZERO_RETURN:
			return 0, nil // clean TLS shutdown
		case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_SYSCALL:
			// With SO_RCVTIMEO on the underlying fd, a deadline expiry
			// surfaces here.
			return 0, pg.Driver_Error.Read_Timeout
		}
		return 0, pg.Driver_Error.TLS_Failed
	},
	write = proc(data: rawptr, buf: []byte) -> pg.Error {
		ts := (^TLS_Stream)(data)
		remaining := buf
		for len(remaining) > 0 {
			ret := SSL_write(
				ts.ssl,
				raw_data(remaining),
				c.int(min(len(remaining), int(max(c.int)))),
			)
			if ret <= 0 {
				switch SSL_get_error(ts.ssl, ret) {
				case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_SYSCALL:
					return pg.Driver_Error.Write_Timeout
				}
				return pg.Driver_Error.TLS_Failed
			}
			remaining = remaining[ret:]
		}
		return nil
	},
	set_deadline = proc(data: rawptr, read_timeout, write_timeout: time.Duration) -> pg.Error {
		ts := (^TLS_Stream)(data)
		if err := net.set_option(ts.socket, .Receive_Timeout, read_timeout); err != nil {
			return net.Network_Error(err)
		}
		if err := net.set_option(ts.socket, .Send_Timeout, write_timeout); err != nil {
			return net.Network_Error(err)
		}
		return nil
	},
	close = proc(data: rawptr) {
		ts := (^TLS_Stream)(data)
		SSL_shutdown(ts.ssl)
		SSL_free(ts.ssl)
		SSL_CTX_free(ts.ctx)
		net.close(ts.socket)
		free(ts, ts.allocator)
	},
}

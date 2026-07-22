package pg

// Connection dialing: TCP with a real connect timeout, and unix-domain
// socket routing (host beginning with '/' names the socket directory, libpq
// style — the socket file is <dir>/.s.PGSQL.<port>).

import "base:runtime"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

// dial_socket routes to unix or TCP based on the host and applies the
// connect timeout.
@(private)
dial_socket :: proc(host: string, port: int, timeout: time.Duration) -> (socket: net.TCP_Socket, is_unix: bool, err: Error) {
	if strings.has_prefix(host, "/") {
		path := unix_socket_path(host, port, context.temp_allocator)
		socket, err = dial_unix(path)
		return socket, true, err
	}
	socket, err = dial_tcp_with_timeout(host, port, timeout)
	return socket, false, err
}

@(private)
unix_socket_path :: proc(dir: string, port: int, allocator := context.temp_allocator) -> string {
	buf: [16]u8
	port_str := strconv.write_int(buf[:], i64(port), 10)
	return strings.concatenate({dir, "/.s.PGSQL.", port_str}, allocator)
}

// --- TCP dial with timeout ---
//
// core:net's dial has no timeout parameter (a SYN to a black-holed host
// blocks for the OS default, ~75s). The dial runs on a detached worker
// thread; if it doesn't finish in time the waiter abandons it and the
// worker closes the socket whenever the OS finally answers. State handoff
// is a single atomic CAS, so exactly one side consumes the result.

@(private = "file")
Dial_State :: enum i32 {
	Pending,
	Abandoned, // waiter timed out; worker must close and discard
	Delivered, // worker stored socket/err and posted the sema
}

@(private = "file")
Dial_Job :: struct {
	host:   string, // owned copy (heap)
	port:   int,
	socket: net.TCP_Socket,
	err:    net.Network_Error,
	done:   sync.Sema,
	state:  Dial_State, // atomic
	refs:   i32, // atomic; starts at 2, last one out frees
}

@(private = "file")
dial_job_release :: proc(job: ^Dial_Job) {
	if sync.atomic_sub(&job.refs, 1) == 1 {
		allocator := runtime.heap_allocator()
		delete(job.host, allocator)
		free(job, allocator)
	}
}

@(private = "file")
dial_worker :: proc(job: ^Dial_Job) {
	socket, dial_err := net.dial_tcp_from_hostname_with_port_override(job.host, job.port)
	job.socket = socket
	job.err = dial_err
	if _, won := sync.atomic_compare_exchange_strong(&job.state, Dial_State.Pending, Dial_State.Delivered); won {
		sync.sema_post(&job.done)
	} else {
		// Abandoned: nobody is waiting for this socket anymore.
		if dial_err == nil {
			net.close(socket)
		}
	}
	dial_job_release(job)
}

@(private)
dial_tcp_with_timeout :: proc(host: string, port: int, timeout: time.Duration) -> (socket: net.TCP_Socket, err: Error) {
	if timeout <= 0 {
		s, dial_err := net.dial_tcp_from_hostname_with_port_override(host, port)
		if dial_err != nil {
			return {}, net.Network_Error(dial_err)
		}
		return s, nil
	}

	// The job lives on the plain heap: it must not depend on the caller's
	// allocator, which the worker thread may outlive.
	allocator := runtime.heap_allocator()
	job, alloc_err := new(Dial_Job, allocator)
	if alloc_err != nil {
		return {}, alloc_err
	}
	job.host, _ = strings.clone(host, allocator)
	job.port = port
	job.refs = 2

	worker := thread.create_and_start_with_poly_data(
		job,
		dial_worker,
		init_context = runtime.default_context(),
		self_cleanup = true,
	)
	if worker == nil {
		// No thread: fall back to a blocking dial rather than failing.
		dial_job_release(job)
		dial_job_release(job)
		return dial_tcp_with_timeout(host, port, 0)
	}

	if !sync.sema_wait_with_timeout(&job.done, timeout) {
		if _, won := sync.atomic_compare_exchange_strong(&job.state, Dial_State.Pending, Dial_State.Abandoned); won {
			dial_job_release(job)
			return {}, Driver_Error.Connect_Timeout
		}
		// The worker delivered in the race window; consume its post.
		sync.sema_wait(&job.done)
	}

	s := job.socket
	dial_err := job.err
	dial_job_release(job)
	if dial_err != nil {
		return {}, net.Network_Error(dial_err)
	}
	return s, nil
}

#+build darwin, linux, freebsd, netbsd, openbsd
package pg

import "core:c"
import "core:net"
import "core:sys/posix"

// dial_unix connects to a unix-domain stream socket. The returned handle is
// a plain file descriptor wrapped as net.TCP_Socket — recv/send/close and
// SO_RCVTIMEO/SO_SNDTIMEO all behave identically for AF_UNIX sockets, so
// the rest of the driver is agnostic.
@(private)
dial_unix :: proc(path: string) -> (socket: net.TCP_Socket, err: Error) {
	addr: posix.sockaddr_un
	if len(path) + 1 > len(addr.sun_path) {
		return {}, Driver_Error.Invalid_Config
	}
	addr.sun_family = posix.sa_family_t(posix.AF.UNIX)
	for i in 0 ..< len(path) {
		addr.sun_path[i] = c.char(path[i])
	}

	fd := posix.socket(.UNIX, .STREAM)
	if posix.FD(fd) < 0 {
		return {}, net.Network_Error(net.Create_Socket_Error.Insufficient_Resources)
	}
	if posix.connect(fd, (^posix.sockaddr)(&addr), posix.socklen_t(size_of(addr))) != .OK {
		posix.close(fd)
		#partial switch posix.get_errno() {
		case .ECONNREFUSED, .ENOENT, .ENOTDIR:
			// No server listening on that socket path.
			return {}, net.Network_Error(net.Dial_Error.Refused)
		case .EACCES, .EPERM:
			return {}, net.Network_Error(net.Dial_Error.Broadcast_Not_Supported) // closest "not permitted"
		case .ETIMEDOUT:
			return {}, net.Network_Error(net.Dial_Error.Timeout)
		}
		return {}, net.Network_Error(net.Dial_Error.Refused)
	}
	return net.TCP_Socket(fd), nil
}

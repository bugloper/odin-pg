#+build windows
package pg

import "core:net"

// Unix-domain sockets are not supported on Windows in v1.
@(private)
dial_unix :: proc(path: string) -> (socket: net.TCP_Socket, err: Error) {
	_ = path
	return {}, Driver_Error.Invalid_Config
}

//go:build linux

package main

import "syscall"

// Linux socket constants not exported by the syscall package.
const (
	_SO_REUSEPORT = 0xf // linux/socket.h
	_TCP_FASTOPEN = 23  // linux/tcp.h
)

// listenControl sets socket options on the listener fd before bind.
//
//   - SO_REUSEPORT: multiple listeners on the same port; required for
//     zero-downtime restarts and allows the kernel to load-balance incoming
//     connections across processes.
//   - SO_REUSEADDR: skip TIME_WAIT on restart so the port is immediately
//     available. Go sets this by default on Linux; included explicitly for
//     clarity and forward compatibility.
//   - TCP_FASTOPEN: reduces handshake latency for repeat clients by allowing
//     data in the SYN. Kernel requires net.ipv4.tcp_fastopen >= 2.
func listenControl(network, address string, c syscall.RawConn) error {
	var setSockErr error
	err := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, _SO_REUSEPORT, 1); err != nil {
			setSockErr = err
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			setSockErr = err
			return
		}
		// TFO queue depth of 16 is conservative; tune up if benchmarks show
		// connection-setup latency under burst load.
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, _TCP_FASTOPEN, 16) //nolint:errcheck
	})
	if err != nil {
		return err
	}
	return setSockErr
}

// NanoVMs runs on Linux so the linux file covers production. This stub covers
// local development on macOS and any other platform.

//go:build !linux

package main

import "syscall"

func listenControl(network, address string, c syscall.RawConn) error {
	return nil
}

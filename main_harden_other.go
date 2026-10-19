//go:build !linux

package main

// hardenMemoryImpl does nothing where mlockall isn't wired up (see main_harden_linux.go for
// what it does on Linux). Memory hardening is Linux-only for now.
func hardenMemoryImpl(_ bool) {}

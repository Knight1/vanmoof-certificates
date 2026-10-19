//go:build linux

package main

import (
	"fmt"
	"syscall"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

// lockMemory and limitCoreDumps are the syscalls hardenMemoryImpl makes; tests replace them.
var (
	lockMemory     = syscall.Mlockall
	limitCoreDumps = syscall.Setrlimit
)

// hardenMemoryImpl keeps the process's secrets off disk, best-effort. It locks all of the
// process's memory into RAM (mlockall) so nothing is swapped out, and sets the core-dump
// size to zero so a crash can't write memory to a core file. It locks the whole process
// because Go moves stacks and copies strings around, so an individual secret can't be
// locked on its own; for the same reason secrets held as strings can't be wiped after use.
//
// mlockall needs RLIMIT_MEMLOCK headroom, which an unprivileged user often lacks (raise it
// with "ulimit -l", or ignore it where there's no swap), so a failure is only a warning.
func hardenMemoryImpl(debug bool) {
	if err := limitCoreDumps(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Couldn't disable core dumps: %v\n", vanmoof.ScrubText(err.Error()))
		}
	} else if debug {
		fmt.Println("[DEBUG] Core dumps disabled")
	}

	if err := lockMemory(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		fmt.Printf("WARNING: couldn't lock memory to keep secrets out of swap: %v (raise the limit with 'ulimit -l', or ignore if this system has no swap)\n", vanmoof.ScrubText(err.Error()))
	} else if debug {
		fmt.Println("[DEBUG] Locked memory into RAM, so secrets aren't swapped to disk")
	}
}

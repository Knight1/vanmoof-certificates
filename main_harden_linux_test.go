//go:build linux

package main

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// hardenMemoryImpl locks memory and disables core dumps best-effort: it reports both in
// debug, and warns (always) if it can't lock memory, without failing.
func TestHardenMemory(t *testing.T) {
	ok := func(int) error { return nil }
	okRlimit := func(int, *syscall.Rlimit) error { return nil }
	fail := func(int) error { return errors.New("cannot allocate memory") }
	failRlimit := func(int, *syscall.Rlimit) error { return errors.New("operation not permitted") }

	origLock, origCore := lockMemory, limitCoreDumps
	t.Cleanup(func() { lockMemory, limitCoreDumps = origLock, origCore })

	// Both succeed: debug reports each
	lockMemory, limitCoreDumps = ok, okRlimit
	if out := captureOutput(t, func() { hardenMemoryImpl(true) }); !strings.Contains(out, "Locked memory") || !strings.Contains(out, "Core dumps disabled") {
		t.Errorf("success output: %q", out)
	}

	// Both fail, in debug: a warning the memory isn't locked, and a note about core dumps
	lockMemory, limitCoreDumps = fail, failRlimit
	if out := captureOutput(t, func() { hardenMemoryImpl(true) }); !strings.Contains(out, "WARNING: couldn't lock memory") || !strings.Contains(out, "Couldn't disable core dumps") {
		t.Errorf("failure output: %q", out)
	}

	// Both fail, without debug: still warns about the lock, but says nothing else
	if out := captureOutput(t, func() { hardenMemoryImpl(false) }); !strings.Contains(out, "WARNING: couldn't lock memory") || strings.Contains(out, "[DEBUG]") {
		t.Errorf("non-debug output: %q", out)
	}
}

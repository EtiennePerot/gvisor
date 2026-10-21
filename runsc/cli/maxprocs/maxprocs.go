// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package maxprocs bounds GOMAXPROCS of runsc processes on hosts with many
// CPUs, from the start of package initialization.
//
// By default, the Go runtime runs with one P per CPU available to the process,
// and allocates each P (about 16 KB) on the heap. With more than about 128
// CPUs, Ps take more than half of the 4 MB heap that triggers the first
// garbage collection cycle, so runsc commands, which are short-lived control
// processes, run that cycle during package initialization or soon after. A
// cycle stops the world and starts mark workers on every P, which costs more
// than the rest of a command such as "runsc state" on such hosts. With fewer
// CPUs, commands usually exit before the first cycle, and lowering GOMAXPROCS
// (which also stops the world) would cost more than it saves.
//
// Lowering GOMAXPROCS in main is too late, so this package does it in its init
// function. It imports only runtime and syscall, so the Go specification's
// initialization order runs it right after syscall, before the packages that
// allocate during initialization.
//
// The bound is not applied if the GOMAXPROCS environment variable is set.
// Processes that are not short-lived control processes (e.g. the gofer) can
// call Restore to go back to the runtime default.
package maxprocs

import (
	"runtime"
	"syscall"
)

const (
	// threshold is the GOMAXPROCS above which initialization lowers it.
	threshold = 128

	// maxProcs is the GOMAXPROCS that initialization lowers it to.
	maxProcs = 8
)

// lowered is true if init lowered GOMAXPROCS.
var lowered bool

func init() {
	_, envSet := syscall.Getenv("GOMAXPROCS")
	if n := bound(runtime.GOMAXPROCS(0), envSet); n != 0 {
		runtime.GOMAXPROCS(n)
		lowered = true
	}
}

// bound returns the GOMAXPROCS to set at initialization given the current
// GOMAXPROCS, or 0 if it should not be changed.
func bound(cur int, envSet bool) int {
	if envSet || cur <= threshold {
		return 0
	}
	return maxProcs
}

// Restore undoes the bound applied during initialization, if any, by
// restoring the runtime's default GOMAXPROCS (which also re-enables the
// runtime's automatic GOMAXPROCS updates).
func Restore() {
	if lowered {
		runtime.SetDefaultGOMAXPROCS()
		lowered = false
	}
}

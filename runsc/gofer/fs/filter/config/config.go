// Copyright 2018 The gVisor Authors.
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

// Package config defines all syscalls the gofer is allowed to make to the
// host.
package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/runsc/gofer/filter"
)

const procSelfFDVarName = "proc_self_fd"

// HostFSAccess is the set of host filesystem syscalls that the gofer can make
// in addition to the ones that every gofer can make. Every gofer can open,
// create, read and write host files, and can change their extended
// attributes by path, so no level makes the host filesystem read-only for
// the gofer.
//
// The levels are ordered. Each level allows all that the level before it
// allows.
type HostFSAccess int

const (
	// HostFSNone means that the gofer can make no more syscalls. This is
	// sufficient when the Sentry uses directfs for every mount.
	HostFSNone HostFSAccess = iota

	// HostFSReadWrite means that the gofer can also list directories, read
	// symlinks, change the metadata of host files, make directories,
	// symlinks, hard links and whiteouts, and rename and remove host files.
	HostFSReadWrite
)

// String returns the name of the access level.
func (a HostFSAccess) String() string {
	switch a {
	case HostFSNone:
		return "none"
	case HostFSReadWrite:
		return "readwrite"
	default:
		return fmt.Sprintf("HostFSAccess(%d)", int(a))
	}
}

// Options are seccomp filter related options.
type Options struct {
	UDSOpenEnabled   bool
	UDSCreateEnabled bool
	ProfileEnabled   bool
	HostFS           HostFSAccess
	ProcSelfFD       uint32
	CgoEnabled       bool
	VendorSyscalls   precompiledseccomp.VarSyscallNumbers
	ExtraRules       []seccomp.SyscallRules
}

// vendorSyscalls is the set of vendor-specific syscalls that the gofer may
// use if the host supports them.
var vendorSyscalls []precompiledseccomp.VarSyscall

// vendorSyscallSetsToPrecompile lists the sets of `vendorSyscalls` (by name)
// that may be available in practice.
var vendorSyscallSetsToPrecompile [][]string

// HostVendorSyscalls returns the vendor-specific syscalls that may be used on
// the current host.
func HostVendorSyscalls() precompiledseccomp.VarSyscallNumbers {
	return precompiledseccomp.HostSupportedVariableSyscallNumbers(vendorSyscalls)
}

// isInstrumentationEnabled returns whether there are any
// instrumentation-specific filters enabled.
func isInstrumentationEnabled() bool {
	return filter.InstrumentationFilters().Size() > 0
}

// ConfigKey returns a unique string representing this set of options.
// This is used for matching a set of `Options` at seccomp precompile
// time with the same set of `Options` at runtime.
// As such, it should encompass all fields that change the structure of
// the seccomp rules, but should not encompass fields that are only known
// at runtime (e.g. the gofer's own PID).
func (opt Options) ConfigKey() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "GOARCH=%q ", runtime.GOARCH)
	fmt.Fprintf(&sb, "UDSOpenEnabled=%t ", opt.UDSOpenEnabled)
	fmt.Fprintf(&sb, "UDSCreateEnabled=%t ", opt.UDSCreateEnabled)
	fmt.Fprintf(&sb, "ProfileEnabled=%t ", opt.ProfileEnabled)
	fmt.Fprintf(&sb, "HostFS=%v ", opt.HostFS)
	fmt.Fprintf(&sb, "Instrumentation=%t ", isInstrumentationEnabled())
	fmt.Fprintf(&sb, "CgoEnabled=%t ", opt.CgoEnabled)
	fmt.Fprintf(&sb, "VendorSyscalls=%q ", opt.VendorSyscalls.Key())
	// Extra rules come from registered extensions, whose filters are not
	// known at precompile time. Cannot precompile.
	fmt.Fprintf(&sb, "ExtraRules=%t ", len(opt.ExtraRules) > 0)
	return strings.TrimSpace(sb.String())
}

// Warnings returns a set of warnings that may be useful to display to the
// user when the given options are used.
func (opt Options) Warnings() []string {
	var warnings []string
	if opt.ProfileEnabled {
		warnings = append(warnings, "profile enabled: syscall filters less restrictive!")
	}
	if opt.UDSOpenEnabled || opt.UDSCreateEnabled {
		warnings = append(warnings, "host UDS enabled: syscall filters less restrictive!")
	}
	if opt.CgoEnabled {
		warnings = append(warnings, "CGO enabled: syscall filters less restrictive!")
	}
	return warnings
}

// Warnings returns a set of warnings that may be useful to display to the
// user when the given options are used.
func Warnings(opt Options) []string {
	return opt.Warnings()
}

// Vars returns the values to use for rendering the precompiled seccomp
// program.
func (opt Options) Vars() precompiledseccomp.Values {
	vars := precompiledseccomp.Values{}
	vars.SetUint64(filter.SelfPIDVarName, uint64(os.Getpid()))
	switch opt.HostFS {
	case HostFSNone:
	case HostFSReadWrite:
		vars[procSelfFDVarName] = opt.ProcSelfFD
	default:
		panic(fmt.Sprintf("unknown HostFSAccess: %v", opt.HostFS))
	}
	opt.VendorSyscalls.SetVars(vars)
	return vars
}

// Rules returns the seccomp rules and denyRules to use for the gofer.
func (opt Options) Rules() (seccomp.SyscallRules, seccomp.SyscallRules) {
	return rules(opt, opt.Vars())
}

// Rules returns the seccomp rules and denyRules to use for the gofer.
func Rules(opt Options) (seccomp.SyscallRules, seccomp.SyscallRules) {
	return opt.Rules()
}

// rules returns the seccomp rules and denyRules to use for the gofer,
// using `vars` as override for variables defined during precompilation.
func rules(opt Options, vars precompiledseccomp.Values) (seccomp.SyscallRules, seccomp.SyscallRules) {
	s := allowedSyscalls.Copy()
	s.Merge(filter.SelfPIDFilters(vars.GetUint64(filter.SelfPIDVarName)))
	s.Merge(precompiledseccomp.VarSyscallRules(vendorSyscalls, opt.VendorSyscalls, vars))
	if opt.ProfileEnabled {
		s.Merge(filter.ProfileFilters())
	}
	if opt.UDSOpenEnabled || opt.UDSCreateEnabled {
		s.Merge(udsCommonSyscalls)
		if opt.UDSOpenEnabled {
			s.Merge(udsOpenSyscalls)
		}
		if opt.UDSCreateEnabled {
			s.Merge(udsCreateSyscalls)
		}
	}
	if opt.CgoEnabled {
		s.Merge(filter.CgoFilters())
	}
	s.Merge(filter.InstrumentationFilters())
	if opt.HostFS == HostFSReadWrite {
		s.Merge(lisafsFilters(vars[procSelfFDVarName]))
	}
	for _, rules := range opt.ExtraRules {
		s.Merge(rules)
	}
	return s, seccomp.DenyNewExecMappings
}

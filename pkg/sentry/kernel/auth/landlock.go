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

package auth

// LandlockDomain is a Landlock domain carried opaquely in credentials. The
// concrete type is vfs.LandlockDomain; auth does not depend on vfs. kernel and
// vfs, which know the concrete type, manage its lifetime.
type LandlockDomain interface {
	// CanPtrace reports whether Landlock allows a task with this domain to
	// ptrace a task with domain tracee: that is, whether this domain is
	// tracee or one of the domains that tracee was stacked onto. tracee may
	// be nil.
	CanPtrace(tracee LandlockDomain) bool
}

// LandlockCanPtrace reports whether Landlock allows a task with domain tracer
// to ptrace a task with domain tracee. A tracer with no domain (nil) may
// ptrace any task, while a tracer with a domain may not ptrace a task with no
// domain.
func LandlockCanPtrace(tracer, tracee LandlockDomain) bool {
	if tracer == nil {
		return true
	}
	if tracee == nil {
		return false
	}
	return tracer.CanPtrace(tracee)
}

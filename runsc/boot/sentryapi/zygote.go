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

package sentryapi

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/specutils"
)

// ContMgrAdopt binds a zygote sandbox to the root container that adopts it.
const ContMgrAdopt = "containerManager.Adopt"

// AdoptArgs are the arguments to containerManager.Adopt.
//
// Files are, in order: the root container's stdio (NumStdio), the gofer FDs
// (NumGoferFDs: rootfs first, then mounts), the gofer filestore FDs
// (NumGoferFilestoreFDs), the device gofer FD (if HaveDevGofer) and the
// gofer's resolved-mounts file (if HaveMountsFile).
type AdoptArgs struct {
	// Spec is the adopting root container's spec, as read from its bundle.
	Spec *specs.Spec

	// GoferMountConfs describes the adopting container's gofer mounts.
	GoferMountConfs []specutils.GoferMountConf

	NumStdio             int
	NumGoferFDs          int
	NumGoferFilestoreFDs int
	HaveDevGofer         bool
	HaveMountsFile       bool

	urpc.FilePayload
}

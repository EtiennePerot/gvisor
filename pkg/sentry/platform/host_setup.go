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

package platform

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
)

// HostSetup is the part of a platform that the process creating its sandbox
// needs. It is available without linking the platform implementation, unlike
// Constructor, which agrees with it.
type HostSetup struct {
	requirements Requirements

	// defaultDevicePath is the device file that the platform needs if no
	// other path is configured, or "" if it needs none.
	defaultDevicePath string
}

// hostSetups maps platform names to their HostSetup.
var hostSetups = map[string]HostSetup{
	"kvm":     {defaultDevicePath: "/dev/kvm"},
	"ptrace":  {requirements: Requirements{RequiresCapSysPtrace: true}},
	"slimvm":  {defaultDevicePath: "/dev/slimvm"},
	"systrap": {requirements: Requirements{RequiresCapSysPtrace: true, FrequentHostThreadWakeups: true}},
}

// LookupHostSetup returns the HostSetup of the named platform.
func LookupHostSetup(name string) (HostSetup, error) {
	h, ok := hostSetups[name]
	if !ok {
		return HostSetup{}, fmt.Errorf("unknown platform: %v", name)
	}
	return h, nil
}

// HostSetupNames lists the platforms that have a HostSetup.
func HostSetupNames() []string {
	names := make([]string, 0, len(hostSetups))
	for name := range hostSetups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Requirements is equivalent to Constructor.Requirements.
func (h HostSetup) Requirements() Requirements {
	return h.requirements
}

// OpenDevice is equivalent to Constructor.OpenDevice.
func (h HostSetup) OpenDevice(devicePath string) (*fd.FD, error) {
	if h.defaultDevicePath == "" {
		return nil, nil
	}
	if devicePath == "" {
		devicePath = h.defaultDevicePath
	}
	f, err := fd.Open(devicePath, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open device file %q: %w", devicePath, err)
	}
	return f, nil
}

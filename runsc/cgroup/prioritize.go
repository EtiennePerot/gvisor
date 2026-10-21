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

package cgroup

import (
	"path/filepath"
	"strconv"
)

// maxCPUWeight is the largest value accepted by cpu.weight.
const maxCPUWeight = 10000

// PrioritizeOwnCgroup raises cpu.weight of the cgroup the current process runs
// in to the maximum, if that cgroup is a sibling of sandbox, i.e. if runsc is
// placing the sandbox next to its caller. It returns true if it changed the
// weight.
//
// runsc commands run in their caller's cgroup. A caller that puts its
// sandboxes next to its own cgroup competes with all of them for CPU at that
// level of the hierarchy, usually at the default weight. Whenever the host is
// busy, the runsc commands that create, restore, checkpoint or destroy
// sandboxes then wait behind the sandboxes, even though they are on the
// critical path of starting and stopping them. Giving the caller's cgroup the
// maximum weight lets this work go first, at the cost of at most the CPU that
// the caller actually uses. This also covers the caller's own processes in
// that cgroup, which act as the control plane of the sandboxes next to it.
//
// The weight is left in place: later commands must start at the raised weight,
// because under contention most of the time of a short command goes into
// getting to run at all (exec, runtime initialization, loading state), before
// it could raise the weight itself.
//
// Callers that place sandboxes anywhere else in the hierarchy (e.g. Docker and
// Kubernetes, which keep the runtime in a system cgroup) are left alone, as are
// cgroups managed by systemd, the root cgroup and cgroup v1.
func PrioritizeOwnCgroup(sandbox Cgroup) (bool, error) {
	cg, ok := sandbox.(*cgroupV2)
	if !ok {
		// cgroup v1, or a systemd-managed cgroup whose properties belong to
		// systemd.
		return false, nil
	}
	paths, err := loadPaths("self")
	if err != nil {
		return false, err
	}
	own, ok := paths[cgroup2Key]
	if !ok {
		return false, nil
	}
	return prioritizeOwnCgroup(cg.Mountpoint, own, cg.Path)
}

func prioritizeOwnCgroup(mountpoint, own, sandbox string) (bool, error) {
	own = filepath.Clean("/" + own)
	sandbox = filepath.Clean("/" + sandbox)
	if own == "/" || own == sandbox || filepath.Dir(own) != filepath.Dir(sandbox) {
		return false, nil
	}
	switch filepath.Ext(own) {
	case ".slice", ".scope", ".service":
		// A systemd unit: systemd owns its attributes.
		return false, nil
	}
	path := filepath.Join(mountpoint, own)
	weight, err := getInt(path, "cpu.weight")
	if err != nil {
		// Typically ENOENT because the cpu controller isn't enabled for the
		// cgroup.
		return false, err
	}
	if weight >= maxCPUWeight {
		return false, nil
	}
	if err := setValue(path, "cpu.weight", strconv.Itoa(maxCPUWeight)); err != nil {
		return false, err
	}
	return true, nil
}

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

package sandbox

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

// Lifecycle CPU boost
//
// A sandbox's CPU limit (cgroup cpu.max) is sized for its application. But
// creating, restoring and checkpointing the sandbox are CPU-bound bursts of
// work that the sandbox does for runsc, and a small limit (e.g. 0.25 CPU)
// slows them down several times. So while runsc performs one of these
// operations, it raises the limit to at least LifecycleCPUs CPUs (and scales
// the CPU weight by the same factor), and it restores both when the operation
// ends. The application never runs with more CPU than its limit.
//
// Several runsc processes can operate on one sandbox at the same time, and any
// of them can be killed. The boost itself is recorded on the cgroup (see
// cgroup.BoostCPU). Each operation holds a shared flock on a per-sandbox file
// in the runsc root directory while it needs the boost, and the last holder to
// end restores the limit. So does the destruction of the sandbox, since its
// cgroup may be reused, and so does the next operation in the same cgroup if
// a killed runsc command left the limit raised.

// LifecycleCPUs is the minimum CPU limit of a sandbox during lifecycle
// operations.
const LifecycleCPUs = 4

// CPUBoost is a hold on a sandbox's lifecycle CPU boost.
type CPUBoost struct {
	rootDir   string
	sandboxID string
	cg        cgroup.Cgroup
	// holder is the file on which the hold is a shared flock.
	holder *os.File
	// boost is the boost recorded on cg.
	boost *cgroup.CPUBoost
}

func cpuBoostPaths(rootDir, sandboxID string) (holder, lock string) {
	base := filepath.Join(rootDir, sandboxID+".cpuboost")
	return base, base + ".lock"
}

// lockCPUBoost serializes changes to the boost of a sandbox. It returns a
// function that releases the lock.
func lockCPUBoost(rootDir, sandboxID string) (func(), error) {
	_, path := cpuBoostPaths(rootDir, sandboxID)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// lifecycleCPUs returns the minimum CPU limit during lifecycle operations
// configured by conf, or 0 if disabled.
func lifecycleCPUs(conf *config.Config) float64 {
	if m := conf.TestOnlyLifecycleCPUBoostMilliCPUs; m >= 0 {
		return float64(m) / 1000
	}
	return LifecycleCPUs
}

// BoostCPU raises the CPU limit of the cgroup cg of sandbox sandboxID for a
// lifecycle operation, if it is lower than LifecycleCPUs. The caller must call
// End or Release on the result when the operation is over.
// It returns nil if the limit isn't changed: there is no limit or it is high
// enough already, or runsc doesn't manage it (see cgroup.BoostCPU). Errors
// are logged and also leave the limit unchanged, since the boost only affects
// performance.
func BoostCPU(conf *config.Config, cg cgroup.Cgroup, sandboxID string) *CPUBoost {
	minCPUs := lifecycleCPUs(conf)
	if cg == nil || !cgroup.WouldBoostCPU(cg, minCPUs) || conf.RootDir == "" {
		return nil
	}
	b, err := boostCPU(conf.RootDir, sandboxID, cg, minCPUs)
	if err != nil {
		log.Warningf("Raising the CPU limit of sandbox %q: %v", sandboxID, err)
		return nil
	}
	return b
}

func boostCPU(rootDir, sandboxID string, cg cgroup.Cgroup, minCPUs float64) (*CPUBoost, error) {
	unlock, err := lockCPUBoost(rootDir, sandboxID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	path, _ := cpuBoostPaths(rootDir, sandboxID)
	holder, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_SH); err != nil {
		_ = holder.Close()
		return nil, err
	}
	// If already boosted, this only returns the boost.
	boost, err := cgroup.BoostCPU(cg, minCPUs)
	if err != nil || boost == nil {
		_ = holder.Close()
		return nil, err
	}
	return &CPUBoost{rootDir: rootDir, sandboxID: sandboxID, cg: cg, holder: holder, boost: boost}, nil
}

// Quota returns the CPU quota and period of the sandbox before the boost.
// quota is -1 if unlimited.
func (b *CPUBoost) Quota() (quota, period int64, err error) {
	return b.boost.Quota()
}

// End releases the hold, and restores the CPU limit if no other operation
// holds the boost. b may be nil.
func (b *CPUBoost) End() {
	if b == nil {
		return
	}
	defer b.holder.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(b.holder.Fd()), &st); err == nil && st.Nlink == 0 {
		// The sandbox was destroyed, see EndCPUBoost.
		return
	}
	unlock, err := lockCPUBoost(b.rootDir, b.sandboxID)
	if err != nil {
		log.Warningf("Restoring the CPU limit of sandbox %q: %v", b.sandboxID, err)
		return
	}
	defer unlock()
	fd := int(b.holder.Fd())
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		log.Warningf("Restoring the CPU limit of sandbox %q: %v", b.sandboxID, err)
		return
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// Still held by another operation.
		return
	}
	if err := restoreCPUBoost(b.cg); err != nil {
		log.Warningf("Restoring the CPU limit of sandbox %q: %v", b.sandboxID, err)
	}
}

// restoreCPUBoost restores the CPU limit of cg, if it is boosted.
func restoreCPUBoost(cg cgroup.Cgroup) error {
	boost, err := cgroup.LoadCPUBoost(cg)
	if err != nil || boost == nil {
		return err
	}
	return boost.Restore()
}

// Release releases the hold without restoring the CPU limit, which then
// stays raised until another operation on the sandbox ends or until the
// sandbox is destroyed. This is for operations after which the sandbox exits,
// whose exit would be slowed down by the limit. b may be nil.
func (b *CPUBoost) Release() {
	if b != nil {
		_ = b.holder.Close()
	}
}

// EndCPUBoost restores the CPU limit of sandbox sandboxID in cgroup cg if it
// is raised, regardless of holds. It is called when the sandbox is destroyed,
// because its cgroup may be reused.
func EndCPUBoost(rootDir, sandboxID string, cg cgroup.Cgroup) {
	path, lockPath := cpuBoostPaths(rootDir, sandboxID)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Never boosted.
		return
	}
	unlock, err := lockCPUBoost(rootDir, sandboxID)
	if err != nil {
		log.Warningf("Restoring the CPU limit of sandbox %q: %v", sandboxID, err)
		return
	}
	defer unlock()
	if err := restoreCPUBoost(cg); err != nil {
		log.Warningf("Restoring the CPU limit of sandbox %q: %v", sandboxID, err)
	}
	_ = os.Remove(path)
	_ = os.Remove(lockPath)
}

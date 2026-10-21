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

package hostsettings

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

// bfqIdleSetting checks that bfq does not idle on a disk that holds files
// used by the sandbox.
//
// When bfq's slice_idle is non-zero (8ms by default), bfq keeps the disk idle
// for up to slice_idle after a synchronous request completes, waiting for the
// same process or cgroup to issue the next one. gVisor serves application I/O
// (including O_DIRECT and AIO) with synchronous host reads and writes issued
// by a few Sentry and gofer threads, which is the pattern that this idling
// penalizes the most.
//
// Setting slice_idle to 0 disables idling. bfq relies on idling to enforce
// cgroup I/O weights (io.bfq.weight), so this also makes weights mostly
// ineffective on the disk, which is why this setting is only changed in the
// "adjust" and "enforce" modes, like other host settings. The scheduler itself
// is never changed, so that the change is easy to identify and to revert.
//
// Rotational disks are not checked, as idling can help their throughput.
type bfqIdleSetting struct {
	// sysfsQueue is the queue directory of the disk, under /sys/block.
	sysfsQueue string

	// path is a sandbox path stored on the disk, for logging.
	path string
}

// Name implements Setting.Name.
func (s bfqIdleSetting) Name() string {
	return filepath.Join(s.sysfsQueue, "iosched", "slice_idle")
}

// Delta implements Setting.Delta.
func (s bfqIdleSetting) Delta(conf *config.Config) (*Delta, error) {
	sched, err := readSysfs(filepath.Join(s.sysfsQueue, "scheduler"))
	if err != nil {
		return nil, err
	}
	if activeScheduler(sched) != "bfq" {
		return nil, nil
	}
	if rotational, err := readSysfs(filepath.Join(s.sysfsQueue, "rotational")); err != nil || rotational != "0" {
		return nil, err
	}
	return pathSetting{
		path:          s.Name(),
		mightNotExist: true, // The scheduler may have changed concurrently.
		purpose:       fmt.Sprintf("bfq idling delays the synchronous I/O that runsc does on behalf of the sandbox for files such as %s; note that without idling, bfq no longer enforces cgroup I/O weights on this disk", s.path),
		delta: func(conf *config.Config, current string) (string, bool, error) {
			if current == "0" {
				return "", false, nil
			}
			return "0", false, nil
		},
	}.Delta(conf)
}

// activeScheduler returns the active scheduler from the contents of a
// queue/scheduler sysfs file, e.g. "bfq" for "mq-deadline kyber [bfq] none".
func activeScheduler(s string) string {
	for _, f := range strings.Fields(s) {
		if len(f) > 2 && f[0] == '[' && f[len(f)-1] == ']' {
			return f[1 : len(f)-1]
		}
	}
	return ""
}

func readSysfs(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// diskResolver finds the disk holding a path.
type diskResolver struct {
	// sysfs is the sysfs mount point.
	sysfs string

	// mountInfo is the path of the mountinfo file, used to find the backing
	// directories of overlay filesystems.
	mountInfo string

	// stat returns the device number of the filesystem holding a path.
	stat func(path string) (uint64, error)
}

func statDev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Dev, nil
}

// queueDir returns the sysfs queue directory of the disk holding path, as
// /sys/block/<disk>/queue, or "" if path is not on a disk with an I/O
// scheduler (e.g. tmpfs).
func (r *diskResolver) queueDir(path string) (string, error) {
	dev, err := r.stat(path)
	if err != nil {
		return "", err
	}
	devDir := filepath.Join(r.sysfs, "dev", "block", fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev)))
	devDir, err = filepath.EvalSymlinks(devDir)
	if os.IsNotExist(err) {
		// Not a block device. If this is an overlay (e.g. a container
		// root filesystem), its I/O goes to the upper or lower directory.
		backing, err := r.overlayBackingDir(dev)
		if err != nil || backing == "" {
			return "", err
		}
		backingDev, err := r.stat(backing)
		if err != nil || backingDev == dev {
			return "", err
		}
		return r.queueDir(backing)
	}
	if err != nil {
		return "", err
	}
	// Partitions do not have their own queue; their parent is the disk.
	if _, err := os.Stat(filepath.Join(devDir, "partition")); err == nil {
		devDir = filepath.Dir(devDir)
	}
	queue := filepath.Join(r.sysfs, "block", filepath.Base(devDir), "queue")
	if _, err := os.Stat(filepath.Join(queue, "scheduler")); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return queue, nil
}

// overlayBackingDir returns the upper directory (or, if there is none, the
// first lower directory) of the overlay filesystem with device number dev, or
// "" if dev is not an overlay filesystem.
func (r *diskResolver) overlayBackingDir(dev uint64) (string, error) {
	f, err := os.Open(r.mountInfo)
	if err != nil {
		return "", err
	}
	defer f.Close()
	devStr := fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 1<<20) // Overlay options can be long.
	for scanner.Scan() {
		// See proc(5): the third field is the device number, and the
		// filesystem type and superblock options follow the "-"
		// separator.
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[2] != devStr {
			continue
		}
		sep := 0
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep == 0 || len(fields) < sep+4 || fields[sep+1] != "overlay" {
			return "", nil
		}
		var lower string
		for _, opt := range strings.Split(fields[sep+3], ",") {
			if dir, ok := strings.CutPrefix(opt, "upperdir="); ok {
				return unescapeMountInfo(dir), nil
			}
			if dirs, ok := strings.CutPrefix(opt, "lowerdir="); ok && lower == "" {
				// Lower directories are separated by ":".
				lower, _, _ = strings.Cut(dirs, ":")
			}
		}
		return unescapeMountInfo(lower), nil
	}
	return "", scanner.Err()
}

// unescapeMountInfo decodes the octal escapes (e.g. "\040" for a space) of a
// mountinfo field.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if c, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// bfqIdleSettings returns one bfqIdleSetting per disk holding the given paths.
func (r *diskResolver) bfqIdleSettings(paths []string) []Setting {
	var settings []Setting
	seen := make(map[string]bool)
	for _, p := range paths {
		queue, err := r.queueDir(p)
		if err != nil {
			log.Debugf("Host settings: cannot find the disk holding %q: %v", p, err)
			continue
		}
		if queue == "" || seen[queue] {
			continue
		}
		seen[queue] = true
		settings = append(settings, bfqIdleSetting{sysfsQueue: queue, path: p})
	}
	return settings
}

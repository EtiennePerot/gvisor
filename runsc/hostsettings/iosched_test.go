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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
)

// fakeHost is a fake sysfs and mountinfo with:
//   - disk nvme0n1 (259:0), with partition nvme0n1p1 (259:1) mounted at /var;
//   - disk sda (8:0), not partitioned, mounted at /data;
//   - an overlay (0:50) at /rootfs with upperdir /var/overlay/upper;
//   - a tmpfs (0:30) at /tmp.
type fakeHost struct {
	resolver diskResolver
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	root := t.TempDir()
	sysfs := filepath.Join(root, "sys")
	disks := map[string]string{
		"nvme0n1": "devices/pci0000:00/0000:00:04.0/nvme/nvme0/nvme0n1",
		"sda":     "devices/pci0000:00/0000:00:05.0/host0/target0:0:0/0:0:0:0/block/sda",
	}
	for name, dir := range disks {
		writeFile(t, filepath.Join(sysfs, dir, "queue", "scheduler"), "[none] mq-deadline bfq\n")
		writeFile(t, filepath.Join(sysfs, dir, "queue", "rotational"), "0\n")
		if err := os.MkdirAll(filepath.Join(sysfs, "block"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", dir), filepath.Join(sysfs, "block", name)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(sysfs, disks["nvme0n1"], "nvme0n1p1", "partition"), "1\n")
	for dev, dir := range map[string]string{
		"259:0": disks["nvme0n1"],
		"259:1": disks["nvme0n1"] + "/nvme0n1p1",
		"8:0":   disks["sda"],
	} {
		if err := os.MkdirAll(filepath.Join(sysfs, "dev", "block"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "..", dir), filepath.Join(sysfs, "dev", "block", dev)); err != nil {
			t.Fatal(err)
		}
	}
	mountInfo := filepath.Join(root, "mountinfo")
	writeFile(t, mountInfo, `22 1 259:1 / /var rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw
23 1 8:0 / /data rw,relatime shared:2 - ext4 /dev/sda rw
24 1 0:30 / /tmp rw shared:3 - tmpfs tmpfs rw
25 1 0:50 / /rootfs rw,relatime - overlay overlay rw,lowerdir=/var/overlay/l1:/var/overlay/l2,upperdir=/var/overlay/upper,workdir=/var/overlay/work
26 1 0:51 / /lower\040only ro,relatime - overlay overlay ro,lowerdir=/data/l\0401:/var/l2
`)
	devs := map[string]uint64{
		"/var":                unix.Mkdev(259, 1),
		"/var/overlay/upper":  unix.Mkdev(259, 1),
		"/data":               unix.Mkdev(8, 0),
		"/data/l 1":           unix.Mkdev(8, 0),
		"/tmp":                unix.Mkdev(0, 30),
		"/rootfs":             unix.Mkdev(0, 50),
		"/lower only":         unix.Mkdev(0, 51),
		"/missing-from-sysfs": unix.Mkdev(259, 7),
	}
	return &fakeHost{
		resolver: diskResolver{
			sysfs:     sysfs,
			mountInfo: mountInfo,
			stat: func(path string) (uint64, error) {
				dev, ok := devs[path]
				if !ok {
					return 0, fmt.Errorf("stat %q: %w", path, os.ErrNotExist)
				}
				return dev, nil
			},
		},
	}
}

func (h *fakeHost) queue(disk string) string {
	return filepath.Join(h.resolver.sysfs, "block", disk, "queue")
}

func TestQueueDir(t *testing.T) {
	h := newFakeHost(t)
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/var", want: "nvme0n1"},
		{path: "/data", want: "sda"},
		{path: "/rootfs", want: "nvme0n1"},
		{path: "/lower only", want: "sda"},
		{path: "/tmp", want: ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, err := h.resolver.queueDir(tc.path)
			if err != nil {
				t.Fatalf("queueDir(%q) failed: %v", tc.path, err)
			}
			want := ""
			if tc.want != "" {
				want = h.queue(tc.want)
			}
			if got != want {
				t.Errorf("queueDir(%q) = %q, want %q", tc.path, got, want)
			}
		})
	}
	if _, err := h.resolver.queueDir("/nonexistent"); err == nil {
		t.Errorf("queueDir(/nonexistent) succeeded, want error")
	}
}

func TestBFQIdleSettingsDeduplicates(t *testing.T) {
	h := newFakeHost(t)
	settings := h.resolver.bfqIdleSettings([]string{"/var", "/rootfs", "/tmp", "/nonexistent", "/data", "/lower only"})
	var got []string
	for _, s := range settings {
		got = append(got, s.Name())
	}
	want := []string{
		filepath.Join(h.queue("nvme0n1"), "iosched", "slice_idle"),
		filepath.Join(h.queue("sda"), "iosched", "slice_idle"),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("bfqIdleSettings names = %v, want %v", got, want)
	}
}

func TestBFQIdleDelta(t *testing.T) {
	for _, tc := range []struct {
		name       string
		scheduler  string
		rotational string
		sliceIdle  string // "" if the file does not exist.
		wantDelta  bool
	}{
		{name: "bfq idling", scheduler: "mq-deadline kyber [bfq] none", rotational: "0", sliceIdle: "8", wantDelta: true},
		{name: "bfq not idling", scheduler: "mq-deadline kyber [bfq] none", rotational: "0", sliceIdle: "0"},
		{name: "bfq idling on rotational disk", scheduler: "mq-deadline kyber [bfq] none", rotational: "1", sliceIdle: "8"},
		{name: "none", scheduler: "[none] mq-deadline bfq", rotational: "0"},
		{name: "mq-deadline", scheduler: "none [mq-deadline] bfq", rotational: "0"},
		{name: "no scheduler", scheduler: "none", rotational: "0"},
		{name: "bfq without slice_idle", scheduler: "[bfq] none", rotational: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHost(t)
			q := h.queue("nvme0n1")
			writeFile(t, filepath.Join(q, "scheduler"), tc.scheduler+"\n")
			writeFile(t, filepath.Join(q, "rotational"), tc.rotational+"\n")
			idlePath := filepath.Join(q, "iosched", "slice_idle")
			if tc.sliceIdle != "" {
				writeFile(t, idlePath, tc.sliceIdle+"\n")
			}
			s := bfqIdleSetting{sysfsQueue: q, path: "/var"}
			conf := &config.Config{}
			delta, err := s.Delta(conf)
			if err != nil {
				t.Fatalf("Delta failed: %v", err)
			}
			if !tc.wantDelta {
				if delta != nil {
					t.Fatalf("Delta = %+v, want nil", delta)
				}
				return
			}
			if delta == nil {
				t.Fatalf("Delta = nil, want non-nil")
			}
			if delta.Name != idlePath || delta.FromValue != tc.sliceIdle || delta.ToValue != "0" || delta.Mandatory {
				t.Errorf("Delta = %+v, want change of %q from %q to 0, not mandatory", delta, idlePath, tc.sliceIdle)
			}
			if err := delta.Apply(); err != nil {
				t.Fatalf("Apply failed: %v", err)
			}
			if got, err := readSysfs(idlePath); err != nil || got != "0" {
				t.Errorf("slice_idle after Apply = %q, %v; want 0", got, err)
			}
			// The scheduler is never changed.
			if got, err := readSysfs(filepath.Join(q, "scheduler")); err != nil || got != tc.scheduler {
				t.Errorf("scheduler after Apply = %q, %v; want %q", got, err, tc.scheduler)
			}
			if delta, err := s.Delta(conf); err != nil || delta != nil {
				t.Errorf("Delta after Apply = %+v, %v; want nil", delta, err)
			}
		})
	}
}

func TestActiveScheduler(t *testing.T) {
	for in, want := range map[string]string{
		"mq-deadline kyber [bfq] none": "bfq",
		"[none] mq-deadline":           "none",
		"none":                         "",
		"":                             "",
		"[]":                           "",
	} {
		if got := activeScheduler(in); got != want {
			t.Errorf("activeScheduler(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnescapeMountInfo(t *testing.T) {
	for in, want := range map[string]string{
		`/a/b`:          "/a/b",
		`/a\040b`:       "/a b",
		`/a\134b`:       `/a\b`,
		`/a\04`:         `/a\04`,
		`/a\999\011end`: "/a\\999\tend",
	} {
		if got := unescapeMountInfo(in); got != want {
			t.Errorf("unescapeMountInfo(%q) = %q, want %q", in, got, want)
		}
	}
}

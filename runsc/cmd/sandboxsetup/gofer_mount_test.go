// Copyright 2024 The gVisor Authors.
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

package sandboxsetup

import (
	"errors"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: true},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestSafeSetupAndMoveMountDanglingSymlink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(t.TempDir()) failed: %v", err)
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", src, err)
	}
	srcFD, err := unix.OpenTree(unix.AT_FDCWD, src, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
			t.Skipf("open_tree unavailable: %v", err)
		}
		t.Fatalf("unix.OpenTree(%q) failed: %v", src, err)
	}
	defer unix.Close(srcFD)

	missing := filepath.Join(dir, "missing")
	dst := filepath.Join(dir, "dst-dangling")
	if err := os.Symlink(missing, dst); err != nil {
		t.Fatalf("os.Symlink() failed: %v", err)
	}
	if err := safeSetupAndMoveMount(srcFD, src, dst, ""); err == nil {
		t.Errorf("safeSetupAndMoveMount(%q -> %q) unexpectedly succeeded", dst, missing)
	} else if errors.Is(err, unix.ENOSYS) || errors.Is(err, os.ErrPermission) {
		t.Fatalf("safeSetupAndMoveMount(%q -> %q) failed unexpectedly: %v", dst, missing, err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Lstat(%q) err = %v, want %v", missing, err, os.ErrNotExist)
	}
}

func TestResolveMountsNonDir(t *testing.T) {
	root := t.TempDir()
	dirDst := filepath.Join(root, "dir")
	if err := os.Mkdir(dirDst, 0755); err != nil {
		t.Fatalf("os.Mkdir(%q) failed: %v", dirDst, err)
	}
	fileDst := filepath.Join(root, "file")
	if err := os.WriteFile(fileDst, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", fileDst, err)
	}
	erofsDst := filepath.Join(root, "erofs")
	if err := os.WriteFile(erofsDst, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", erofsDst, err)
	}
	fifoDst := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifoDst, 0644); err != nil {
		t.Fatalf("unix.Mkfifo(%q) failed: %v", fifoDst, err)
	}
	if err := os.Symlink("/file", filepath.Join(root, "file-link")); err != nil {
		t.Fatalf("os.Symlink failed: %v", err)
	}
	if err := os.Symlink("/dir", filepath.Join(root, "dir-link")); err != nil {
		t.Fatalf("os.Symlink failed: %v", err)
	}

	mounts := []specs.Mount{
		{Type: "bind", Source: "/src/dir", Destination: "/dir"},
		{Type: "bind", Source: "/src/file", Destination: "/file"},
		{Type: "tmpfs", Destination: "/tmp"},
		{Type: "bind", Source: "/src/erofs", Destination: "/erofs"},
		{Type: "bind", Source: "/src/file", Destination: "/file-link"},
		{Type: "bind", Source: "/src/dir", Destination: "/dir-link"},
		{Type: "bind", Source: "/src/fifo", Destination: "/fifo"},
	}
	mountConfs := []specutils.GoferMountConf{
		{Lower: specutils.Lisafs, Upper: specutils.NoOverlay}, // rootfs
		{Lower: specutils.Lisafs, Upper: specutils.NoOverlay},
		{Lower: specutils.Lisafs, Upper: specutils.NoOverlay},
		{Lower: specutils.Erofs, Upper: specutils.NoOverlay},
		{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay},
		{Lower: specutils.Lisafs, Upper: specutils.NoOverlay},
		{Lower: specutils.Lisafs, Upper: specutils.NoOverlay},
	}

	// /erofs is a file too, but the gofer does not serve it.
	wantNonDir := []bool{false, true, false, false, true, false, true}
	wantDst := []string{"/dir", "/file", "/tmp", "/erofs", "/file", "/dir", "/fifo"}
	for _, withoutChroot := range []bool{false, true} {
		conf := &config.Config{TestOnlyAllowRunAsCurrentUserWithoutChroot: withoutChroot}
		resolved, err := ResolveMounts(conf, mounts, root, mountConfs)
		if err != nil {
			t.Fatalf("ResolveMounts(withoutChroot=%t) failed: %v", withoutChroot, err)
		}
		if len(resolved) != len(mounts) {
			t.Fatalf("ResolveMounts(withoutChroot=%t) returned %d mounts, want %d", withoutChroot, len(resolved), len(mounts))
		}
		for i, m := range resolved {
			if m.NonDir != wantNonDir[i] {
				t.Errorf("ResolveMounts(withoutChroot=%t): mount %d at %q has NonDir = %t, want %t", withoutChroot, i, mounts[i].Destination, m.NonDir, wantNonDir[i])
			}
			if m.Spec.Destination != wantDst[i] {
				t.Errorf("ResolveMounts(withoutChroot=%t): mount %d at %q has destination %q, want %q", withoutChroot, i, mounts[i].Destination, m.Spec.Destination, wantDst[i])
			}
		}
	}
}

func TestWriteReadMounts(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("unix.Pipe() failed: %v", err)
	}
	r := os.NewFile(uintptr(fds[0]), "mounts read")
	defer r.Close()

	want := []specutils.ResolvedMount{
		{Spec: specs.Mount{Type: "bind", Source: "/src", Destination: "/dst", Options: []string{"ro"}}},
		{Spec: specs.Mount{Type: "tmpfs", Destination: "/tmp"}},
		{Spec: specs.Mount{Type: "bind", Source: "/file", Destination: "/file"}, NonDir: true},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- WriteMounts(fds[1], want)
	}()

	got, err := specutils.ReadMounts(r)
	if err != nil {
		t.Fatalf("ReadMounts() failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteMounts() failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadMounts() = %+v, want %+v", got, want)
	}
}

func TestLockedMountFlags(t *testing.T) {
	const atimeMask = unix.MS_NOATIME | unix.MS_RELATIME | unix.MS_STRICTATIME
	for _, tc := range []struct {
		name        string
		flags       uint32
		statfsFlags int64
		want        uint32
		wantAttr    uint64
	}{
		{
			name:     "strictatime mount kept",
			want:     unix.MS_STRICTATIME,
			wantAttr: unix.MOUNT_ATTR_STRICTATIME,
		},
		{
			name:        "relatime mount kept",
			statfsFlags: unix.ST_RELATIME,
			want:        unix.MS_RELATIME,
			wantAttr:    unix.MOUNT_ATTR_RELATIME,
		},
		{
			name:        "noatime mount kept",
			statfsFlags: unix.ST_NOATIME,
			want:        unix.MS_NOATIME,
			wantAttr:    unix.MOUNT_ATTR_NOATIME,
		},
		{
			name:        "nodiratime without atime flag keeps noatime",
			flags:       unix.MS_BIND | unix.MS_REC | unix.MS_NOSUID | unix.MS_NODIRATIME,
			statfsFlags: unix.ST_NOATIME,
			want:        unix.MS_NOATIME,
			wantAttr:    unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOATIME | unix.MOUNT_ATTR_NODIRATIME,
		},
		{
			name:        "strictatime replaces relatime",
			flags:       unix.MS_STRICTATIME,
			statfsFlags: unix.ST_RELATIME,
			want:        0,
			wantAttr:    unix.MOUNT_ATTR_STRICTATIME,
		},
		{
			name:        "strictatime replaces noatime",
			flags:       unix.MS_STRICTATIME,
			statfsFlags: unix.ST_NOATIME,
			want:        0,
			wantAttr:    unix.MOUNT_ATTR_STRICTATIME,
		},
		{
			name:        "relatime replaces noatime",
			flags:       unix.MS_RELATIME,
			statfsFlags: unix.ST_NOATIME,
			want:        0,
			wantAttr:    unix.MOUNT_ATTR_RELATIME,
		},
		{
			name:        "noatime replaces relatime",
			flags:       unix.MS_NOATIME,
			statfsFlags: unix.ST_RELATIME,
			want:        0,
			wantAttr:    unix.MOUNT_ATTR_NOATIME,
		},
		{
			name:        "other flags kept with explicit atime",
			flags:       unix.MS_STRICTATIME,
			statfsFlags: unix.ST_RDONLY | unix.ST_NOEXEC | unix.ST_NODEV | unix.ST_NODIRATIME | unix.ST_RELATIME,
			want:        unix.MS_RDONLY | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_NODIRATIME,
			wantAttr:    unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOEXEC | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NODIRATIME | unix.MOUNT_ATTR_STRICTATIME,
		},
		{
			name:        "ST_NOSUID not kept",
			statfsFlags: unix.ST_NOSUID,
			want:        unix.MS_STRICTATIME,
			wantAttr:    unix.MOUNT_ATTR_STRICTATIME,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := lockedMountFlags(tc.flags, tc.statfsFlags)
			if got != tc.want {
				t.Errorf("lockedMountFlags(%#x, %#x) = %#x, want %#x", tc.flags, tc.statfsFlags, got, tc.want)
			}
			if n := bits.OnesCount32((tc.flags | got) & atimeMask); n != 1 {
				t.Errorf("flags %#x | locked %#x has %d atime flags, want 1", tc.flags, got, n)
			}
			attrSet, attrClr := msFlagsToMountAttr(tc.flags | got)
			if attrSet != tc.wantAttr {
				t.Errorf("msFlagsToMountAttr(%#x) attrSet = %#x, want %#x", tc.flags|got, attrSet, tc.wantAttr)
			}
			if attrClr != unix.MOUNT_ATTR__ATIME {
				t.Errorf("msFlagsToMountAttr(%#x) attrClr = %#x, want %#x", tc.flags|got, attrClr, unix.MOUNT_ATTR__ATIME)
			}
		})
	}
}

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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// LandlockOps is a set of the path operations whose access a Landlock domain
// can restrict.
type LandlockOps uint8

// LandlockOps values.
const (
	// LandlockOpOpen is open(2), including O_CREAT and the open of execve(2).
	LandlockOpOpen LandlockOps = 1 << iota

	// LandlockOpMkdir is mkdir(2).
	LandlockOpMkdir

	// LandlockOpMknod is mknod(2), including the socket file that bind(2)
	// creates.
	LandlockOpMknod

	// LandlockOpSymlink is symlink(2).
	LandlockOpSymlink

	// LandlockOpUnlink is unlink(2).
	LandlockOpUnlink

	// LandlockOpRmdir is rmdir(2).
	LandlockOpRmdir

	// LandlockOpLink is link(2).
	LandlockOpLink

	// LandlockOpRename is rename(2).
	LandlockOpRename
)

// LandlockCheckingFilesystemImpl is implemented by FilesystemImpls that check
// the access of some path operations against the caller's Landlock domain
// themselves.
//
// VFS refuses, with EACCES, the path operations of a task whose Landlock
// domain handles a right that the operation may need, on filesystems that do
// not declare that operation here; see ResolvingPath.checkLandlockGate.
type LandlockCheckingFilesystemImpl interface {
	// LandlockCheckedOps returns the path operations whose access the
	// filesystem checks against the caller's Landlock domain. It must return
	// the same set every time.
	LandlockCheckedOps() LandlockOps
}

// Filesystem rights that the gated path operations may need.
const (
	landlockOpenAccessFS = linux.LANDLOCK_ACCESS_FS_EXECUTE |
		linux.LANDLOCK_ACCESS_FS_WRITE_FILE |
		linux.LANDLOCK_ACCESS_FS_READ_FILE |
		linux.LANDLOCK_ACCESS_FS_READ_DIR |
		linux.LANDLOCK_ACCESS_FS_MAKE_REG
	landlockMakeAccessFS = linux.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		linux.LANDLOCK_ACCESS_FS_MAKE_DIR |
		linux.LANDLOCK_ACCESS_FS_MAKE_REG |
		linux.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		linux.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		linux.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		linux.LANDLOCK_ACCESS_FS_MAKE_SYM
	landlockRemoveAccessFS = linux.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		linux.LANDLOCK_ACCESS_FS_REMOVE_FILE
)

// landlockMknodAccessFS returns the filesystem right that creating a file of
// mode's type needs. A type that is not a creatable file type needs
// LANDLOCK_ACCESS_FS_MAKE_REG, like a regular file.
func landlockMknodAccessFS(mode linux.FileMode) uint64 {
	switch mode.FileType() {
	case linux.ModeDirectory:
		return linux.LANDLOCK_ACCESS_FS_MAKE_DIR
	case linux.ModeSymlink:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SYM
	case linux.ModeCharacterDevice:
		return linux.LANDLOCK_ACCESS_FS_MAKE_CHAR
	case linux.ModeBlockDevice:
		return linux.LANDLOCK_ACCESS_FS_MAKE_BLOCK
	case linux.ModeNamedPipe:
		return linux.LANDLOCK_ACCESS_FS_MAKE_FIFO
	case linux.ModeSocket:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SOCK
	default:
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	}
}

// checkLandlockGate returns EACCES if VFS must refuse to hand path operation
// op, which may need the filesystem rights in accessFS, to the filesystem of
// rp.Mount(), and nil otherwise. VFS refuses it if rp's Landlock domain
// handles any right in accessFS, in any layer, and the filesystem does not
// check op's access against Landlock domains itself (see
// LandlockCheckingFilesystemImpl). Files reached through internal mounts are
// never refused.
//
// VFS calls checkLandlockGate each time it hands op to a filesystem: for the
// filesystem where path resolution starts, and again for each filesystem that
// resolution moves into as it crosses mounts. For example, with a domain that
// handles READ_FILE, opening a file by path fails on every filesystem that
// does not check opens itself, even beneath a rule that allows reading it.
func (rp *ResolvingPath) checkLandlockGate(op LandlockOps, accessFS uint64) error {
	dom := LandlockDomainOf(rp.creds)
	if dom == nil || dom.HandledAccessFS()&accessFS == 0 || rp.mount.IsInternal() {
		return nil
	}
	if c, ok := rp.mount.fs.impl.(LandlockCheckingFilesystemImpl); ok && c.LandlockCheckedOps()&op != 0 {
		return nil
	}
	return linuxerr.EACCES
}

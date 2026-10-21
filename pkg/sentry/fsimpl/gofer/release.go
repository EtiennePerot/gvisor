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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ReleaseServers closes the server connections of all gofer filesystems in
// vfsObj that belong to the given container (InternalFilesystemOptions.UniqueID),
// so that the server process can exit, provided that all of them can operate
// without their server. Otherwise, it does nothing. It returns true if the
// connections were closed.
//
// With directfs, the sentry performs file operations on host FDs itself. It
// only needs the server to open the root of the filesystem (which has no
// parent directory FD to open it from), for xattr syscalls and chmod(2) on
// sockets and symlinks (whose O_PATH host FDs these syscalls reject), and to
// bind(2) and connect(2) host sockets. After release:
//   - A directory root is opened from its own host FD. A regular file root is
//     opened by duplicating host FDs that are opened before the release.
//   - bind(2) and connect(2) of host sockets fail with EPERM, as the server
//     does when host sockets are disabled. bind(2) then falls back to
//     creating a socket file in the sentry.
//   - Sockets and symlinks appear to have no extended attributes.
//   - chmod(2) of host sockets fails with EIO.
//
// Callers must only call ReleaseServers if the servers refuse to bind(2) and
// connect(2) host sockets, and must only set
// InternalFilesystemOptions.AllowServerRelease for filesystems that can't be
// modified through their mount, because it is read-only or is the lower layer
// of an overlay, so that bind(2) and chmod(2) can't reach them. A filesystem
// whose root is a regular file has no sockets or symlinks, so it is released
// regardless. A filesystem whose root is a directory is only released if
// AllowServerRelease is set. The only remaining difference is then that
// extended attributes that the host may have on sockets and symlinks, such as
// SELinux labels, are hidden.
//
// Preconditions: The container's filesystems are not being mounted or
// unmounted concurrently.
func ReleaseServers(ctx context.Context, vfsObj *vfs.VirtualFilesystem, containerName string) bool {
	var filesystems []*filesystem
	for _, vfsfs := range vfsObj.GetFilesystems() {
		defer vfsfs.DecRef(ctx)
		if fs, ok := vfsfs.Impl().(*filesystem); ok && fs.iopts.UniqueID.ContainerName == containerName && !fs.serverReleased.Load() {
			filesystems = append(filesystems, fs)
		}
	}
	if len(filesystems) == 0 {
		return false
	}
	for _, fs := range filesystems {
		if !fs.canReleaseServer() {
			log.Debugf("gofer: not releasing the servers of container %q: filesystem %q needs its server", containerName, fs.iopts.UniqueID.Path)
			return false
		}
	}
	for i, fs := range filesystems {
		if err := fs.prepareServerRelease(ctx); err != nil {
			log.Debugf("gofer: not releasing the servers of container %q: preparing filesystem %q: %v", containerName, fs.iopts.UniqueID.Path, err)
			for _, fs := range filesystems[:i] {
				fs.releasedRoot.close()
				fs.releasedRoot = nil
			}
			return false
		}
	}
	for _, fs := range filesystems {
		fs.renameMu.Lock()
		fs.serverReleased.Store(true)
		fs.renameMu.Unlock()
		fs.client.Close()
	}
	return true
}

// canReleaseServer returns true if fs can operate without its server. See
// ReleaseServers.
func (fs *filesystem) canReleaseServer() bool {
	if !fs.opts.directfs.enabled || fs.iopts.LeakConnection || fs.root == nil {
		return false
	}
	switch fs.root.inode.fileType() {
	case linux.S_IFREG:
		return true
	case linux.S_IFDIR:
		return fs.iopts.AllowServerRelease
	default:
		return false
	}
}

// prepareServerRelease opens host FDs to the root of fs, if it is a regular
// file, so that it can still be opened once the server connection is closed.
func (fs *filesystem) prepareServerRelease(ctx context.Context) error {
	if fs.root.inode.fileType() != linux.S_IFREG {
		return nil
	}
	root := fs.root.inode.impl.(*directfsInode)
	open := func(flags uint32) (int, error) {
		openFD, hostFD, err := root.controlFDLisa.OpenAt(ctx, flags)
		if err != nil {
			return -1, err
		}
		fs.client.CloseFD(ctx, openFD, true /* flush */)
		if hostFD < 0 {
			return -1, unix.EIO
		}
		return hostFD, nil
	}
	readFD, err := open(unix.O_RDONLY)
	if err != nil {
		return err
	}
	// The file may not be writable, in which case opening it for writing
	// fails with the same error after release.
	writeFD, writeErr := open(unix.O_RDWR)
	fs.releasedRoot = &releasedFileRoot{
		readFD:   readFD,
		writeFD:  writeFD,
		writeErr: writeErr,
	}
	return nil
}

// releasedFileRoot holds host FDs to the regular file at the root of a
// filesystem, opened before the filesystem's server connection was closed.
type releasedFileRoot struct {
	// readFD is opened read-only.
	readFD int

	// writeFD is opened read-write, or is -1 if that failed with writeErr.
	writeFD  int
	writeErr error
}

// open returns a new host FD to the file, opened with the given flags.
// Regular file handles are always accessed at explicit offsets, so FDs can be
// shared.
func (r *releasedFileRoot) open(flags uint32) (int, error) {
	fd := r.readFD
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		if r.writeFD < 0 {
			return -1, r.writeErr
		}
		fd = r.writeFD
	}
	newFD, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}
	if flags&unix.O_TRUNC != 0 {
		if err := unix.Ftruncate(newFD, 0); err != nil {
			_ = unix.Close(newFD)
			return -1, err
		}
	}
	return newFD, nil
}

// close closes r's FDs. r may be nil.
func (r *releasedFileRoot) close() {
	if r == nil {
		return
	}
	_ = unix.Close(r.readFD)
	if r.writeFD >= 0 {
		_ = unix.Close(r.writeFD)
	}
}

// openReleasedRoot opens the root of a filesystem whose server connection has
// been released.
//
// Preconditions: i is the root of i.fs, and i.fs.serverReleased is set.
func (i *directfsInode) openReleasedRoot(flags uint32) (handle, error) {
	var (
		fd  int
		err error
	)
	switch i.fileType() {
	case linux.S_IFDIR:
		fd, err = unix.Openat(i.controlFD, ".", int(flags|hostOpenFlags|unix.O_DIRECTORY), 0)
	case linux.S_IFREG:
		fd, err = i.fs.releasedRoot.open(flags)
	default:
		err = unix.EIO
	}
	if err != nil {
		return noHandle, err
	}
	return handle{fd: int32(fd)}, nil
}

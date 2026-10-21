// Copyright 2020 The gVisor Authors.
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

package host

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// MakeResourceID creates a ResourceID for a given application FD. The
// application FD remains the same between restores, e.g. stdout=2 before and
// after restore, but the host FD that is maps to can change between restores.
// This ID is used to map application FDs to their respective FD after a
// restore happens.
func MakeResourceID(containerName string, fd int) checkpoint.ResourceID {
	return checkpoint.ResourceID{
		ContainerName: containerName,
		Path:          fmt.Sprintf("host:%d", fd),
	}
}

// beforeSave is invoked by stateify.
//
// +checklocksexclude:i.bufMu
func (i *inode) beforeSave() {
	if !i.savable {
		panic("host.inode is not savable")
	}
	if i.ftype == unix.S_IFIFO {
		// If this pipe FD is readable, drain it so that bytes in the pipe can
		// be read after restore. (This is a legacy VFS1 feature.) We don't
		// know if the pipe FD is readable, so just try reading and tolerate
		// EBADF from the read.
		i.bufMu.Lock()
		defer i.bufMu.Unlock()
		buf := make([]byte, hostarch.PageSize)
		for {
			n, err := hostfd.Preadv2(int32(i.hostFD), safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:])), -1 /* offset */, 0 /* flags */)
			if n != 0 {
				i.buf = append(i.buf, buf[:n]...)
			}
			if err != nil {
				if err == io.EOF || err == unix.EAGAIN || err == unix.EBADF {
					break
				}
				panic(fmt.Errorf("host.inode.beforeSave: buffering from pipe failed: %v", err))
			}
		}
		if len(i.buf) != 0 {
			i.haveBuf.Store(1)
		}
	}
}

// afterLoad is invoked by stateify.
func (i *inode) afterLoad(ctx context.Context) {
	if !i.restorable {
		log.Infof("Skipping host FD (%+v) that is not restorable", i.restoreKey)
		i.hostFD = -1
		return
	}

	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[i.restoreKey]
	if !ok {
		if d, ok := ctx.Value(CtxDeferredFDRemaps).(*DeferredFDRemaps); ok {
			i.hostFD = -1
			d.add(i)
			return
		}
		panic(fmt.Sprintf("no host FD available for %q, map: %#v", i.restoreKey, fdmap))
	}
	i.remapHostFD(fd)
}

// remapHostFD sets the host FD of a restored inode.
func (i *inode) remapHostFD(fd int) {
	log.Debugf("Remapping host FD from %d to %d", i.hostFD, fd)
	i.hostFD = fd
	i.mmapFile.SetFD(fd)

	if i.epollable {
		if err := unix.SetNonblock(i.hostFD, true); err != nil {
			panic(fmt.Sprintf("host.inode.remapHostFD: failed to set host FD %d non-blocking: %v", i.hostFD, err))
		}
		if err := fdnotifier.AddFD(int32(i.hostFD), &i.queue); err != nil {
			panic(fmt.Sprintf("host.inode.remapHostFD: fdnotifier.AddFD(%d) failed: %v", i.hostFD, err))
		}
	}
}

type deferredFDRemapsKey int

// CtxDeferredFDRemaps is a Context.Value key for a *DeferredFDRemaps. When a
// restore context carries one, host inodes whose FD is missing from
// vfs.CtxRestoreFilesystemFDMap are added to it instead of panicking, and
// have no host FD (-1) until DeferredFDRemaps.Apply remaps them.
const CtxDeferredFDRemaps deferredFDRemapsKey = 0

// DeferredFDRemaps collects host inodes whose host FD was not known when they
// were restored. This is the case when a restore starts decoding the kernel
// state before every container's FDs have been donated.
type DeferredFDRemaps struct {
	inodes []*inode
}

func (d *DeferredFDRemaps) add(i *inode) {
	d.inodes = append(d.inodes, i)
}

// Apply remaps the host FDs of all deferred inodes using fdmap.
//
// Preconditions: The decode that populated d has completed.
func (d *DeferredFDRemaps) Apply(fdmap map[checkpoint.ResourceID]int) error {
	for _, i := range d.inodes {
		fd, ok := fdmap[i.restoreKey]
		if !ok {
			return fmt.Errorf("no host FD available for %q", i.restoreKey)
		}
		i.remapHostFD(fd)
	}
	d.inodes = nil
	return nil
}

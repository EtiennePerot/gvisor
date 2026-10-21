// Copyright 2023 The gVisor Authors.
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

package erofs

import (
	"context"
	"fmt"
	"os"

	gcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(ctx context.Context) {
	fs.memoryFile = pgalloc.MemoryFileFromContext(ctx)
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	if fd, ok := fdmap[fs.iopts.UniqueID]; ok {
		fs.reopenImage(fd)
	}
	// Otherwise, the image FD has not been donated yet; this happens when the
	// kernel state is decoded before every container has registered.
	// CompleteRestore reopens the image.
}

// reopenImage replaces fs.image with the image read from the host FD fd.
func (fs *filesystem) reopenImage(fd int) {
	newImage, err := erofs.OpenImage(os.NewFile(uintptr(fd), "EROFS image file"))
	if err != nil {
		panic(fmt.Sprintf("erofs.OpenImage failed: %v", err))
	}
	if got, want := newImage.SuperBlock(), fs.image.SuperBlock(); got != want {
		panic(fmt.Sprintf("superblock mismatch detected on restore, got %+v, expected %+v", got, want))
	}
	// We need to update the image in place, as there are other pointers
	// pointing to this image as well.
	*fs.image = *newImage
	fs.imageRestored = true
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx gcontext.Context) error {
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx gcontext.Context) {}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx gcontext.Context, opts vfs.CompleteRestoreOptions) error {
	if fs.imageRestored {
		return nil
	}
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		return fmt.Errorf("no image FD available for filesystem with unique ID %q, map: %#v", fs.iopts.UniqueID, fdmap)
	}
	fs.reopenImage(fd)
	return nil
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ context.Context, parent *dentry) {
	d.parent.Store(parent)
}

// afterLoad is called by stateify.
func (d *dentry) afterLoad(context.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}

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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// TestPrepareSaveRefreshesMetadata checks that saving refreshes the
// non-authoritative cached metadata of regular files only if restore may
// validate it.
func TestPrepareSaveRefreshesMetadata(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		interop                   InteropMode
		validateMetadataOnRestore bool
		wantRefresh               bool
	}{
		{name: "shared", interop: InteropModeShared, validateMetadataOnRestore: false, wantRefresh: false},
		{name: "shared-validate", interop: InteropModeShared, validateMetadataOnRestore: true, wantRefresh: true},
		// Cached metadata is authoritative, so it is never refreshed.
		{name: "exclusive", interop: InteropModeExclusive, validateMetadataOnRestore: false, wantRefresh: false},
		{name: "exclusive-validate", interop: InteropModeExclusive, validateMetadataOnRestore: true, wantRefresh: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			fs := filesystem{
				mf:          pgalloc.MemoryFileFromContext(ctx),
				inoByKey:    make(map[inoKey]uint64),
				inodeByKey:  make(map[inoKey]*inode),
				clock:       ktime.RealtimeClockFromContext(ctx),
				dentryCache: &dentryCache{maxCachedDentries: 0},
			}
			fs.opts.interop = tc.interop
			fs.savedDentryRW = make(map[*dentry]savedDentryRW)

			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
				t.Fatalf("os.WriteFile: %v", err)
			}
			controlFD, err := unix.Open(path, unix.O_PATH, 0)
			if err != nil {
				t.Fatalf("unix.Open: %v", err)
			}
			d, err := fs.newDirectfsDentry(controlFD)
			if err != nil {
				t.Fatalf("fs.newDirectfsDentry: %v", err)
			}

			// Change the file behind the client's back.
			if err := os.WriteFile(path, []byte("new and longer"), 0644); err != nil {
				t.Fatalf("os.WriteFile: %v", err)
			}

			opts := vfs.PrepareSaveOptions{ValidateMetadataOnRestore: tc.validateMetadataOnRestore}
			if err := d.prepareSaveRecursive(ctx, &opts); err != nil {
				t.Fatalf("d.prepareSaveRecursive: %v", err)
			}
			want := uint64(len("old"))
			if tc.wantRefresh {
				want = uint64(len("new and longer"))
			}
			if got := d.inode.size.Load(); got != want {
				t.Errorf("cached size after prepareSaveRecursive: got %d, want %d", got, want)
			}
		})
	}
}

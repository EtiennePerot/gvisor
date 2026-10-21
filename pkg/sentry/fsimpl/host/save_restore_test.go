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

package host

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func restoreContext(fdmap map[checkpoint.ResourceID]int, d *DeferredFDRemaps) context.Context {
	ctx := context.WithValue(context.Background(), vfs.CtxRestoreFilesystemFDMap, fdmap)
	if d != nil {
		ctx = context.WithValue(ctx, CtxDeferredFDRemaps, d)
	}
	return ctx
}

func TestAfterLoadRemapsHostFD(t *testing.T) {
	key := MakeResourceID("cont", 1)
	i := &inode{restorable: true, restoreKey: key}
	i.afterLoad(restoreContext(map[checkpoint.ResourceID]int{key: 42}, &DeferredFDRemaps{}))
	if i.hostFD != 42 {
		t.Errorf("hostFD after afterLoad = %d, want 42", i.hostFD)
	}
}

func TestAfterLoadMissingHostFDPanics(t *testing.T) {
	i := &inode{restorable: true, restoreKey: MakeResourceID("cont", 1)}
	defer func() {
		if recover() == nil {
			t.Errorf("afterLoad without host FD or DeferredFDRemaps did not panic")
		}
	}()
	i.afterLoad(restoreContext(map[checkpoint.ResourceID]int{}, nil))
}

func TestDeferredFDRemaps(t *testing.T) {
	key1 := MakeResourceID("cont", 1)
	key2 := MakeResourceID("cont", 2)
	i1 := &inode{restorable: true, restoreKey: key1}
	i2 := &inode{restorable: true, restoreKey: key2}
	var d DeferredFDRemaps
	ctx := restoreContext(map[checkpoint.ResourceID]int{}, &d)
	i1.afterLoad(ctx)
	i2.afterLoad(ctx)
	if i1.hostFD != -1 || i2.hostFD != -1 {
		t.Errorf("hostFDs of deferred inodes = %d, %d, want -1, -1", i1.hostFD, i2.hostFD)
	}

	if err := d.Apply(map[checkpoint.ResourceID]int{key1: 42}); err == nil {
		t.Errorf("Apply() with a missing host FD succeeded, want error")
	}
	if err := d.Apply(map[checkpoint.ResourceID]int{key1: 42, key2: 43}); err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}
	if i1.hostFD != 42 || i2.hostFD != 43 {
		t.Errorf("hostFDs after Apply() = %d, %d, want 42, 43", i1.hostFD, i2.hostFD)
	}
}

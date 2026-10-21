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

package pgalloc

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
)

func newTestMemFile(t *testing.T) *os.File {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-deferred-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	return os.NewFile(uintptr(fd), "pgalloc-deferred-test")
}

func testMemoryFileOpts(id checkpoint.ResourceID) MemoryFileOpts {
	return MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		ResourceID:              id,
	}
}

func TestMemoryFileForRestore(t *testing.T) {
	known := checkpoint.ResourceID{ContainerName: "a", Path: "/"}
	missing := checkpoint.ResourceID{ContainerName: "b", Path: "/"}
	mf, err := NewMemoryFile(newTestMemFile(t), testMemoryFileOpts(known))
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	defer mf.Destroy()
	mfmap := map[checkpoint.ResourceID]*MemoryFile{known: mf}
	ctx := context.WithValue(context.Background(), CtxMemoryFileMap, mfmap)

	if got, ok := MemoryFileForRestore(ctx, known); !ok || got != mf {
		t.Errorf("MemoryFileForRestore(%v) = %p, %t, want %p, true", known, got, ok, mf)
	}
	if got, ok := MemoryFileForRestore(ctx, missing); ok {
		t.Errorf("MemoryFileForRestore(%v) without DeferredMemoryFiles = %p, true, want false", missing, got)
	}

	var d DeferredMemoryFiles
	ctx = context.WithValue(ctx, CtxDeferredMemoryFiles, &d)
	if got, ok := MemoryFileForRestore(ctx, known); !ok || got != mf {
		t.Errorf("MemoryFileForRestore(%v) with DeferredMemoryFiles = %p, %t, want %p, true", known, got, ok, mf)
	}
	placeholder, ok := MemoryFileForRestore(ctx, missing)
	if !ok || placeholder == nil {
		t.Fatalf("MemoryFileForRestore(%v) with DeferredMemoryFiles = %p, %t, want placeholder, true", missing, placeholder, ok)
	}
	if again, _ := MemoryFileForRestore(ctx, missing); again != placeholder {
		t.Errorf("second MemoryFileForRestore(%v) = %p, want same placeholder %p", missing, again, placeholder)
	}
	if err := d.CheckResolved(); err == nil {
		t.Errorf("CheckResolved() with an uninitialized placeholder succeeded, want error")
	}

	// Creating the memory file initializes the placeholder in place.
	got, err := d.NewMemoryFile(newTestMemFile(t), testMemoryFileOpts(missing))
	if err != nil {
		t.Fatalf("DeferredMemoryFiles.NewMemoryFile: %v", err)
	}
	defer got.Destroy()
	if got != placeholder {
		t.Errorf("DeferredMemoryFiles.NewMemoryFile() = %p, want placeholder %p", got, placeholder)
	}
	if got.FD() < 0 {
		t.Errorf("initialized placeholder has no file")
	}
	if err := d.CheckResolved(); err != nil {
		t.Errorf("CheckResolved() after initializing all placeholders: %v", err)
	}

	// Other memory files are created as usual.
	other, err := d.NewMemoryFile(newTestMemFile(t), testMemoryFileOpts(checkpoint.ResourceID{ContainerName: "c", Path: "/"}))
	if err != nil {
		t.Fatalf("DeferredMemoryFiles.NewMemoryFile: %v", err)
	}
	defer other.Destroy()
	if other == placeholder || other == mf {
		t.Errorf("DeferredMemoryFiles.NewMemoryFile() for an unknown ID reused an existing MemoryFile")
	}
}

func TestNilDeferredMemoryFiles(t *testing.T) {
	var d *DeferredMemoryFiles
	mf, err := d.NewMemoryFile(newTestMemFile(t), testMemoryFileOpts(checkpoint.ResourceID{ContainerName: "a", Path: "/"}))
	if err != nil {
		t.Fatalf("(*DeferredMemoryFiles)(nil).NewMemoryFile: %v", err)
	}
	mf.Destroy()
}

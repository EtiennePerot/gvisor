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

package boot

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func TestLocalStateFileReaderRegularFile(t *testing.T) {
	data := bytes.Repeat([]byte("state"), stateio.StateFileFDReadBytes/4)
	path := t.TempDir() + "/checkpoint.img"
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write state file: %v", err)
	}
	f, err := fd.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open state file: %v", err)
	}
	r, err := newLocalStateFileReader(f)
	if err != nil {
		t.Fatalf("newLocalStateFileReader failed: %v", err)
	}
	defer r.Close()
	if _, ok := r.(*stateio.BufReader); !ok {
		t.Errorf("got reader of type %T for a regular file, want *stateio.BufReader", r)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %d bytes that don't match the %d bytes written", len(got), len(data))
	}
}

func TestLocalStateFileReaderSmallFile(t *testing.T) {
	data := bytes.Repeat([]byte("s"), stateio.StateFileFDReadBytes)
	path := t.TempDir() + "/checkpoint.img"
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write state file: %v", err)
	}
	f, err := fd.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open state file: %v", err)
	}
	r, err := newLocalStateFileReader(f)
	if err != nil {
		t.Fatalf("newLocalStateFileReader failed: %v", err)
	}
	defer r.Close()
	if _, ok := r.(*stateio.BufReader); ok {
		t.Errorf("got *stateio.BufReader for a file of %d bytes, want the file itself", len(data))
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %d bytes that don't match the %d bytes written", len(got), len(data))
	}
}

func TestLocalStateFileReaderEmptyFile(t *testing.T) {
	path := t.TempDir() + "/checkpoint.img"
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatalf("failed to write state file: %v", err)
	}
	f, err := fd.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open state file: %v", err)
	}
	if r, err := newLocalStateFileReader(f); err == nil {
		r.Close()
		t.Errorf("newLocalStateFileReader succeeded for an empty file, want error")
	}
}

func TestLocalStateFileReaderPipe(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer unix.Close(fds[1])
	// Pipes report a size of 0, so they are rejected as empty for now. Either
	// way, they must not be read at offsets.
	r, err := newLocalStateFileReader(fd.New(fds[0]))
	if err != nil {
		return
	}
	defer r.Close()
	if _, ok := r.(*stateio.BufReader); ok {
		t.Errorf("got *stateio.BufReader for a pipe, want a sequential reader")
	}
}

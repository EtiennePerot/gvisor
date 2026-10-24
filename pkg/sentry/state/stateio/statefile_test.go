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

package stateio

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rand"
)

func TestStateFileFDReader(t *testing.T) {
	const maxSize = 3*StateFileFDReadBytes*stateFileFDMaxReads + 3
	data := make([]byte, maxSize)
	_, _ = rand.Read(data)
	for _, size := range []int{
		0,
		1,
		StateFileFDReadBytes - 1,
		StateFileFDReadBytes,
		StateFileFDReadBytes + 1,
		StateFileFDReadBytes * stateFileFDMaxReads,
		StateFileFDReadBytes*stateFileFDMaxReads + 1,
		maxSize,
	} {
		// Read the file both with large reads and with small reads like those
		// of compressio.SimpleReader's bufio.Reader.
		for _, readBytes := range []int{4096, 256 << 10, 2 * StateFileFDReadBytes} {
			t.Run(fmt.Sprintf("Size%d_ReadBytes%d", size, readBytes), func(t *testing.T) {
				f, err := os.CreateTemp(t.TempDir(), "statefile")
				if err != nil {
					t.Fatalf("failed to create file: %v", err)
				}
				defer f.Close()
				if _, err := f.Write(data[:size]); err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
				fd, err := unix.Dup(int(f.Fd()))
				if err != nil {
					t.Fatalf("failed to dup file: %v", err)
				}
				r, err := NewStateFileFDReader(int32(fd))
				if err != nil {
					t.Fatalf("NewStateFileFDReader failed: %v", err)
				}
				defer r.Close()
				got, err := io.ReadAll(bufio.NewReaderSize(r, readBytes))
				if err != nil {
					t.Fatalf("read failed: %v", err)
				}
				if !bytes.Equal(got, data[:size]) {
					t.Errorf("read %d bytes that don't match the %d bytes written", len(got), size)
				}
			})
		}
	}
}

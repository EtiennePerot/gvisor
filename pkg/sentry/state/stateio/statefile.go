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

const (
	// StateFileFDReadBytes is the size of each read issued by the BufReader
	// returned by NewStateFileFDReader. Large reads are efficient even on
	// slow or busy disks. A state file that is no larger than this is read
	// by a single read, so there is nothing to read ahead.
	StateFileFDReadBytes = 4 << 20

	// Only two reads are in flight at a time: the state file is decoded
	// sequentially, so one read can complete while the decoder consumes the
	// other, and each parallel read adds a worker goroutine and raises
	// GOMAXPROCS (see aio.NewGoQueue).
	stateFileFDMaxReads = 2
)

// NewStateFileFDReader returns a BufReader that reads a state file from the
// given host file descriptor, reading ahead of the consumer. It takes
// ownership of the file descriptor, even if it returns a non-nil error.
//
// Preconditions: fd refers to a regular file, positioned at offset 0.
func NewStateFileFDReader(fd int32) (*BufReader, error) {
	return NewBufReader(NewFDReader(fd, StateFileFDReadBytes, 1 /* maxRanges */, stateFileFDMaxReads), StateFileFDReadBytes*stateFileFDMaxReads)
}

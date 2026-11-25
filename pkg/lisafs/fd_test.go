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

package lisafs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

type publicationTestFS struct {
	ControlFDImpl
	t *testing.T
	c *Connection
}

// +checklocksread:fs.c.server.renameMu
func (fs *publicationTestFS) newDir() *ControlFD {
	fd := &ControlFD{}
	fs.c.server.root.IncRef()
	fd.Init(fs.c, fs.c.server.root, linux.ModeDirectory, fs)
	return fd
}

// +checklocksread:fs.c.server.renameMu
func (fs *publicationTestFS) Walk(string) (*ControlFD, Statx, error) {
	fs.c.fdsMu.RLock()
	count := len(fs.c.fds)
	fs.c.fdsMu.RUnlock()
	if count != 1 {
		fs.t.Errorf("connection has %d FDs during traversal, want only the root", count)
	}
	return fs.newDir(), Statx{}, nil
}

type closeOnlyOpenFD struct{ OpenFDImpl }
type closeOnlySocketFD struct{ BoundSocketFDImpl }

func (*publicationTestFS) Close() {}
func (closeOnlyOpenFD) Close()    {}
func (closeOnlySocketFD) Close()  {}

func TestFDPublication(t *testing.T) {
	c := &Connection{server: NewServer(), fds: make(map[FDID]genericFD), nextFDID: 1, maxMessageSize: MaxMessageSize()}
	defer c.server.Destroy()
	fs := publicationTestFS{t: t, c: c}

	fs.c.server.renameMu.RLock()
	root := fs.newDir()
	fs.c.server.renameMu.RUnlock()
	var open OpenFD
	open.Init(root, 0, closeOnlyOpenFD{})
	var socket BoundSocketFD
	socket.Init(root, closeOnlySocketFD{})

	c.fdsMu.RLock()
	count := len(c.fds)
	c.fdsMu.RUnlock()
	if count != 0 {
		t.Fatalf("connection has %d FDs before publication, want 0", count)
	}
	c.removeFD(c.publishFD(&open))
	c.removeFD(c.publishFD(&socket))

	req := WalkReq{DirFD: c.publishFD(root), Path: StringArray{"a", "b"}}
	var comm sockCommunicator
	reqLen := uint32(req.SizeBytes())
	req.MarshalBytes(comm.PayloadBuf(reqLen))
	respLen, err := WalkHandler(c, &comm, reqLen)
	if err != nil {
		t.Fatalf("WalkHandler: %v", err)
	}
	var resp WalkResp
	if _, ok := resp.CheckedUnmarshal(comm.PayloadBuf(respLen)); !ok || resp.Status != WalkSuccess || len(resp.Inodes) != len(req.Path) {
		t.Fatalf("unexpected Walk response: %v", resp)
	}
	for _, i := range resp.Inodes {
		c.removeFD(i.ControlFD)
	}
	c.removeFD(req.DirFD)
	if got := root.ReadRefs(); got != 0 {
		t.Errorf("root has %d references after close, want 0", got)
	}
}

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

package server

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Echo is a test control object.
type Echo struct{}

// Echo returns its argument.
func (*Echo) Echo(arg *string, ret *string) error {
	*ret = *arg
	return nil
}

// TestConnectBeforeServing checks that clients can connect to a socket
// returned by CreateSocket before the server starts, and that their calls are
// served once it does.
func TestConnectBeforeServing(t *testing.T) {
	addr := fmt.Sprintf("\x00control-server-test.%010d", rand.Int())
	fd, err := CreateSocket(addr)
	if err != nil {
		t.Fatalf("CreateSocket(%q) failed: %v", addr, err)
	}
	srv, err := CreateFromFD(fd)
	if err != nil {
		t.Fatalf("CreateFromFD failed: %v", err)
	}
	srv.Register(&Echo{})

	// Connect before the server is serving: this must not be refused.
	conn, err := unet.Connect(addr, false)
	if err != nil {
		t.Fatalf("unet.Connect(%q) before StartServing failed: %v", addr, err)
	}
	client := urpc.NewClient(conn)
	defer client.Close()

	done := make(chan error, 1)
	var got string
	go func() {
		arg := "hello"
		done <- client.Call("Echo.Echo", &arg, &got)
	}()
	select {
	case err := <-done:
		t.Fatalf("Call returned before the server started serving: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := srv.StartServing(); err != nil {
		t.Fatalf("StartServing failed: %v", err)
	}
	defer srv.Stop(time.Second)
	if err := <-done; err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if got != "hello" {
		t.Errorf("Call returned %q, want %q", got, "hello")
	}
}

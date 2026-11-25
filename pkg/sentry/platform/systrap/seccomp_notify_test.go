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

package systrap

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifySeccompNotifyFDListener(t *testing.T) {
	// newSystrapTest initializes seccompNotifyIsSupported.
	_, as, _, _ := newSystrapTest(t)
	if !seccompNotifyIsSupported {
		t.Skip("seccomp user notification is not supported")
	}
	fd := as.(*subprocess).syscallThread.seccompNotify.Fd()
	if err := verifySeccompNotifyFD(fd); err != nil {
		t.Errorf("verifySeccompNotifyFD(listener) = %v, want nil", err)
	}
	// ioctl(2) truncates the FD to 32 bits, so this refers to the listener too.
	if err := verifySeccompNotifyFD(1<<32 | fd); err == nil {
		t.Errorf("verifySeccompNotifyFD(1<<32 | listener) = nil, want error")
	}
}

func TestVerifySeccompNotifyFDNotListener(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatalf("cannot create eventfd: %v", err)
	}
	defer unix.Close(efd)
	sfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("cannot create socket: %v", err)
	}
	defer unix.Close(sfd)
	devNull, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("cannot open /dev/null: %v", err)
	}
	defer devNull.Close()
	urandom, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatalf("cannot open /dev/urandom: %v", err)
	}
	defer urandom.Close()
	pathFD, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("cannot open / with O_PATH: %v", err)
	}
	defer unix.Close(pathFD)
	closed, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatalf("cannot create eventfd: %v", err)
	}
	unix.Close(closed)

	for _, tc := range []struct {
		name string
		fd   uintptr
	}{
		{"pipe", r.Fd()},
		{"eventfd", uintptr(efd)},
		{"unix socket", uintptr(sfd)},
		{"/dev/null", devNull.Fd()},
		{"/dev/urandom", urandom.Fd()},
		{"O_PATH", uintptr(pathFD)},
		{"closed", uintptr(closed)},
	} {
		if err := verifySeccompNotifyFD(tc.fd); err == nil {
			t.Errorf("verifySeccompNotifyFD(%s) = nil, want error", tc.name)
		}
	}
}

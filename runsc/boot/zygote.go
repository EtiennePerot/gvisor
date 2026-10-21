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
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/starttime"
)

// zygoteState is the state of a sandbox booted as a zygote: a sandbox booted
// ahead of time from a spec stripped of everything specific to the container
// that will run in it, and that a single root container later adopts. See
// runsc/container/zygote.go.
type zygoteState struct {
	// enabled is set if the sandbox was booted as a zygote.
	enabled bool

	// adopted is set once Adopt has started. A zygote is adopted at most
	// once, and can neither start nor restore a container before.
	adopted bool
}

// errZygoteNotAdopted is returned by operations that need a container in a
// zygote that no container adopted.
var errZygoteNotAdopted = errors.New("sandbox is a zygote that no container adopted")

// checkAdoptedLocked returns an error if l is a zygote that was not adopted.
//
// +checklocks:l.mu
func (l *Loader) checkAdoptedLocked() error {
	if l.zygote.enabled && !l.zygote.adopted {
		return errZygoteNotAdopted
	}
	return nil
}

// Adopt binds a zygote to the root container described by args: it gives the
// root container its spec, stdio and gofer connections, which replace the
// zygote's placeholders.
//
// Nothing the zygote booted with needs to be undone: its spec had no process
// arguments, environment, hostname, rootfs, mount sources or network, and
// the zygote never ran any application code. The root filesystem is only
// mounted when the container starts (and restore builds a new kernel), so
// the boot-time kernel holds no gofer connection.
func (cm *containerManager) Adopt(args *sentryapi.AdoptArgs, _ *struct{}) error {
	defer args.FilePayload.Close()
	timer := starttime.Timer("Adopt")
	l := cm.l
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case !l.zygote.enabled:
		return errors.New("sandbox is not a zygote")
	case l.zygote.adopted:
		return errors.New("zygote was already adopted")
	case l.state != created:
		return fmt.Errorf("cannot adopt a zygote in state %s", l.state)
	case args.Spec == nil || args.Spec.Process == nil:
		return errors.New("missing spec")
	case args.NumStdio != len(l.root.stdioFDs):
		return fmt.Errorf("got %d stdio files, zygote has %d", args.NumStdio, len(l.root.stdioFDs))
	}
	want := args.NumStdio + args.NumGoferFDs + args.NumGoferFilestoreFDs
	if args.HaveDevGofer {
		want++
	}
	if args.HaveMountsFile {
		want++
	}
	if len(args.Files) != want {
		return fmt.Errorf("got %d files, want %d", len(args.Files), want)
	}
	files := args.Files
	take := func(n int) []*os.File {
		r := files[:n]
		files = files[n:]
		return r
	}
	stdios := take(args.NumStdio)
	gofers := take(args.NumGoferFDs)
	filestores := take(args.NumGoferFilestoreFDs)
	var devGofer, mounts *os.File
	if args.HaveDevGofer {
		devGofer = take(1)[0]
	}
	if args.HaveMountsFile {
		mounts = take(1)[0]
	}

	// From here on, a failure leaves the zygote unusable.
	l.zygote.adopted = true

	spec := args.Spec
	if mounts != nil {
		// Like a normal boot, wait for the gofer to resolve the mounts.
		cleanMounts, err := specutils.ReadMounts(mounts)
		if err != nil {
			return fmt.Errorf("reading resolved mounts: %w", err)
		}
		spec.Mounts = cleanMounts
		timer.Reached("resolved mounts read")
	}

	// Replace stdio in place: host FD numbers must stay stable across
	// checkpoint and restore.
	for i, f := range stdios {
		if err := unix.Dup3(int(f.Fd()), l.root.stdioFDs[i].FD(), unix.O_CLOEXEC); err != nil {
			return fmt.Errorf("replacing stdio %d: %w", i, err)
		}
	}
	goferFDs, err := fd.NewFromFiles(gofers)
	if err != nil {
		return fmt.Errorf("dup'ing gofer files: %w", err)
	}
	filestoreFDs, err := fd.NewFromFiles(filestores)
	if err != nil {
		return fmt.Errorf("dup'ing gofer filestore files: %w", err)
	}
	var devGoferFD *fd.FD
	if devGofer != nil {
		if devGoferFD, err = fd.NewFromFile(devGofer); err != nil {
			return fmt.Errorf("dup'ing device gofer file: %w", err)
		}
	}
	// A zygote boots without gofer connections, but close whatever it has
	// for good measure.
	for _, f := range l.root.goferFDs {
		_ = f.Close()
	}
	for _, f := range l.root.goferFilestoreFDs {
		_ = f.Close()
	}
	if l.root.devGoferFD != nil {
		_ = l.root.devGoferFD.Close()
	}
	l.root.goferFDs = goferFDs
	l.root.goferFilestoreFDs = filestoreFDs
	l.root.devGoferFD = devGoferFD
	l.root.goferMountConfs = args.GoferMountConfs

	// Rebuild everything that New derived from the parts of the spec that a
	// zygote boots without. runsc only lets a container adopt a zygote
	// booted from a spec that is otherwise identical.
	// The container name comes from annotations, which are part of the
	// shape, so it is unchanged.
	l.registerContainerNameLocked(spec, l.root.cid, l.root.containerName)
	l.root.spec = spec
	if l.mountHints, err = sentryapi.NewPodMountHints(spec); err != nil {
		return fmt.Errorf("creating pod mount hints: %w", err)
	}
	ctx := l.k.SupervisorContext()
	l.k.RootUTSNamespace().SetHostName(ctx, spec.Hostname)
	l.k.RootUTSNamespace().SetDomainName(ctx, spec.Domainname)
	creds := getRootCredentials(spec, l.root.conf, l.k.RootUserNamespace())
	if creds == nil {
		return errors.New("getting root credentials")
	}
	procArgs, err := createProcessArgs(l.root.cid, spec, l.root.conf, creds, l.k, l.k.RootPIDNamespace())
	if err != nil {
		return fmt.Errorf("creating init process args: %w", err)
	}
	l.root.procArgs = procArgs
	timer.Reached("root container adopted")
	timer.Log()
	log.Infof("Zygote adopted by container %q", l.root.cid)
	return nil
}

// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/capabilitytest"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/filter"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	fsgofer "gvisor.dev/gvisor/runsc/gofer/fs"
	"gvisor.dev/gvisor/runsc/specutils"
)

// procSelfFD is passed as Args.ProcSelfFD to every loader created by tests.
var procSelfFD int

func init() {
	log.SetLevel(log.Debug)
	if err := fsgofer.OpenProcSelfFD("/proc/self/fd"); err != nil {
		panic(err)
	}
	fd, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}
	procSelfFD = fd
}

func testConfig() *config.Config {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(testFlags)
	conf, err := config.NewFromFlags(testFlags)
	if err != nil {
		panic(err)
	}
	// Change test defaults.
	conf.RootDir = "unused_root_dir"
	conf.Network = config.NetworkNone
	conf.DisableSeccomp = true
	return conf
}

// testSpec returns a simple spec that can be used in tests.
func testSpec() *specs.Spec {
	return &specs.Spec{
		// The host filesystem root is the sandbox root.
		Root: &specs.Root{
			Path:     "/",
			Readonly: true,
		},
		Process: &specs.Process{
			Args: []string{"/bin/true"},
		},
	}
}

// startGofer starts a new gofer routine serving 'root' path. It returns the
// sandbox side of the connection, and a function that when called will stop the
// gofer.
func startGofer(root string, conf *config.Config) (int, func(), error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	sandboxEnd, goferEnd := fds[0], fds[1]

	socket, err := unet.NewSocket(goferEnd)
	if err != nil {
		unix.Close(sandboxEnd)
		unix.Close(goferEnd)
		return 0, nil, fmt.Errorf("error creating server on FD %d: %v", goferEnd, err)
	}
	server := lisafs.NewServer()
	connImpl := fsgofer.NewConnectionImpl(&fsgofer.Config{
		HostUDS:            conf.GetHostUDS(),
		HostFifo:           conf.HostFifo,
		DonateMountPointFD: conf.DirectFS,
	})
	c, err := server.CreateConnection(socket, root, fsgofer.ConnectionOpts(true), connImpl)
	if err != nil {
		return 0, nil, err
	}
	server.StartConnection(c)
	// Closing the gofer socket will stop the gofer and exit goroutine above.
	cleanup := func() {
		if err := socket.Close(); err != nil {
			log.Warningf("Error closing gofer socket: %v", err)
		}
		server.Wait()
		server.Destroy()
	}
	return sandboxEnd, cleanup, nil
}

// createLoader creates a Loader for spec. The root and each bind mount of
// spec get a gofer.
func createLoader(conf *config.Config, spec *specs.Spec) (*Loader, func(), error) {
	sock := fmt.Sprintf("\x00loader-test.%010d", rand.Int())
	fd, err := server.CreateSocket(sock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create socket: %w", err)
	}
	var (
		goferFDs   []int
		mountConfs []specutils.GoferMountConf
		cu         cleanup.Cleanup
		errCu      cleanup.Cleanup
	)
	defer cu.Clean()
	defer errCu.Clean()
	errCu.Add(func() { unix.Close(fd) })
	goferRoots := []string{spec.Root.Path}
	for _, m := range spec.Mounts {
		if specutils.HasMountConfig(m) {
			goferRoots = append(goferRoots, m.Source)
		}
	}
	for _, goferRoot := range goferRoots {
		sandEnd, stopGofer, err := startGofer(goferRoot, conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to start gofer for %q: %w", goferRoot, err)
		}
		cu.Add(stopGofer)
		errCu.Add(func() { unix.Close(sandEnd) })
		goferFDs = append(goferFDs, sandEnd)
		mountConfs = append(mountConfs, specutils.GoferMountConf{Lower: specutils.Lisafs, Upper: specutils.NoOverlay})
	}

	// Loader takes ownership of stdio.
	var stdio []int
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		fd := int(f.Fd())
		newFd, err := unix.Dup(fd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to dup FD %d: %w", fd, err)
		}
		errCu.Add(func() { unix.Close(newFd) })
		stdio = append(stdio, newFd)
	}

	args := Args{
		ID:               "foo",
		Spec:             spec,
		Conf:             conf,
		ControllerFD:     fd,
		GoferFDs:         goferFDs,
		DevGoferFD:       -1,
		StdioFDs:         stdio,
		GoferMountConfs:  mountConfs,
		PodInitConfigFD:  -1,
		ExecFD:           -1,
		ProcSelfFD:       procSelfFD,
		RootfsUpperTarFD: -1,
		CPUDMALatencyFD:  -1,
	}
	errCu.Release()
	l, err := New(args)
	if err != nil {
		return nil, nil, fmt.Errorf("boot.New: %w", err)
	}
	return l, cu.Release(), nil
}

// TestRun runs a simple application in a sandbox and checks that it succeeds.
func TestRun(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}

	defer l.Destroy()
	defer cleanup()

	// Start a goroutine to read the start chan result, otherwise Run will
	// block forever.
	var resultChanErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		resultChanErr = <-l.ctrl.manager.startResultChan
		wg.Done()
	}()

	// Run the container.
	if err := l.Run(); err != nil {
		t.Errorf("error running container: %v", err)
	}

	// We should have not gotten an error on the startResultChan.
	wg.Wait()
	if resultChanErr != nil {
		t.Errorf("error on startResultChan: %v", resultChanErr)
	}

	// Wait for the application to exit.  It should succeed.
	if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
		t.Errorf("application exited with %s, want exit status 0", status)
	}
}

// TestStartSignal tests that the controller Start message will cause
// WaitForStartSignal to return.
func TestStartSignal(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer l.ctrl.srv.Stop(time.Hour)

	// Start a goroutine that calls WaitForStartSignal and writes to a
	// channel when it returns.
	waitFinished := make(chan struct{})
	go func() {
		l.WaitForStartSignal()
		// Pretend that Run() executed and returned no error.
		l.ctrl.manager.startResultChan <- nil
		waitFinished <- struct{}{}
	}()

	// Nothing has been written to the channel, so waitFinished should not
	// return.  Give it a little bit of time to make sure the goroutine has
	// started.
	select {
	case <-waitFinished:
		t.Errorf("WaitForStartSignal completed but it should not have")
	case <-time.After(50 * time.Millisecond):
		// OK.
	}

	// Trigger the control server StartRoot method.
	cid := "foo"
	if err := l.ctrl.manager.StartRoot(&cid, nil); err != nil {
		t.Errorf("error calling StartRoot: %v", err)
	}

	// Now WaitForStartSignal should return (within a short amount of
	// time).
	select {
	case <-waitFinished:
		// OK.
	case <-time.After(50 * time.Millisecond):
		t.Errorf("WaitForStartSignal did not complete but it should have")
	}
}

// TestRestoreFailBeforeStart checks that a restore that fails before it starts
// restoring reports the failure.
func TestRestoreFailBeforeStart(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	if err := l.ctrl.manager.Restore(&sentryapi.RestoreOpts{}, nil); err == nil {
		t.Fatalf("restoring without files succeeded")
	}
	if err := l.waitRestore(); err == nil {
		t.Errorf("waiting for the failed restore succeeded")
	}
}

// watchStartupHeapReleases replaces l.freeOSMemory. It returns a channel that
// receives a value for each release.
func watchStartupHeapReleases(l *Loader) <-chan struct{} {
	released := make(chan struct{}, 10)
	l.freeOSMemory = func() { released <- struct{}{} }
	return released
}

// expectOneStartupHeapRelease checks that exactly one release happens.
func expectOneStartupHeapRelease(t *testing.T, released <-chan struct{}) {
	t.Helper()
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatalf("startup heap was not released")
	}
	select {
	case <-released:
		t.Errorf("startup heap was released more than once")
	case <-time.After(2 * startupHeapReleaseIdleDelay):
	}
}

// TestStartupHeapReleaseOnStart checks that the startup heap is released once
// after the root container starts.
func TestStartupHeapReleaseOnStart(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	released := watchStartupHeapReleases(l)

	go func() { <-l.ctrl.manager.startResultChan }()
	if err := l.Run(); err != nil {
		t.Fatalf("error running container: %v", err)
	}
	expectOneStartupHeapRelease(t, released)
	if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
		t.Errorf("application exited with %s, want exit status 0", status)
	}
}

// TestStartupHeapReleaseOnRestore checks that the startup heap is released
// once after a restore is complete.
func TestStartupHeapReleaseOnRestore(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	released := watchStartupHeapReleases(l)
	defer l.ctrl.srv.Stop(time.Hour)

	// Put the loader in the state that a restore leaves it in after the
	// restored kernel starts (see containerManager.Restore and Loader.run).
	l.mu.Lock()
	l.state = restoringStarted
	l.mu.Unlock()
	l.ctrl.manager.onRestoreDone(sentryapi.Savings{})
	// A second trigger while the release is pending doesn't add a release.
	l.releaseStartupHeapWhenIdle()
	expectOneStartupHeapRelease(t, released)
}

// Test that network=host with raw sockets enabled requires CAP_NET_RAW on the
// host.
func TestHostnetWithRawSockets(t *testing.T) {
	capabilitytest.DropEffective(t, unix.CAP_NET_RAW)

	// Configure host network with raw sockets.
	conf := testConfig()
	conf.Network = config.NetworkHost
	conf.EnableRaw = true

	// Creating loader should fail.
	l, err := New(Args{
		ID:              "should-fail",
		Spec:            testSpec(),
		Conf:            conf,
		DevGoferFD:      -1,
		PodInitConfigFD: -1,
		ExecFD:          -1,
		CPUDMALatencyFD: -1,
	})
	if err == nil {
		l.Destroy()
		t.Fatalf("expected loader.New() to fail but it did not")
	}
	// Error message must be about CAP_NET_RAW.
	if !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Errorf("expected error to contain CAP_NET_RAW but got %q", err)
	}
}

type CreateMountTestcase struct {
	name string
	// Spec that will be used to create the mount manager.  Note
	// that we can't mount procfs without a kernel, so each spec
	// MUST contain something other than procfs mounted at /proc.
	spec specs.Spec
	// Paths that are expected to exist in the resulting fs.
	expectedPaths []string
}

func createMountTestcases() []*CreateMountTestcase {
	testCases := []*CreateMountTestcase{
		{
			// Only proc.
			name: "only proc mount",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /proc, /dev, and /sys should always be mounted.
			expectedPaths: []string{"/proc", "/dev", "/sys"},
		},
		{
			// Mount at a deep path, with many components that do
			// not exist in the root.
			name: "deep mount path",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/some/very/very/deep/path",
						Type:        "tmpfs",
					},
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /some/deep/path should be mounted, along with /proc, /dev, and /sys.
			expectedPaths: []string{"/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			// Mounts are nested inside each other.
			name: "nested mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/qux",
						Type:        "tmpfs",
					},
					{
						// File mounts with the same prefix.
						Destination: "/foo/qux-quz",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar/baz",
						Type:        "tmpfs",
					},
					{
						// A deep path that is in foo but not the other mounts.
						Destination: "/foo/some/very/very/deep/path",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/foo", "/foo/bar", "/foo/bar/baz", "/foo/qux",
				"/foo/qux-quz", "/foo/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			name: "mount inside /dev",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev",
						Type:        "tmpfs",
					},
					{
						// Mount with the same prefix.
						Destination: "/dev/fd-foo",
						Type:        "tmpfs",
					},
					{
						// Unsupported fs type.
						Destination: "/dev/mqueue",
						Type:        "mqueue",
					},
					{
						Destination: "/dev/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev/bar",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/dev", "/dev/fd-foo", "/dev/foo", "/dev/bar", "/sys"},
		},
		{
			name: "mounts inside mandatory mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/sys/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/tmp/baz",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev/goo",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/sys", "/sys/bar", "/tmp", "/tmp/baz", "/dev/goo"},
		},
	}

	return testCases
}

// Test that MountNamespace can be created with various specs.
func TestCreateMountNamespace(t *testing.T) {
	for _, tc := range createMountTestcases() {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			spec.Mounts = tc.spec.Mounts
			spec.Root = tc.spec.Root

			t.Logf("Using root: %q", spec.Root.Path)
			l, loaderCleanup, err := createLoader(testConfig(), spec)
			if err != nil {
				t.Fatalf("failed to create loader: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			l.mu.Lock()
			defer l.mu.Unlock()
			mntr := l.newContainerMounter(&l.root)
			ctx := l.k.SupervisorContext()
			creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
			mns, err := mntr.mountAll(ctx, creds, l.root.spec, l.root.conf, &l.root.procArgs)
			if err != nil {
				t.Fatalf("mountAll: %v", err)
			}

			root := mns.Root(ctx)
			defer root.DecRef(ctx)
			for _, p := range tc.expectedPaths {
				target := &vfs.PathOperation{
					Root:  root,
					Start: root,
					Path:  fspath.Parse(p),
				}

				if d, err := l.k.VFS().GetDentryAt(ctx, l.root.procArgs.Credentials, target, &vfs.GetDentryOptions{}); err != nil {
					t.Errorf("expected path %v to exist with spec %v, but got error %v", p, tc.spec, err)
				} else {
					d.DecRef(ctx)
				}
			}
		})
	}
}

type createMountPointTestCase struct {
	name string
	path string
	mode linux.FileMode
	fail bool
}

func TestCreateMountPoint(t *testing.T) {
	createMountPointTestCases := []createMountPointTestCase{
		{
			name: "File",
			path: "/test/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "Directory",
			path: "/test/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "FileWithIntDirs",
			path: "/test/a/b/c/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "DirectoryWithIntDirs",
			path: "/test/d/e/f/g/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "ExistingFile",
			path: "/test/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "ExistingDirectory",
			path: "/test/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "DirVSFile",
			path: "/test/test-file",
			mode: linux.ModeDirectory,
			fail: true,
		},
		{
			name: "FileVSDir",
			path: "/test/test-dir",
			mode: linux.ModeRegular,
			fail: true,
		},
	}

	spec := testSpec()
	spec.Root = &specs.Root{
		Path: os.TempDir(),
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/test",
		Type:        "tmpfs",
	})

	t.Logf("Using root: %q", spec.Root.Path)
	l, loaderCleanup, err := createLoader(testConfig(), spec)
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	defer l.Destroy()
	defer loaderCleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	mntr := l.newContainerMounter(&l.root)
	ctx := l.k.SupervisorContext()
	creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
	mns, err := mntr.mountAll(ctx, creds, l.root.spec, l.root.conf, &l.root.procArgs)
	if err != nil {
		t.Fatalf("mountAll: %v", err)
	}

	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	for _, tc := range createMountPointTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mntr.makeMountPoint(ctx, creds, mns, tc.path, tc.mode); err != nil {
				if tc.fail {
					return
				}
				t.Fatalf("makeMountPoint failed: %v", err)
			} else {
				if tc.fail {
					t.Fatalf("makeMountPoint doesn't fail")
				}
			}
			target := &vfs.PathOperation{
				Root:  root,
				Start: root,
				Path:  fspath.Parse(tc.path),
			}

			if mode, err := mntr.getPathMode(ctx, creds, target); err != nil {
				t.Errorf("expected path %v, but got error %v", tc.path, err)
			} else {
				if mode.IsDir() != tc.mode.IsDir() {
					t.Errorf("path mode %v doesn't match the mount mode %v", mode, tc.mode)
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	cpuid.Initialize()
	os.Exit(m.Run())
}

func TestNetworkConfig(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer l.ctrl.srv.Stop(time.Hour)

	go func() {
		l.WaitForStartSignal()
		l.ctrl.manager.startResultChan <- nil
	}()

	args := &sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks: []sentryapi.LoopbackLink{
			{
				Name: "lo",
				Addresses: []sentryapi.IPWithPrefix{
					{Address: net.IP("\x7f\x00\x00\x01"), PrefixLen: 8},
				},
				Routes: []sentryapi.Route{
					{
						Destination: net.IPNet{
							IP:   net.IP{127, 0, 0, 0},
							Mask: net.IPMask{255, 0, 0, 0},
						},
					},
				},
			},
		},
	}
	if err := l.ctrl.manager.SetNetworkArgs(args, nil); err != nil {
		t.Errorf("error calling SetNetworkConfig: %v", err)
	}
	var networkArgs sentryapi.CreateLinksAndRoutesArgs
	if err := l.ctrl.manager.GetNetworkConfig(nil, &networkArgs); err != nil {
		t.Errorf("error calling NetworkConfig: %v", err)
	}
	if diff := cmp.Diff(networkArgs.LoopbackLinks, args.LoopbackLinks); diff != "" {
		t.Errorf("Network config content mismatch (-want +got):\n%s", diff)
	}
}

func TestSignalUnkillablePolicyMapping(t *testing.T) {
	for _, tc := range []struct {
		confPolicy   config.SignalUnkillablePolicy
		kernelPolicy kernel.SignalUnkillablePolicy
	}{
		{config.SignalUnkillableNone, kernel.SignalUnkillableNone},
		{config.SignalUnkillableLinux, kernel.SignalUnkillableLinux},
		{config.SignalUnkillablePolicy(-1), kernel.SignalUnkillableNone},
	} {
		if got := signalUnkillablePolicy(tc.confPolicy); got != tc.kernelPolicy {
			t.Errorf("signalUnkillablePolicy(%v) = %v, want %v", tc.confPolicy, got, tc.kernelPolicy)
		}
	}
}

func TestRunRecordsHostFS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		directFS bool
		want     filter.HostFSAccess
	}{
		{name: "no directfs", directFS: false, want: filter.HostFSNone},
		{name: "directfs", directFS: true, want: filter.HostFSReadWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			conf.DirectFS = tc.directFS
			l, loaderCleanup, err := createLoader(conf, testSpec())
			if err != nil {
				t.Fatalf("error creating loader: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			var resultChanErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				resultChanErr = <-l.ctrl.manager.startResultChan
				wg.Done()
			}()
			if err := l.Run(); err != nil {
				t.Fatalf("error running container: %v", err)
			}
			wg.Wait()
			if resultChanErr != nil {
				t.Fatalf("error on startResultChan: %v", resultChanErr)
			}
			l.mu.Lock()
			got := l.hostFS
			l.mu.Unlock()
			if got != tc.want {
				t.Errorf("l.hostFS = %v, want %v", got, tc.want)
			}
			if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
				t.Errorf("application exited with %s, want exit status 0", status)
			}
		})
	}
}

func TestPrepareSeccompFilters(t *testing.T) {
	t.Cleanup(func() {
		gofer.SetProcSelfFD(procSelfFD)
	})
	dupProcSelfFD := func(t *testing.T) int {
		t.Helper()
		dupFD, err := unix.FcntlInt(uintptr(procSelfFD), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			t.Fatalf("F_DUPFD_CLOEXEC(procSelfFD) failed: %v", err)
		}
		return dupFD
	}

	t.Run("HostFSNone closes procSelfFD and passes -1 to callback", func(t *testing.T) {
		dupFD := dupProcSelfFD(t)
		gofer.SetProcSelfFD(dupFD)
		conf := testConfig()
		conf.DisableSeccomp = false
		gotCB := -2
		l := &Loader{
			root:       containerInfo{conf: conf},
			procSelfFD: dupFD,
			PreSeccompCallback: func(fd int) {
				gotCB = fd
			},
		}
		if err := l.prepareSeccompFilters(filter.HostFSNone); err != nil {
			t.Fatalf("prepareSeccompFilters() failed: %v", err)
		}
		if l.procSelfFD != -1 {
			t.Errorf("l.procSelfFD = %d, want -1", l.procSelfFD)
		}
		if gotCB != -1 {
			t.Errorf("PreSeccompCallback received %d, want -1", gotCB)
		}
		if _, err := unix.FcntlInt(uintptr(dupFD), unix.F_GETFD, 0); !os.IsNotExist(err) && err != unix.EBADF {
			t.Errorf("dupFD still open after prepareSeccompFilters: fcntl err = %v, want EBADF", err)
		}
	})

	t.Run("close error skips callback", func(t *testing.T) {
		conf := testConfig()
		conf.DisableSeccomp = false
		called := false
		l := &Loader{
			root:       containerInfo{conf: conf},
			procSelfFD: math.MaxInt32,
			PreSeccompCallback: func(int) {
				called = true
			},
		}
		if err := l.installSeccompFilters(filter.HostFSNone); err == nil || !strings.Contains(err.Error(), "closing procSelfFD") {
			t.Errorf("installSeccompFilters() = %v, want closing procSelfFD error", err)
		}
		if called {
			t.Errorf("PreSeccompCallback was called after close error")
		}
	})

	t.Run("DisableSeccomp leaves procSelfFD open", func(t *testing.T) {
		dupFD := dupProcSelfFD(t)
		defer unix.Close(dupFD)
		conf := testConfig()
		conf.DisableSeccomp = true
		gotCB := -2
		l := &Loader{
			root:       containerInfo{conf: conf},
			procSelfFD: dupFD,
			PreSeccompCallback: func(fd int) {
				gotCB = fd
			},
		}
		if err := l.installSeccompFilters(filter.HostFSNone); err != nil {
			t.Fatalf("installSeccompFilters() failed: %v", err)
		}
		if l.procSelfFD != dupFD || gotCB != dupFD {
			t.Errorf("l.procSelfFD=%d, callback=%d, want %d", l.procSelfFD, gotCB, dupFD)
		}
		if _, err := unix.FcntlInt(uintptr(dupFD), unix.F_GETFD, 0); err != nil {
			t.Errorf("dupFD closed unexpectedly: %v", err)
		}
	})

	t.Run("HostFS above none keeps procSelfFD open", func(t *testing.T) {
		for _, level := range []filter.HostFSAccess{filter.HostFSReadOnly, filter.HostFSReadWrite} {
			dupFD := dupProcSelfFD(t)
			defer unix.Close(dupFD)
			conf := testConfig()
			conf.DisableSeccomp = false
			gotCB := -2
			l := &Loader{
				root:       containerInfo{conf: conf},
				procSelfFD: dupFD,
				PreSeccompCallback: func(fd int) {
					gotCB = fd
				},
			}
			if err := l.prepareSeccompFilters(level); err != nil {
				t.Fatalf("prepareSeccompFilters(%v) failed: %v", level, err)
			}
			if l.procSelfFD != dupFD || gotCB != dupFD {
				t.Errorf("level %v: l.procSelfFD=%d, callback=%d, want %d", level, l.procSelfFD, gotCB, dupFD)
			}
		}
	})

	t.Run("HostFSNone with procSelfFD -1 succeeds", func(t *testing.T) {
		conf := testConfig()
		conf.DisableSeccomp = false
		gotCB := -2
		l := &Loader{
			root:       containerInfo{conf: conf},
			procSelfFD: -1,
			PreSeccompCallback: func(fd int) {
				gotCB = fd
			},
		}
		if err := l.prepareSeccompFilters(filter.HostFSNone); err != nil {
			t.Fatalf("prepareSeccompFilters() failed: %v", err)
		}
		if gotCB != -1 {
			t.Errorf("PreSeccompCallback received %d, want -1", gotCB)
		}
	})

	t.Run("HostFS above none requires procSelfFD", func(t *testing.T) {
		conf := testConfig()
		conf.DisableSeccomp = false
		called := false
		l := &Loader{
			root:       containerInfo{conf: conf},
			procSelfFD: -1,
			PreSeccompCallback: func(int) {
				called = true
			},
		}
		if err := l.prepareSeccompFilters(filter.HostFSReadOnly); err == nil || !strings.Contains(err.Error(), "requires procSelfFD") {
			t.Errorf("prepareSeccompFilters() = %v, want requires procSelfFD error", err)
		}
		if called {
			t.Errorf("PreSeccompCallback was called despite missing procSelfFD")
		}
	})

	t.Run("procSelfFD zero rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			disableSeccomp bool
			hostFS         filter.HostFSAccess
		}{
			{"HostFSNone", false, filter.HostFSNone},
			{"HostFSReadOnly", false, filter.HostFSReadOnly},
			{"DisableSeccomp", true, filter.HostFSNone},
		} {
			t.Run(tc.name, func(t *testing.T) {
				conf := testConfig()
				conf.DisableSeccomp = tc.disableSeccomp
				called := false
				l := &Loader{
					root:       containerInfo{conf: conf},
					procSelfFD: 0,
					PreSeccompCallback: func(int) {
						called = true
					},
				}
				if err := l.prepareSeccompFilters(tc.hostFS); err == nil || !strings.Contains(err.Error(), "invalid procSelfFD: 0") {
					t.Errorf("prepareSeccompFilters(%v) = %v, want invalid procSelfFD: 0 error", tc.hostFS, err)
				}
				if called {
					t.Errorf("PreSeccompCallback was called despite procSelfFD == 0")
				}
			})
		}
	})

	t.Run("invalid HostFS level rejected", func(t *testing.T) {
		conf := testConfig()
		conf.DisableSeccomp = false
		for _, invalid := range []filter.HostFSAccess{-1, filter.HostFSReadWrite + 1} {
			l := &Loader{
				root:       containerInfo{conf: conf},
				procSelfFD: procSelfFD,
			}
			if err := l.prepareSeccompFilters(invalid); err == nil || !strings.Contains(err.Error(), "invalid host filesystem access level") {
				t.Errorf("prepareSeccompFilters(%v) = %v, want invalid level error", invalid, err)
			}
		}
	})
}

func TestMountHostFSAccess(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", file, err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", file, symlink, err)
	}
	for _, tc := range []struct {
		name               string
		sourceKind         string
		rootNoOverlay      bool
		rootReadOnly       bool
		rootDirectFSAnnot  string
		overlay            bool
		directFS           bool
		mountDirectFSAnnot string
		disableSeccomp     bool
		subDisableSeccomp  bool
		devGofer           bool
		mismatchedErofs    bool
		hostFS             filter.HostFSAccess
		wantErr            string
	}{
		{
			name:       "directory with HostFSReadWrite",
			sourceKind: "dir",
			directFS:   true,
			hostFS:     filter.HostFSReadWrite,
		},
		{
			name:       "file with HostFSReadWrite",
			sourceKind: "file",
			directFS:   true,
			hostFS:     filter.HostFSReadWrite,
		},
		{
			name:       "directory with HostFSReadOnly",
			sourceKind: "dir",
			directFS:   true,
			hostFS:     filter.HostFSReadOnly,
			wantErr:    "needs readwrite access",
		},
		{
			name:       "directory with HostFSNone",
			sourceKind: "dir",
			directFS:   true,
			hostFS:     filter.HostFSNone,
			wantErr:    "root mount needs",
		},
		{
			name:          "root without overlay with HostFSReadWrite",
			sourceKind:    "file",
			rootNoOverlay: true,
			directFS:      true,
			hostFS:        filter.HostFSReadWrite,
		},
		{
			name:          "root without overlay with HostFSReadOnly",
			sourceKind:    "file",
			rootNoOverlay: true,
			directFS:      true,
			hostFS:        filter.HostFSReadOnly,
			wantErr:       "root mount needs readwrite access",
		},
		{
			name:          "root without overlay with HostFSNone",
			sourceKind:    "file",
			rootNoOverlay: true,
			directFS:      true,
			hostFS:        filter.HostFSNone,
			wantErr:       "root mount needs readwrite access",
		},
		{
			name:              "root without overlay with directfs suppressed",
			sourceKind:        "dir",
			rootNoOverlay:     true,
			rootDirectFSAnnot: "off",
			overlay:           true,
			directFS:          true,
			hostFS:            filter.HostFSReadOnly,
		},
		{
			name:              "root without overlay with directfs default hint",
			sourceKind:        "dir",
			rootNoOverlay:     true,
			rootDirectFSAnnot: "default",
			overlay:           true,
			directFS:          true,
			hostFS:            filter.HostFSReadOnly,
			wantErr:           "root mount needs readwrite access",
		},
		{
			name:          "root without overlay without directfs",
			sourceKind:    "dir",
			rootNoOverlay: true,
			directFS:      false,
			hostFS:        filter.HostFSNone,
		},
		{
			name:           "root without overlay with seccomp disabled",
			sourceKind:     "dir",
			rootNoOverlay:  true,
			directFS:       true,
			disableSeccomp: true,
			hostFS:         filter.HostFSNone,
		},
		{
			name:              "overlaid submount rejected under HostFSNone",
			sourceKind:        "dir",
			rootDirectFSAnnot: "off",
			overlay:           true,
			directFS:          true,
			hostFS:            filter.HostFSNone,
			wantErr:           "needs readonly access",
		},
		{
			name:       "file below HostFSReadWrite",
			sourceKind: "file",
			directFS:   true,
			hostFS:     filter.HostFSReadOnly,
			wantErr:    "needs readwrite access",
		},
		{
			name:       "symlink below HostFSReadWrite",
			sourceKind: "symlink",
			directFS:   true,
			hostFS:     filter.HostFSReadOnly,
			wantErr:    "needs readwrite access",
		},
		{
			name:       "symlink with HostFSReadWrite",
			sourceKind: "symlink",
			directFS:   true,
			hostFS:     filter.HostFSReadWrite,
		},
		{
			name:       "directory with an overlay",
			sourceKind: "dir",
			overlay:    true,
			directFS:   true,
			hostFS:     filter.HostFSReadOnly,
		},
		{
			name:       "directory without directfs",
			sourceKind: "dir",
			directFS:   false,
			hostFS:     filter.HostFSNone,
		},
		{
			name:               "directory with directfs suppressed",
			sourceKind:         "dir",
			directFS:           true,
			mountDirectFSAnnot: "off",
			hostFS:             filter.HostFSReadOnly,
		},
		{
			name:               "directory with mount hint directfs default still rejected",
			sourceKind:         "dir",
			directFS:           true,
			mountDirectFSAnnot: "default",
			hostFS:             filter.HostFSReadOnly,
			wantErr:            "needs readwrite access",
		},
		{
			name:           "directory with seccomp disabled",
			sourceKind:     "dir",
			directFS:       true,
			disableSeccomp: true,
			hostFS:         filter.HostFSReadOnly,
		},
		{
			name:              "subcontainer DisableSeccomp ignored when root seccomp enabled",
			sourceKind:        "dir",
			directFS:          true,
			subDisableSeccomp: true,
			hostFS:            filter.HostFSReadOnly,
			wantErr:           "needs readwrite access",
		},
		{
			name:         "readonly root failing submount unwinds cleanly",
			sourceKind:   "dir",
			rootReadOnly: true,
			directFS:     true,
			hostFS:       filter.HostFSReadOnly,
			wantErr:      "needs readwrite access",
		},
		{
			name:       "dev gofer rejected under HostFSReadOnly",
			sourceKind: "dir",
			overlay:    true,
			directFS:   true,
			devGofer:   true,
			hostFS:     filter.HostFSReadOnly,
			wantErr:    "device gofer needs readwrite access",
		},
		{
			name:            "bind mount with Erofs Lower rejected",
			sourceKind:      "dir",
			directFS:        true,
			mismatchedErofs: true,
			hostFS:          filter.HostFSReadOnly,
			wantErr:         "does not match gofer mount config",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			mountPoint := filepath.Join(root, "mnt")
			var source string
			switch tc.sourceKind {
			case "dir":
				source = dir
				if err := os.Mkdir(mountPoint, 0755); err != nil {
					t.Fatalf("os.Mkdir(%q) failed: %v", mountPoint, err)
				}
			case "file":
				source = file
				if err := os.WriteFile(mountPoint, nil, 0644); err != nil {
					t.Fatalf("os.WriteFile(%q) failed: %v", mountPoint, err)
				}
			case "symlink":
				source = symlink
				if err := os.WriteFile(mountPoint, nil, 0644); err != nil {
					t.Fatalf("os.WriteFile(%q) failed: %v", mountPoint, err)
				}
			default:
				t.Fatalf("unknown sourceKind %q", tc.sourceKind)
			}
			spec := testSpec()
			spec.Root = &specs.Root{Path: root, Readonly: tc.rootReadOnly}
			if tc.rootReadOnly {
				for _, d := range []string{"dev", "proc", "sys"} {
					if err := os.Mkdir(filepath.Join(root, d), 0755); err != nil {
						t.Fatalf("os.Mkdir(%q) failed: %v", d, err)
					}
				}
			}
			spec.Mounts = []specs.Mount{
				{Destination: "/proc", Type: "tmpfs"},
				{Destination: "/mnt", Type: "bind", Source: source},
			}
			annotations := map[string]string{}
			if tc.rootDirectFSAnnot != "" {
				annotations[sentryapi.RootfsPrefix+"source"] = root
				annotations[sentryapi.RootfsPrefix+"type"] = "bind"
				annotations[sentryapi.RootfsPrefix+"directfs"] = tc.rootDirectFSAnnot
			}
			if tc.mountDirectFSAnnot != "" {
				annotations[sentryapi.MountPrefix+"m1.source"] = source
				annotations[sentryapi.MountPrefix+"m1.type"] = "bind"
				annotations[sentryapi.MountPrefix+"m1.share"] = "container"
				annotations[sentryapi.MountPrefix+"m1.directfs"] = tc.mountDirectFSAnnot
			}
			if len(annotations) > 0 {
				spec.Annotations = annotations
			}
			conf := testConfig()
			conf.DirectFS = tc.directFS
			conf.DisableSeccomp = tc.disableSeccomp
			l, loaderCleanup, err := createLoader(conf, spec)
			if err != nil {
				t.Fatalf("failed to create loader: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			l.mu.Lock()
			defer l.mu.Unlock()
			l.hostFS = tc.hostFS
			if !tc.rootNoOverlay {
				l.root.goferMountConfs[0].Upper = specutils.MemoryOverlay
			}
			if tc.overlay {
				l.root.goferMountConfs[1].Upper = specutils.MemoryOverlay
			}
			if tc.mismatchedErofs {
				l.root.goferMountConfs[1].Lower = specutils.Erofs
			}
			if tc.devGofer {
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatalf("os.Pipe() failed: %v", err)
				}
				defer w.Close()
				devFD, err := fd.NewFromFile(r)
				r.Close()
				if err != nil {
					t.Fatalf("fd.NewFromFile() failed: %v", err)
				}
				defer devFD.Close()
				l.root.devGoferFD = devFD
			}
			mntr := l.newContainerMounter(&l.root)
			mountConf := *l.root.conf
			if tc.subDisableSeccomp {
				mountConf.DisableSeccomp = true
			}
			ctx := l.root.procArgs.NewContext(l.k)
			creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
			mns, err := mntr.mountAll(ctx, creds, l.root.spec, &mountConf, &l.root.procArgs)
			if mns != nil {
				defer mns.DecRef(ctx)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("mountAll() = %v, want an error with %q", err, tc.wantErr)
				}
				if l.root.procArgs.MountNamespace != nil {
					t.Errorf("root.procArgs.MountNamespace not cleared on mountAll error")
				}
			} else if err != nil {
				t.Errorf("mountAll() failed: %v", err)
			}
		})
	}
}

func TestMountSharedMasterHostFSAccess(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name             string
		hostFS           filter.HostFSAccess
		suppressDirectFS bool
		wantErr          string
	}{
		{
			name:    "HostFSNone rejected before mount",
			hostFS:  filter.HostFSNone,
			wantErr: "needs readwrite access",
		},
		{
			name:    "HostFSReadOnly rejects directory",
			hostFS:  filter.HostFSReadOnly,
			wantErr: "needs readwrite access",
		},
		{
			name:   "HostFSReadWrite allowed",
			hostFS: filter.HostFSReadWrite,
		},
		{
			name:             "suppressed directfs allowed under HostFSNone",
			hostFS:           filter.HostFSNone,
			suppressDirectFS: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			conf.DirectFS = true
			conf.DisableSeccomp = false
			l, loaderCleanup, err := createLoader(conf, testSpec())
			if err != nil {
				t.Fatalf("createLoader() failed: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			sandEnd, stopGofer, err := startGofer(dir, conf)
			if err != nil {
				t.Fatalf("startGofer() failed: %v", err)
			}
			defer stopGofer()
			goferFD := fd.New(sandEnd)
			defer goferFD.Close()

			l.mu.Lock()
			defer l.mu.Unlock()
			l.hostFS = tc.hostFS
			mntr := l.newContainerMounter(&l.root)
			mnt := specs.Mount{
				Type:        "bind",
				Source:      dir,
				Destination: "/shared",
			}
			mntInfo := &mountInfo{
				mount:          &mnt,
				goferFD:        goferFD,
				goferMountConf: specutils.GoferMountConf{Lower: specutils.Lisafs, Upper: specutils.NoOverlay},
				hint: &sentryapi.MountHint{
					Name:             "shared",
					Mount:            mnt,
					SuppressDirectFS: tc.suppressDirectFS,
				},
			}
			ctx := l.k.SupervisorContext()
			creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
			sharedMnt, err := mntr.mountSharedMaster(ctx, l.root.spec, l.root.conf, mntInfo, creds)
			if sharedMnt != nil {
				defer sharedMnt.DecRef(ctx)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("mountSharedMaster() = %v, want error containing %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Errorf("mountSharedMaster() failed: %v", err)
			}
		})
	}
}

func TestRootHostFSAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		directFS bool
		want     filter.HostFSAccess
	}{
		{name: "no directfs", directFS: false, want: filter.HostFSNone},
		{name: "directfs", directFS: true, want: filter.HostFSReadWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			conf.DirectFS = tc.directFS
			l := &Loader{root: containerInfo{conf: conf, spec: testSpec()}}
			if got := l.rootHostFSAccess(); got != tc.want {
				t.Errorf("rootHostFSAccess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRestoreHostFSAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		directFS bool
		want     filter.HostFSAccess
	}{
		{name: "no directfs", directFS: false, want: filter.HostFSNone},
		{name: "directfs", directFS: true, want: filter.HostFSReadWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			conf.DirectFS = tc.directFS
			l := &Loader{root: containerInfo{
				conf:            conf,
				spec:            testSpec(),
				goferMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs, Upper: specutils.SelfOverlay}},
			}}
			if got := l.restoreHostFSAccess(); got != tc.want {
				t.Errorf("restoreHostFSAccess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckDirectFSMount(t *testing.T) {
	for _, tc := range []struct {
		name           string
		disableSeccomp bool
		hostFS         filter.HostFSAccess
		wantErr        bool
	}{
		{name: "HostFSNone", hostFS: filter.HostFSNone, wantErr: true},
		{name: "HostFSReadOnly", hostFS: filter.HostFSReadOnly, wantErr: true},
		{name: "HostFSReadWrite", hostFS: filter.HostFSReadWrite},
		{name: "seccomp disabled", disableSeccomp: true, hostFS: filter.HostFSNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testConfig()
			conf.DisableSeccomp = tc.disableSeccomp
			l := &Loader{
				root:   containerInfo{conf: conf},
				hostFS: tc.hostFS,
			}
			err := l.checkDirectFSMount()
			if tc.wantErr && err == nil {
				t.Errorf("checkDirectFSMount() = nil, want an error")
			} else if !tc.wantErr && err != nil {
				t.Errorf("checkDirectFSMount() = %v, want nil", err)
			}
		})
	}
}

func TestControllerDirectFSMountCheck(t *testing.T) {
	conf := testConfig()
	conf.DisableSeccomp = false
	l, loaderCleanup, err := createLoader(conf, testSpec())
	if err != nil {
		t.Fatalf("createLoader() failed: %v", err)
	}
	defer l.Destroy()
	defer loaderCleanup()

	sock := fmt.Sprintf("\x00ctrl-directfs-test.%010d", rand.Int())
	ctrlFD, err := server.CreateSocket(sock)
	if err != nil {
		t.Fatalf("CreateSocket() failed: %v", err)
	}
	ctrl, err := newController(ctrlFD, l)
	if err != nil {
		unix.Close(ctrlFD)
		t.Fatalf("newController() failed: %v", err)
	}
	ctrl.srv.StartServing()
	defer ctrl.stop()

	callMount := func(t *testing.T) error {
		t.Helper()
		conn, err := unet.Connect(sock, false)
		if err != nil {
			t.Fatalf("unet.Connect() failed: %v", err)
		}
		client := urpc.NewClient(conn)
		defer client.Close()
		return client.Call("Fs.Mount", &control.MountOpts{
			Target: "/mnt",
			FSType: "gofer",
			Data:   "directfs",
		}, nil)
	}

	l.mu.Lock()
	l.hostFS = filter.HostFSReadOnly
	l.mu.Unlock()
	if err := callMount(t); err == nil || !strings.Contains(err.Error(), "cannot mount a directfs filesystem") {
		t.Errorf("Fs.Mount before refreshHandlers = %v, want directfs denial", err)
	}

	// Verify handler wiring survives controller.refreshHandlers (used on restore).
	ctrl.refreshHandlers()
	if err := callMount(t); err == nil || !strings.Contains(err.Error(), "cannot mount a directfs filesystem") {
		t.Errorf("Fs.Mount after refreshHandlers = %v, want directfs denial", err)
	}
}

func TestCheckSubcontainerHostFSAccess(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rootDirectFS    bool
		rootDisableSec  bool
		noRootContainer bool
		containerType   string
		subDirectFS     bool
		subMountConfs   []specutils.GoferMountConf
		subRootAnnot    string
		subMountAnnot   string
		subMountShare   string
		subMountType    string
		subPrecedesProc bool
		subHasDevGofer  bool
		subDisableSec   bool
		rootHostFS      filter.HostFSAccess
		wantErr         string
		wantNoErrSubstr string
	}{
		{
			name:           "root disable seccomp allows more access",
			rootDirectFS:   true,
			rootDisableSec: true,
			subDirectFS:    true,
			subMountConfs:  []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:     filter.HostFSReadOnly,
		},
		{
			name:          "subcontainer disable seccomp still rejected",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			subDisableSec: true,
			rootHostFS:    filter.HostFSReadOnly,
			wantErr:       "--no-root-container",
		},
		{
			name:          "root directfs disabled rejects directfs subcontainer",
			rootDirectFS:  false,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:    filter.HostFSNone,
			wantErr:       "directfs is disabled for the sandbox",
		},
		{
			name:          "goferless EROFS subcontainer allowed when root directfs disabled",
			rootDirectFS:  false,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.NoneLower}},
			rootHostFS:    filter.HostFSNone,
		},
		{
			name:          "suppressed directfs rootfs allowed when root directfs disabled",
			rootDirectFS:  false,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			subRootAnnot:  "off",
			rootHostFS:    filter.HostFSNone,
		},
		{
			name:          "suppressed directfs subcontainer allowed when root directfs disabled",
			rootDirectFS:  false,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.NoneLower}, {Lower: specutils.Lisafs}},
			subMountAnnot: "off",
			rootHostFS:    filter.HostFSNone,
		},
		{
			name:            "suppressed directfs bind after /proc allowed when root directfs disabled",
			rootDirectFS:    false,
			subDirectFS:     true,
			subMountConfs:   []specutils.GoferMountConf{{Lower: specutils.NoneLower}, {Lower: specutils.Lisafs}},
			subMountAnnot:   "off",
			subPrecedesProc: true,
			rootHostFS:      filter.HostFSNone,
		},
		{
			name:          "subcontainer without directfs allowed when root directfs disabled",
			rootDirectFS:  false,
			subDirectFS:   false,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:    filter.HostFSNone,
		},
		{
			name:          "subcontainer without directfs allowed under HostFSReadOnly",
			rootDirectFS:  true,
			subDirectFS:   false,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:    filter.HostFSReadOnly,
		},
		{
			name:            "no-root-container uses generic error without hint",
			rootDirectFS:    true,
			noRootContainer: true,
			subDirectFS:     true,
			subMountConfs:   []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:      filter.HostFSReadOnly,
			wantErr:         "only allow readonly",
			wantNoErrSubstr: "--no-root-container",
		},
		{
			name:            "pod sandbox annotation uses generic error without hint",
			rootDirectFS:    true,
			containerType:   specutils.ContainerdContainerTypeSandbox,
			subDirectFS:     true,
			subMountConfs:   []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:      filter.HostFSReadOnly,
			wantErr:         "only allow readonly",
			wantNoErrSubstr: "--no-root-container",
		},
		{
			name:          "root directfs enabled with HostFSNone rejected",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:    filter.HostFSNone,
			wantErr:       "only allow none",
		},
		{
			name:          "matching level allowed",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs}},
			rootHostFS:    filter.HostFSReadWrite,
		},
		{
			name:           "goferless EROFS with devGofer rejected under HostFSNone",
			rootDirectFS:   false,
			subDirectFS:    true,
			subMountConfs:  []specutils.GoferMountConf{{Lower: specutils.NoneLower}},
			subHasDevGofer: true,
			rootHostFS:     filter.HostFSNone,
			wantErr:        "directfs is disabled for the sandbox",
		},
		{
			name:           "goferless EROFS with devGofer rejected under HostFSReadOnly",
			rootDirectFS:   true,
			subDirectFS:    true,
			subMountConfs:  []specutils.GoferMountConf{{Lower: specutils.NoneLower}},
			subHasDevGofer: true,
			rootHostFS:     filter.HostFSReadOnly,
			wantErr:        "needs readwrite access",
		},
		{
			name:           "goferless EROFS with devGofer allowed under HostFSReadWrite",
			rootDirectFS:   true,
			subDirectFS:    true,
			subMountConfs:  []specutils.GoferMountConf{{Lower: specutils.NoneLower}},
			subHasDevGofer: true,
			rootHostFS:     filter.HostFSReadWrite,
		},
		{
			name:          "overlaid directfs subcontainer allowed under HostFSReadOnly",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}},
			rootHostFS:    filter.HostFSReadOnly,
		},
		{
			name:          "overlaid directfs subcontainer rejected under HostFSNone",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}},
			rootHostFS:    filter.HostFSNone,
			wantErr:       "needs readonly access",
		},
		{
			name:          "shared overlaid bind subcontainer rejected under HostFSReadOnly",
			rootDirectFS:  true,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}, {Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}},
			subMountShare: "pod",
			rootHostFS:    filter.HostFSReadOnly,
			wantErr:       "needs readwrite access",
		},
		{
			name:         "empty mountConfs rejected",
			rootDirectFS: true,
			subDirectFS:  true,
			rootHostFS:   filter.HostFSReadWrite,
			wantErr:      "missing root gofer mount config",
		},
		{
			name:          "erofs submount overridden to tmpfs allowed under HostFSNone",
			rootDirectFS:  false,
			subDirectFS:   true,
			subMountConfs: []specutils.GoferMountConf{{Lower: specutils.NoneLower}, {Lower: specutils.NoneLower, Upper: specutils.MemoryOverlay}},
			subMountType:  "erofs",
			rootHostFS:    filter.HostFSNone,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootConf := testConfig()
			rootConf.DirectFS = tc.rootDirectFS
			rootConf.DisableSeccomp = tc.rootDisableSec
			rootSpec := testSpec()
			if tc.containerType != "" {
				rootSpec.Annotations = map[string]string{
					specutils.ContainerdContainerTypeAnnotation: tc.containerType,
				}
			}
			subConf := testConfig()
			subConf.DirectFS = tc.subDirectFS
			subConf.DisableSeccomp = tc.subDisableSec
			subSpec := testSpec()
			var mountHints *sentryapi.PodMountHints
			if tc.subRootAnnot != "" {
				if subSpec.Annotations == nil {
					subSpec.Annotations = map[string]string{}
				}
				subSpec.Annotations[sentryapi.RootfsPrefix+"source"] = "/root"
				subSpec.Annotations[sentryapi.RootfsPrefix+"type"] = "bind"
				subSpec.Annotations[sentryapi.RootfsPrefix+"directfs"] = tc.subRootAnnot
			}
			if tc.subMountAnnot != "" || tc.subMountShare != "" || tc.subMountType != "" {
				if tc.subPrecedesProc {
					subSpec.Mounts = append(subSpec.Mounts, specs.Mount{
						Source:      "proc",
						Destination: "/proc",
						Type:        "proc",
					})
				}
				mntType := tc.subMountType
				if mntType == "" {
					mntType = "bind"
				}
				subSpec.Mounts = append(subSpec.Mounts, specs.Mount{
					Source:      "/src",
					Destination: "/mnt",
					Type:        mntType,
				})
				if subSpec.Annotations == nil {
					subSpec.Annotations = map[string]string{}
				}
				share := tc.subMountShare
				if share == "" {
					share = "pod"
				}
				subSpec.Annotations[sentryapi.MountPrefix+"vol.share"] = share
				subSpec.Annotations[sentryapi.MountPrefix+"vol.type"] = "tmpfs"
				subSpec.Annotations[sentryapi.MountPrefix+"vol.source"] = "/src"
				if tc.subMountAnnot != "" {
					subSpec.Annotations[sentryapi.MountPrefix+"vol.directfs"] = tc.subMountAnnot
				}
				var err error
				mountHints, err = sentryapi.NewPodMountHints(subSpec)
				if err != nil {
					t.Fatalf("NewPodMountHints() failed: %v", err)
				}
			}
			l := &Loader{
				root:       containerInfo{conf: rootConf, spec: rootSpec},
				hostFS:     tc.rootHostFS,
				mountHints: mountHints,
			}
			l.noRootContainer.enabled = tc.noRootContainer
			l.mu.Lock()
			err := l.checkSubcontainerHostFSAccess(subConf, subSpec, tc.subMountConfs, tc.subHasDevGofer, "sub")
			l.mu.Unlock()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("checkSubcontainerHostFSAccess() = %v, want error containing %q", err, tc.wantErr)
				}
				if tc.wantNoErrSubstr != "" && err != nil && strings.Contains(err.Error(), tc.wantNoErrSubstr) {
					t.Errorf("checkSubcontainerHostFSAccess() = %v, must not contain %q", err, tc.wantNoErrSubstr)
				}
			} else if err != nil {
				t.Errorf("checkSubcontainerHostFSAccess() = %v, want nil", err)
			}
		})
	}
}

func TestStartSubcontainerHostFSAccessRejected(t *testing.T) {
	rootConf := testConfig()
	rootConf.DirectFS = false
	rootConf.DisableSeccomp = false
	l := &Loader{
		root:          containerInfo{conf: rootConf, spec: testSpec()},
		hostFS:        filter.HostFSNone,
		processes:     map[execID]*execProcess{{cid: "sub"}: {}},
		failedToStart: map[string]struct{}{},
	}
	subConf := testConfig()
	subConf.DirectFS = true
	err := l.startSubcontainer(testSpec(), subConf, "sub", nil, nil, nil, nil, []specutils.GoferMountConf{{Lower: specutils.Lisafs}}, nil)
	if err == nil || !strings.Contains(err.Error(), "directfs is disabled for the sandbox") {
		t.Fatalf("startSubcontainer() = %v, want directfs disabled error", err)
	}
	l.mu.Lock()
	_, failed := l.failedToStart["sub"]
	l.mu.Unlock()
	if !failed {
		t.Errorf("failedToStart does not record rejected subcontainer")
	}
}

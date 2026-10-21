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

package container

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/sandbox"
)

// TestAsyncBoot checks that containers in a sandbox created with
// Args.AsyncBoot can be started and exec'd into right away, even if the
// bundle's config.json is rewritten in between.
func TestAsyncBoot(t *testing.T) {
	for name, conf := range configs(t, false /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			rootDir := setupTestRootDir(t, conf)
			specs, ids := createSpecs(sleepCmd, sleepCmd)
			var conts []*Container
			for i, spec := range specs {
				bundleDir, cleanup, err := testutil.SetupBundleDir(spec)
				if err != nil {
					t.Fatalf("error setting up bundle: %v", err)
				}
				defer cleanup()
				cont, err := New(conf, Args{ID: ids[i], Spec: spec, BundleDir: bundleDir, AsyncBoot: true})
				if err != nil {
					t.Fatalf("error creating container %d: %v", i, err)
				}
				defer cont.Destroy()
				conts = append(conts, cont)

				if i == 0 {
					// The sandbox and the root container's gofer may not have
					// read the spec yet: "Any updates to config.json after
					// [create] MUST NOT affect the container" -OCI spec.
					if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), nil, 0644); err != nil {
						t.Fatalf("error truncating config.json: %v", err)
					}
					// The sandbox may still be booting. Its state must still
					// be reported as created.
					loaded, err := Load(rootDir, FullID{ContainerID: ids[i]}, LoadOpts{})
					if err != nil {
						t.Fatalf("error loading container: %v", err)
					}
					if got, want := loaded.Status, Created; got != want {
						t.Errorf("container status got %v, want %v", got, want)
					}
				}
				if err := cont.Start(conf); err != nil {
					t.Fatalf("error starting container %d: %v", i, err)
				}
			}
			for _, cont := range conts {
				if got, want := cont.Status, Running; got != want {
					t.Errorf("container %q status got %v, want %v", cont.ID, got, want)
				}
				if out, err := executeCombinedOutput(conf, cont, nil, "/bin/true"); err != nil {
					t.Errorf("exec in container %q failed: %v, output: %s", cont.ID, err, out)
				}
			}
		})
	}
}

// TestAsyncBootRestore checks that a sandbox created with Args.AsyncBoot can
// be restored right away.
func TestAsyncBootRestore(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			spec, _ := sleepSpecConf(t)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()
			args := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}
			dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
			if err != nil {
				t.Fatalf("os.MkdirTemp failed: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{}); err != nil {
				t.Fatalf("error checkpointing: %v", err)
			}
			cont.Destroy()

			args.AsyncBoot = true
			cont2, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont2.Destroy()
			if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
				t.Fatalf("error restoring container: %v", err)
			}
			if out, err := executeCombinedOutput(conf, cont2, nil, "/bin/true"); err != nil {
				t.Errorf("exec in restored container failed: %v, output: %s", err, out)
			}
		})
	}
}

// TestAsyncBootSandboxDied checks that if a sandbox created with
// Args.AsyncBoot dies before it is started, as when it fails to boot, start
// reports it, the container is reported as stopped, and it can be destroyed.
func TestAsyncBootSandboxDied(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()
	id := testutil.RandomContainerID()
	cont, err := New(conf, Args{ID: id, Spec: spec, BundleDir: bundleDir, AsyncBoot: true})
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()

	if err := unix.Kill(cont.SandboxPid(), unix.SIGKILL); err != nil {
		t.Fatalf("error killing sandbox: %v", err)
	}
	// Start the container as loaded by another runsc command, as well as
	// from the container that New returned, which doesn't know that the
	// sandbox died.
	loaded, err := Load(rootDir, FullID{ContainerID: id}, LoadOpts{})
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	if got, want := loaded.Status, Stopped; got != want {
		t.Errorf("container status got %v, want %v", got, want)
	}
	for _, c := range []*Container{loaded, cont} {
		if err := c.Start(conf); !errors.Is(err, errExitedBeforeStart) {
			t.Errorf("starting container with a dead sandbox returned error %v, want %v", err, errExitedBeforeStart)
		}
	}
	if err := cont.Destroy(); err != nil {
		t.Errorf("error destroying container: %v", err)
	}
}

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
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	metricpb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/cbor"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// testContainer returns a container with most fields of the state file set.
func testContainer(t *testing.T, rootDir string) *Container {
	t.Helper()
	id := FullID{SandboxID: "sandbox", ContainerID: "container"}
	sb := &sandbox.Sandbox{
		ID:                  id.SandboxID,
		PodName:             "pod",
		Namespace:           "namespace",
		UID:                 1000,
		GID:                 1001,
		OriginalOOMScoreAdj: -998,
		RegisteredMetrics: &metricpb.MetricRegistration{
			Metrics: []*metricpb.MetricMetadata{{
				Name:        "/fs/opens",
				Description: "Number of file opens.",
				Cumulative:  true,
				Type:        metricpb.MetricMetadata_TYPE_UINT64,
				Units:       metricpb.MetricMetadata_UNITS_NONE,
			}},
			Stages: []string{"stage1", "stage2"},
		},
		MetricMetadata:      map[string]string{"key": "value"},
		MetricServerAddress: "/run/metrics.sock",
		ControlSocketPath:   "/run/control.sock",
		MountHints: &sentryapi.PodMountHints{
			Mounts: map[string]*sentryapi.MountHint{
				"volume": {
					Name:  "volume",
					Share: sentryapi.ShareType(2), // pod
					Mount: specs.Mount{Type: "tmpfs", Source: "volume", Options: []string{"rw"}},
				},
			},
		},
		StartTime:     time.Date(2026, 10, 21, 1, 2, 3, 456789123, time.FixedZone("test", -7*3600)),
		Checkpointed:  true,
		CPUTimeSaved:  1234 * time.Millisecond,
		WallTimeSaved: 5678 * time.Microsecond,
	}
	sb.Pid.Store(123)
	c := &Container{
		ID: id.ContainerID,
		Spec: &specs.Spec{
			Version: "1.2.1",
			Process: &specs.Process{
				Terminal: true,
				User:     specs.User{UID: 1, GID: 2, AdditionalGids: []uint32{3, 4}},
				Args:     []string{"/bin/sh", "-c", "true"},
				Env:      []string{"PATH=/bin"},
				Cwd:      "/",
				Rlimits:  []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1 << 20, Soft: 1 << 20}},
			},
			Root:     &specs.Root{Path: "/rootfs", Readonly: true},
			Hostname: "host",
			Mounts: []specs.Mount{
				{Destination: "/proc", Type: "proc", Source: "proc"},
				{Destination: "/tmp", Type: "bind", Source: "/tmp", Options: []string{"rbind", "ro"}},
			},
			Hooks: &specs.Hooks{
				Poststop: []specs.Hook{{Path: "/bin/hook", Args: []string{"hook", "arg"}}},
			},
			Annotations: map[string]string{"dev.gvisor.spec.mount.volume.share": "pod"},
			Linux: &specs.Linux{
				UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 1000, Size: 65536}},
				Resources: &specs.LinuxResources{
					Memory: &specs.LinuxMemory{Limit: new(int64(512 << 20))},
					CPU:    &specs.LinuxCPU{Quota: new(int64(25000)), Period: new(uint64(100000))},
				},
				CgroupsPath: "/pod/container",
				Namespaces:  []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.NetworkNamespace, Path: "/run/netns/pod"}},
			},
		},
		BundleDir:       "/bundle",
		CreatedAt:       time.Date(2026, 10, 21, 1, 2, 3, 4, time.UTC),
		Owner:           "owner",
		ConsoleSocket:   "/run/console.sock",
		Status:          Running,
		Sandbox:         sb,
		Saver:           StateFile{RootDir: rootDir, ID: id},
		GoferMountConfs: specutils.GoferMountConfFlags{{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}},
	}
	c.GoferPid.Store(456)
	return c
}

// mustJSON returns the JSON encoding of v, to compare decoded values.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestStateEncodingRoundTrip(t *testing.T) {
	want := testContainer(t, "/root")
	data, err := encodeState(want)
	if err != nil {
		t.Fatalf("encodeState: %v", err)
	}
	if !bytes.HasPrefix(data, stateFileMagic) {
		t.Errorf("encoded state %x doesn't start with %x", data, stateFileMagic)
	}
	var got Container
	if err := decodeState(data, &got); err != nil {
		t.Fatalf("decodeState: %v", err)
	}
	if g, w := mustJSON(t, &got), mustJSON(t, want); g != w {
		t.Errorf("decoded state differs:\ngot:  %s\nwant: %s", g, w)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.Sandbox.StartTime.Equal(want.Sandbox.StartTime) {
		t.Errorf("times differ: got %v, %v, want %v, %v", got.CreatedAt, got.Sandbox.StartTime, want.CreatedAt, want.Sandbox.StartTime)
	}
}

// TestStateEncodingLegacyJSON checks that state files written as JSON by
// older versions of runsc can still be read.
func TestStateEncodingLegacyJSON(t *testing.T) {
	want := testContainer(t, "/root")
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got Container
	if err := decodeState(data, &got); err != nil {
		t.Fatalf("decodeState: %v", err)
	}
	if g, w := mustJSON(t, &got), mustJSON(t, want); g != w {
		t.Errorf("decoded state differs:\ngot:  %s\nwant: %s", g, w)
	}
}

// TestStateEncodingOtherVersions checks that state files written by versions
// of runsc that have more fields can be read.
func TestStateEncodingOtherVersions(t *testing.T) {
	want := testContainer(t, "/root")
	data, err := encodeState(want)
	if err != nil {
		t.Fatalf("encodeState: %v", err)
	}
	// Add a field to the map that encodes the container.
	body := data[len(stateFileMagic):]
	if body[0]>>5 != 5 || body[0]&0x1f >= 23 {
		t.Fatalf("unexpected encoding of the container: %x", body[:1])
	}
	body[0]++
	for _, v := range []any{"fieldFromAnotherVersion", map[string][]int{"a": {1, 2}}} {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatalf("cbor.Marshal: %v", err)
		}
		data = append(data, b...)
	}
	var got Container
	if err := decodeState(data, &got); err != nil {
		t.Fatalf("decodeState: %v", err)
	}
	if g, w := mustJSON(t, &got), mustJSON(t, want); g != w {
		t.Errorf("decoded state differs:\ngot:  %s\nwant: %s", g, w)
	}
}

// TestStateEncodingOldReader checks that versions of runsc that only read
// JSON state files fail to read the new ones, rather than misreading them.
func TestStateEncodingOldReader(t *testing.T) {
	data, err := encodeState(testContainer(t, "/root"))
	if err != nil {
		t.Fatalf("encodeState: %v", err)
	}
	var c Container
	if err := json.Unmarshal(data, &c); err == nil {
		t.Errorf("json.Unmarshal succeeded, want error")
	}
}

func TestStateEncodingCorrupt(t *testing.T) {
	data, err := encodeState(testContainer(t, "/root"))
	if err != nil {
		t.Fatalf("encodeState: %v", err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "magic only", data: stateFileMagic},
		{name: "truncated", data: data[:len(data)-1]},
		{name: "trailing data", data: append(append([]byte{}, data...), 0)},
		{name: "truncated json", data: []byte(`{"id":"container"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Container
			if err := decodeState(tc.data, &c); err == nil {
				t.Errorf("decodeState succeeded, want error")
			}
		})
	}
}

// TestStateFileSaveLoad checks that state files are saved with CBOR and
// loaded, and that JSON state files written by older versions of runsc are
// loaded.
func TestStateFileSaveLoad(t *testing.T) {
	rootDir := t.TempDir()
	want := testContainer(t, rootDir)
	if err := want.Saver.LockForNew(); err != nil {
		t.Fatalf("LockForNew: %v", err)
	}
	if err := want.Saver.SaveLocked(want); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}
	want.Saver.UnlockOrDie()
	data, err := os.ReadFile(want.Saver.statePath())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.HasPrefix(data, stateFileMagic) {
		t.Errorf("state file %x doesn't start with %x", data, stateFileMagic)
	}

	load := func() *Container {
		t.Helper()
		got, err := Load(rootDir, want.Saver.ID, LoadOpts{Exact: true, SkipCheck: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return got
	}
	if g, w := mustJSON(t, load()), mustJSON(t, want); g != w {
		t.Errorf("loaded state differs:\ngot:  %s\nwant: %s", g, w)
	}

	legacy, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(want.Saver.statePath(), legacy, 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if g, w := mustJSON(t, load()), mustJSON(t, want); g != w {
		t.Errorf("loaded legacy state differs:\ngot:  %s\nwant: %s", g, w)
	}
}

func BenchmarkStateEncoding(b *testing.B) {
	c := testContainer(&testing.T{}, "/root")
	cborData, err := encodeState(c)
	if err != nil {
		b.Fatalf("encodeState: %v", err)
	}
	jsonData, err := json.Marshal(c)
	if err != nil {
		b.Fatalf("json.Marshal: %v", err)
	}
	b.Run("EncodeCBOR", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := encodeState(c); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("EncodeJSON", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := json.Marshal(c); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DecodeCBOR", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var c Container
			if err := decodeState(cborData, &c); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DecodeJSON", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var c Container
			if err := decodeState(jsonData, &c); err != nil {
				b.Fatal(err)
			}
		}
	})
}

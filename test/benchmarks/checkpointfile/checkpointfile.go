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

// Package checkpointfile benchmarks decoding and encoding the kernel state of
// a checkpoint.
//
// BenchmarkCheckpointFile starts nginx with a fixed number of worker
// processes, waits until it listens and its CPU usage has stayed flat,
// checkpoints it, and reports the sizes of the checkpoint files. Each
// iteration then decodes the kernel from the state file with this binary's
// pkg/state (as runsc restore does), and encodes the decoded kernel again (as
// runsc checkpoint does), reporting the CPU time and Go heap allocations of
// each.
//
// The state file must be decoded by the codec that wrote it, so this binary
// must be built from the same tree as the runtime under test. It checks that
// both use the same stream format, and decoding fails on type mismatches.
package checkpointfile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

const (
	// workers is the number of nginx worker processes. It is fixed, rather
	// than nginx's "auto", so that the kernel object graph doesn't depend
	// on the number of CPUs.
	workers = 4

	// quiesceInterval is the interval between CPU usage samples, and
	// quiesceSamples is the number of consecutive intervals in which the
	// container must use less than quiesceMaxCPU of a CPU.
	quiesceInterval = 500 * time.Millisecond
	quiesceSamples  = 4
	quiesceMaxCPU   = 0.005
	quiesceTimeout  = 60 * time.Second
)

// BenchmarkCheckpointFile reports, for a checkpoint of an idle nginx with
// several worker processes:
//
//   - state_file_bytes, pages_file_bytes, pages_metadata_bytes: the sizes of
//     the checkpoint files, and checkpoint_bytes, their sum.
//   - decode_cpu_seconds, decode_allocs, decode_alloc_bytes: the process CPU
//     time (user and system, so including garbage collection) and the Go heap
//     allocations of state.Load of the kernel from the state file, including
//     decompression and the afterLoad callbacks of the kernel's objects.
//   - encode_cpu_seconds, encode_allocs, encode_alloc_bytes: the same for
//     state.Save of the decoded kernel to a counting writer, without
//     compression; encoded_bytes is the size of that encoding.
func BenchmarkCheckpointFile(b *testing.B) {
	if !testutil.IsCheckpointSupported() {
		b.Skip("Checkpoint is not supported on this runtime.")
	}
	if rt := dockerutil.Runtime(); rt == "" || rt == "runc" {
		b.Skip("The checkpoint file benchmark requires runsc.")
	}
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()
	ctx := context.Background()

	files, names, mounts := checkpointNginx(ctx, b, machine)
	stateFile := files["checkpoint.img"]
	ctx = restoreContext(b, names, mounts)
	// Tasks create their platform contexts when they are loaded.
	plat, err := ptrace.New()
	if err != nil {
		b.Fatalf("failed to create platform: %v", err)
	}

	var decode, encode usage
	var encodedBytes int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ctx, cleanup := withHostFDs(b, ctx, names)
		b.StartTimer()
		var k *kernel.Kernel
		decode.add(measure(b, func() error {
			var err error
			k, err = loadKernel(ctx, plat, stateFile)
			return err
		}))
		w := &countingWriter{}
		encode.add(measure(b, func() error {
			_, err := state.Save(ctx, w, k)
			return err
		}))
		encodedBytes = w.n
		b.StopTimer()
		cleanup()
		b.StartTimer()
	}
	b.StopTimer()
	b.ReportMetric(float64(len(stateFile)), "state_file_bytes")
	b.ReportMetric(float64(len(files["pages.img"])), "pages_file_bytes")
	b.ReportMetric(float64(len(files["pages_meta.img"])), "pages_metadata_bytes")
	total := 0
	for _, f := range files {
		total += len(f)
	}
	b.ReportMetric(float64(total), "checkpoint_bytes")
	n := float64(b.N)
	b.ReportMetric(decode.cpu.Seconds()/n, "decode_cpu_seconds")
	b.ReportMetric(float64(decode.allocs)/n, "decode_allocs")
	b.ReportMetric(float64(decode.bytes)/n, "decode_alloc_bytes")
	b.ReportMetric(encode.cpu.Seconds()/n, "encode_cpu_seconds")
	b.ReportMetric(float64(encode.allocs)/n, "encode_allocs")
	b.ReportMetric(float64(encode.bytes)/n, "encode_alloc_bytes")
	b.ReportMetric(float64(encodedBytes), "encoded_bytes")
}

// checkpointNginx checkpoints an idle nginx container, and returns the
// contents of the checkpoint files by name, and the names that runsc may give
// the container and its mount destinations (see containerSpec).
func checkpointNginx(ctx context.Context, b *testing.B, machine harness.Machine) (files map[string][]byte, names, mounts []string) {
	b.Helper()
	container := machine.GetContainer(ctx, b)
	defer container.CleanUp(ctx)
	if err := container.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}, "nginx", "-c", "/etc/nginx/nginx_gofer.conf", "-g", fmt.Sprintf("worker_processes %d;", workers)); err != nil {
		b.Fatalf("failed to spawn container: %v", err)
	}
	if err := waitListening(ctx, container, 80); err != nil {
		b.Fatalf("nginx is not listening: %v", err)
	}
	if err := waitQuiescent(ctx, container); err != nil {
		b.Fatalf("nginx did not quiesce: %v", err)
	}
	names, mounts, err := containerSpec(container.ID())
	if err != nil {
		b.Fatalf("failed to read the container's spec: %v", err)
	}

	const name = "checkpointfile"
	if err := container.Checkpoint(ctx, name); err != nil {
		b.Fatalf("failed to checkpoint container: %v", err)
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		b.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()
	info, err := cli.Info(ctx)
	if err != nil {
		b.Fatalf("failed to get docker info: %v", err)
	}
	dir := filepath.Join(info.DockerRootDir, "containers", container.ID(), "checkpoints", name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatalf("failed to read checkpoint directory (the benchmark must run as root): %v", err)
	}
	files = make(map[string][]byte)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			b.Fatalf("failed to read checkpoint file: %v", err)
		}
		files[e.Name()] = data
	}
	if _, ok := files["checkpoint.img"]; !ok {
		b.Fatalf("no checkpoint.img in %s", dir)
	}
	return files, names, mounts
}

// containerSpec returns the names that runsc may give the container, and the
// destinations of its root and mounts, from its spec. runsc derives the IDs
// of the container's host file descriptors and of the private memory files of
// its filesystems from them (see runsc/boot).
func containerSpec(id string) (names, mounts []string, err error) {
	data, err := os.ReadFile(filepath.Join("/run/containerd/io.containerd.runtime.v2.task/moby", id, "config.json"))
	if err != nil {
		return nil, nil, err
	}
	var spec struct {
		Annotations map[string]string
		Mounts      []struct {
			Destination string
		}
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, err
	}
	// Docker doesn't name containers, so runsc names the first container
	// "__no_name_0"; CRI runtimes set an annotation.
	names = []string{"__no_name_0"}
	for k, v := range spec.Annotations {
		if strings.HasSuffix(k, "container-name") || strings.HasSuffix(k, "container_name") {
			names = append(names, v)
		}
	}
	mounts = []string{"/"}
	for _, m := range spec.Mounts {
		mounts = append(mounts, m.Destination)
	}
	return names, mounts, nil
}

// restoreContext returns a context with the memory files that the kernel's
// objects use when they are loaded and saved: the main memory file, and a
// private memory file for each container name and mount. The memory files are
// empty, since the benchmark doesn't load pages.
func restoreContext(b *testing.B, names, mounts []string) context.Context {
	b.Helper()
	newMF := func(id checkpoint.ResourceID) *pgalloc.MemoryFile {
		fd, err := memutil.CreateMemFD("checkpointfile", 0)
		if err != nil {
			b.Fatalf("failed to create memory file: %v", err)
		}
		mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), "checkpointfile"), pgalloc.MemoryFileOpts{
			DisableMemoryAccounting: true,
			ResourceID:              id,
		})
		if err != nil {
			b.Fatalf("failed to create memory file: %v", err)
		}
		// Allow saving the filesystems that use it again.
		mf.MarkSavable()
		return mf
	}
	mfs := make(map[checkpoint.ResourceID]*pgalloc.MemoryFile)
	for _, name := range names {
		for _, mount := range mounts {
			id := checkpoint.ResourceID{ContainerName: name, Path: mount}
			mfs[id] = newMF(id)
		}
	}
	ctx := context.WithValue(context.Background(), pgalloc.CtxMemoryFile, newMF(checkpoint.ResourceID{}))
	return context.WithValue(ctx, pgalloc.CtxMemoryFileMap, mfs)
}

// withHostFDs returns ctx with host file descriptors for the standard I/O of
// containers with the given names, which the kernel's host file inodes adopt
// when they are loaded, and a function that releases them.
func withHostFDs(b *testing.B, ctx context.Context, names []string) (context.Context, func()) {
	b.Helper()
	fdmap := make(map[checkpoint.ResourceID]int)
	var fds []int
	for _, name := range names {
		// Each host inode registers its file descriptor with fdnotifier,
		// so each needs its own.
		for stdio := 0; stdio < 3; stdio++ {
			var p [2]int
			if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
				b.Fatalf("pipe2: %v", err)
			}
			fds = append(fds, p[0], p[1])
			if stdio == 0 {
				fdmap[host.MakeResourceID(name, stdio)] = p[0]
			} else {
				fdmap[host.MakeResourceID(name, stdio)] = p[1]
			}
		}
	}
	return context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, fdmap), func() {
		for _, fd := range fds {
			if fdnotifier.HasFD(int32(fd)) {
				fdnotifier.RemoveFD(int32(fd))
			}
			unix.Close(fd)
		}
	}
}

// waitListening waits for a socket listening on port in the container.
func waitListening(ctx context.Context, container *dockerutil.Container, port int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := fmt.Sprintf("while ! grep -s -E ':%04X [0-9A-F:]+ 0A' /proc/net/tcp /proc/net/tcp6; do sleep 0.01; done", port)
	if out, err := container.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// waitQuiescent waits until the container's CPU usage stays below
// quiesceMaxCPU for quiesceSamples consecutive intervals of quiesceInterval.
func waitQuiescent(ctx context.Context, container *dockerutil.Container) error {
	deadline := time.Now().Add(quiesceTimeout)
	var lastUsage uint64
	var lastTime time.Time
	quiet := 0
	for quiet < quiesceSamples {
		if time.Now().After(deadline) {
			return fmt.Errorf("CPU usage did not stay below %.1f%% for %v within %v", 100*quiesceMaxCPU, quiesceSamples*quiesceInterval, quiesceTimeout)
		}
		stats, err := container.Stats(ctx)
		if err != nil {
			return err
		}
		now := time.Now()
		usage := stats.CPUStats.CPUUsage.TotalUsage
		if !lastTime.IsZero() {
			if float64(usage-lastUsage) < quiesceMaxCPU*float64(now.Sub(lastTime).Nanoseconds()) {
				quiet++
			} else {
				quiet = 0
			}
		}
		lastUsage, lastTime = usage, now
		time.Sleep(quiesceInterval)
	}
	return nil
}

// loadKernel decodes the kernel from the state file data, as runsc restore
// and kernel.LoadFrom do, without the steps that follow state.Load.
func loadKernel(ctx context.Context, plat platform.Platform, data []byte) (*kernel.Kernel, error) {
	sr, _, err := statefile.NewReader(io.NopCloser(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, fmt.Errorf("statefile.NewReader: %w", err)
	}
	r := bufio.NewReader(sr)
	if err := checkFormat(r); err != nil {
		return nil, err
	}
	var fs cpuid.FeatureSet
	if _, err := state.Load(ctx, r, &fs); err != nil {
		return nil, fmt.Errorf("loading the CPUID feature set: %w (the benchmark must be built from the same tree as the runtime)", err)
	}
	k := &kernel.Kernel{Platform: plat}
	k.SetMemoryFile(pgalloc.MemoryFileFromContext(ctx))
	if _, err := state.Load(ctx, r, k); err != nil {
		return nil, fmt.Errorf("loading the kernel: %w (the benchmark must be built from the same tree as the runtime)", err)
	}
	return k, nil
}

// typedFlag is set in the object header of streams in the typed format of
// pkg/state, where it exists.
const typedFlag = 1 << 62

// streamFlags returns the flags of the object header at the start of r.
func streamFlags(r *bufio.Reader) (uint64, error) {
	hdr, err := r.Peek(binary.MaxVarintLen64)
	if err != nil && len(hdr) == 0 {
		return 0, err
	}
	v, n := binary.Uvarint(hdr)
	if n <= 0 {
		return 0, fmt.Errorf("invalid object header")
	}
	return v & typedFlag, nil
}

// checkFormat checks that the stream at the start of r is in the format that
// this binary's pkg/state writes, so that it is decoded by the same codec.
func checkFormat(r *bufio.Reader) error {
	got, err := streamFlags(r)
	if err != nil {
		return fmt.Errorf("reading the stream header: %w", err)
	}
	var (
		buf   bytes.Buffer
		probe int64
	)
	if _, err := state.Save(context.Background(), &buf, &probe); err != nil {
		return fmt.Errorf("encoding a probe: %w", err)
	}
	want, err := streamFlags(bufio.NewReader(&buf))
	if err != nil {
		return fmt.Errorf("reading the probe header: %w", err)
	}
	if got != want {
		return fmt.Errorf("the state file's stream format (flags %#x) differs from this binary's (flags %#x): the benchmark must be built from the same tree as the runtime", got, want)
	}
	return nil
}

// usage is the CPU time and allocations of an operation.
type usage struct {
	cpu    time.Duration
	allocs uint64
	bytes  uint64
}

func (u *usage) add(v usage) {
	u.cpu += v.cpu
	u.allocs += v.allocs
	u.bytes += v.bytes
}

// measure runs fn and returns the process CPU time and Go heap allocations it
// used. It collects garbage first, so that fn is only charged for the
// collections that its own allocations cause.
func measure(b *testing.B, fn func() error) usage {
	b.Helper()
	b.StopTimer()
	runtime.GC()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	cpu0 := processCPU(b)
	b.StartTimer()
	err := fn()
	b.StopTimer()
	cpu1 := processCPU(b)
	runtime.ReadMemStats(&ms1)
	b.StartTimer()
	if err != nil {
		b.Fatal(err)
	}
	return usage{
		cpu:    cpu1 - cpu0,
		allocs: ms1.Mallocs - ms0.Mallocs,
		bytes:  ms1.TotalAlloc - ms0.TotalAlloc,
	}
}

// processCPU returns the user and system CPU time of the process.
func processCPU(b *testing.B) time.Duration {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		b.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// countingWriter counts the bytes written to it.
type countingWriter struct {
	n int64
}

// Write implements io.Writer.Write.
func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// Make sure that the kernel's state types are registered as by runsc.
var _ = boot.VersionKey

func TestMain(m *testing.M) {
	harness.Init()
	// Loading tasks' floating point state uses the host's CPUID, as in
	// runsc.
	cpuid.Initialize()
	os.Exit(m.Run())
}

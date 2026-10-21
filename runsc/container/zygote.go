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

// A zygote is a sandbox booted ahead of time for a root container that does
// not exist yet. Booting a sandbox (exec'ing the Sentry, setting up its
// namespaces, chroot, platform, seccomp filters and kernel) is most of the
// cost of creating a container; adopting a zygote leaves only the container's
// gofer and one RPC on the critical path.
//
// A zygote is booted from a template bundle by "runsc create --zygote", and
// adopted by "runsc create --adopt-zygote" (or "runsc restore"). The caller
// owns the zygotes: it decides how many to keep, where, and when to delete
// unused ones, which it does like for any other container. runsc runs no
// pool and no background process.
//
// Security: a zygote is used at most once and never runs application code
// before it is adopted, so it holds nothing that a previous container could
// have tampered with. It is booted from a copy of the template spec stripped
// of everything container-specific: the process arguments, environment and
// working directory, the hostname, the rootfs and mount sources, the hooks
// and the network namespace. It has no gofer, so it has no access to any container
// file, and it boots in a new, empty network namespace. The adopting container
// provides all of these at adoption, exactly as it would to a new sandbox.
//
// Adoption requires that the rest of the spec, the runsc flags and the
// binaries are the same as the zygote's (the zygote's "shape"): those are
// what the zygote's Sentry was booted with. In particular the container must
// use the zygote's cgroup, so that adoption moves no process between cgroups.
// Any mismatch or failure falls back to booting a new sandbox.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// zygotePlaceholder replaces the paths and process arguments that a zygote
// boots without. Nothing can exist at this path.
const zygotePlaceholder = "/dev/null/zygote"

// zygoteIneligible returns why the root container described by args can
// neither boot as nor adopt a zygote, or "" if it can.
func zygoteIneligible(conf *config.Config, args *Args) string {
	spec := args.Spec
	switch {
	case !specutils.IsRootContainer(spec):
		return "not a root container"
	case args.NoRootContainer:
		return "no root container"
	case len(args.FSRestoreImagePaths) != 0:
		return "filesystem restore"
	case len(args.PassFiles) != 0, args.ExecFile != nil:
		return "passed files"
	case args.ConsoleSocket != "", spec.Process == nil, spec.Process.Terminal:
		return "terminal"
	case args.UserLog != "":
		return "user log"
	case args.Attached:
		return "attached sandbox"
	case spec.Root == nil:
		return "no root filesystem"
	case conf.Network != config.NetworkSandbox && conf.Network != config.NetworkNone:
		return fmt.Sprintf("network %q", conf.Network)
	case conf.Rootless:
		return "rootless"
	case conf.IgnoreCgroups, spec.Linux == nil, spec.Linux.CgroupsPath == "":
		return "no cgroup"
	case conf.SystemdCgroup, cgroup.LikelySystemdPath(spec.Linux.CgroupsPath):
		return "systemd cgroup"
	case conf.ProfilingMetricsLog == "-":
		return "profiling metrics on stdout"
	case specutils.NVProxyEnabled(spec, conf), specutils.TPUProxyEnabled(spec, conf), specutils.RDMAEnabled(spec, conf):
		return "device proxy"
	case specutils.RootfsTarUpperPath(spec) != "":
		return "rootfs tar"
	}
	if _, ok := spec.Annotations[cgroupParentAnnotation]; ok {
		return "cgroup parent annotation"
	}
	return ""
}

// zygoteSpec returns a copy of spec without anything specific to one
// container: the copy holds placeholders for the process arguments, rootfs
// and gofer mount sources, and holds no environment, working directory,
// hostname or network namespace path. Mount sources under bundleDir (to
// which specutils.ReadSpec turns relative sources) are made relative again.
func zygoteSpec(spec *specs.Spec, bundleDir string) (*specs.Spec, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	z := &specs.Spec{}
	if err := json.Unmarshal(b, z); err != nil {
		return nil, err
	}
	z.Process.Args = []string{zygotePlaceholder}
	z.Process.Env = nil
	z.Process.Cwd = "/"
	// The order of capabilities doesn't matter.
	if c := z.Process.Capabilities; c != nil {
		for _, set := range [][]string{c.Bounding, c.Effective, c.Inheritable, c.Permitted, c.Ambient} {
			slices.Sort(set)
		}
	}
	z.Hostname = ""
	z.Domainname = ""
	// Hooks run in runsc, and only for the adopting container.
	z.Hooks = nil
	z.Root.Path = zygotePlaceholder
	prefix := filepath.Clean(bundleDir) + "/"
	for i := range z.Mounts {
		m := &z.Mounts[i]
		if specutils.IsGoferMount(*m) {
			m.Source = zygotePlaceholder
		} else if rel, ok := strings.CutPrefix(m.Source, prefix); ok {
			m.Source = rel
		}
	}
	if z.Linux != nil {
		for i := range z.Linux.Namespaces {
			if z.Linux.Namespaces[i].Type == specs.NetworkNamespace {
				z.Linux.Namespaces[i].Path = ""
			}
		}
	}
	return z, nil
}

// readBundleSpec returns the spec in bundleDir as the Sentry reads it.
func readBundleSpec(conf *config.Config, bundleDir string) (*specs.Spec, error) {
	f, err := specutils.OpenSpec(bundleDir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return specutils.ReadSpecFromFile(bundleDir, f, specutils.SpecOpts{Conf: conf})
}

// zygoteShape identifies the zygotes that the container whose bundle spec
// is spec may adopt: zygotes booted from the same zygote spec, with the same
// flags and binaries.
func zygoteShape(conf *config.Config, spec *specs.Spec, bundleDir string) (string, error) {
	z, err := zygoteSpec(spec, bundleDir)
	if err != nil {
		return "", err
	}
	var st unix.Stat_t
	if err := unix.Stat(specutils.ExePath, &st); err != nil {
		return "", fmt.Errorf("stat %q: %w", specutils.ExePath, err)
	}
	runscID := fmt.Sprintf("%d:%d:%d:%d.%d", st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec)
	sentryID, err := sandbox.SentryBinaryID(conf)
	if err != nil {
		return "", err
	}
	return hashZygoteShape(z, conf, runscID, sentryID)
}

// hashZygoteShape hashes the zygote spec z, the flags in conf and the
// binary identities binIDs.
func hashZygoteShape(z *specs.Spec, conf *config.Config, binIDs ...string) (string, error) {
	b, err := json.Marshal(z)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(b)
	// All flags but --root, which is where zygotes and containers keep their
	// state. ToFlags iterates over a map.
	flags := slices.DeleteFunc(conf.ToFlags(), func(f string) bool {
		return strings.HasPrefix(f, "--root=")
	})
	slices.Sort(flags)
	log.Debugf("Zygote shape: spec %s, flags %q, binaries %q", b, flags, binIDs)
	for _, s := range append(flags, binIDs...) {
		fmt.Fprintf(h, "\x00%s", s)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// zygoteSpecFile returns a memfd holding spec.
func zygoteSpecFile(spec *specs.Spec) (*os.File, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate("zygote-spec", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "zygote spec")
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// claimZygote takes the zygote with the given ID in rootDir, if it has the
// given shape. On success, the zygote's state file is gone, so that nothing
// else can claim, start or delete it, and the caller must either adopt or
// destroy the zygote.
func claimZygote(rootDir, id, shape string) (*Container, error) {
	st := StateFile{RootDir: rootDir, ID: FullID{SandboxID: id, ContainerID: id}}
	if err := st.lock(TryAcquire); err != nil {
		return nil, fmt.Errorf("locking zygote: %w", err)
	}
	defer func() {
		st.UnlockOrDie()
		_ = st.close()
	}()
	z := &Container{}
	if err := st.loadLocked(z); err != nil {
		return nil, fmt.Errorf("loading zygote: %w", err)
	}
	switch {
	case z.Sandbox == nil || z.Sandbox.ZygoteShape == "" || z.Status != Created:
		return nil, errors.New("not an unadopted zygote")
	case z.Sandbox.ZygoteShape != shape:
		return nil, errors.New("zygote was booted for a different spec, flags or binary")
	}
	z.Sandbox.SetRootDir(rootDir)
	if ok, err := z.Sandbox.IsRunning(); err != nil || !ok {
		return nil, fmt.Errorf("zygote is not running: %v", err)
	}
	if err := os.Remove(st.statePath()); err != nil {
		return nil, fmt.Errorf("claiming zygote: %w", err)
	}
	z.Saver = StateFile{RootDir: rootDir, ID: st.ID}
	return z, nil
}

// adoptZygote creates the root container described by args by adopting the
// zygote in args.AdoptZygote, instead of booting a new sandbox.
func (c *Container) adoptZygote(conf *config.Config, args *Args) (retErr error) {
	if why := zygoteIneligible(conf, args); why != "" {
		return fmt.Errorf("container is not eligible: %s", why)
	}
	spec, err := readBundleSpec(conf, args.BundleDir)
	if err != nil {
		return fmt.Errorf("reading spec: %w", err)
	}
	shape, err := zygoteShape(conf, spec, args.BundleDir)
	if err != nil {
		return err
	}
	z, err := claimZygote(args.AdoptZygote, args.ID, shape)
	if err != nil {
		return err
	}
	sb := z.Sandbox
	defer func() {
		if retErr != nil {
			if err := z.Destroy(); err != nil {
				log.Warningf("Destroying zygote %q: %v", z.Saver.RootDir, err)
			}
		}
	}()

	// Move the control socket first: the zygote's root directory may be
	// removed once the zygote is gone, and the socket can only be renamed
	// within a file system.
	if err := sb.MoveTo(conf.RootDir); err != nil {
		return err
	}
	mountHints, err := sentryapi.NewPodMountHints(args.Spec)
	if err != nil {
		return fmt.Errorf("creating pod mount hints: %w", err)
	}
	if err := cgroup.RunInCgroup(sb.CgroupJSON.Cgroup, func(cloneIntoCgroupFD *os.File) error {
		ioFiles, filestores, devIOFile, mountsFile, err := c.createGoferProcess(conf, mountHints, false /* attached */, cloneIntoCgroupFD)
		if err != nil {
			return fmt.Errorf("creating gofer process: %w", err)
		}
		defer func() {
			for _, f := range slices.Concat(ioFiles, filestores, []*os.File{devIOFile, mountsFile}) {
				if f != nil {
					_ = f.Close()
				}
			}
		}()
		return sb.Adopt(conf, spec, &sandbox.AdoptFiles{
			Stdios:          []*os.File{os.Stdin, os.Stdout, os.Stderr},
			GoferFiles:      ioFiles,
			GoferFilestores: filestores,
			DevIOFile:       devIOFile,
			MountsFile:      mountsFile,
			GoferMountConfs: c.GoferMountConfs,
		})
	}); err != nil {
		if pid := c.GoferPid.Load(); pid > 0 {
			_ = unix.Kill(pid, unix.SIGKILL)
			c.GoferPid.Store(0)
		}
		return err
	}

	// The zygote's Sentry stays in the network namespace it was booted in;
	// its network is copied from the container's.
	if ns, ok := specutils.GetNS(specs.NetworkNamespace, args.Spec); ok && conf.Network == config.NetworkSandbox {
		sb.NetNSPath = ns.Path
	}
	sb.MountHints = mountHints
	if err := z.Saver.Destroy(); err != nil {
		log.Warningf("Removing zygote state in %q: %v", z.Saver.RootDir, err)
	}
	c.Sandbox = sb
	log.Infof("Container %q adopted zygote from %q, PID: %d", c.ID, args.AdoptZygote, sb.Pid.Load())
	return nil
}

// zygoteBootSpec returns the shape of a zygote booted from the bundle in
// bundleDir, and a file holding the zygote spec to boot it with.
func zygoteBootSpec(conf *config.Config, bundleDir string) (string, *os.File, error) {
	spec, err := readBundleSpec(conf, bundleDir)
	if err != nil {
		return "", nil, fmt.Errorf("reading spec: %w", err)
	}
	shape, err := zygoteShape(conf, spec, bundleDir)
	if err != nil {
		return "", nil, err
	}
	z, err := zygoteSpec(spec, bundleDir)
	if err != nil {
		return "", nil, err
	}
	f, err := zygoteSpecFile(z)
	if err != nil {
		return "", nil, err
	}
	return shape, f, nil
}

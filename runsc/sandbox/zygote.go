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

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// AdoptFiles are the host files that a root container hands to the zygote it
// adopts. The caller keeps ownership of the files.
type AdoptFiles struct {
	// Stdios replace the root container's stdio.
	Stdios []*os.File

	// GoferFiles, GoferFilestores, DevIOFile and MountsFile come from the
	// adopting container's gofer, as for a sandbox booted for it.
	GoferFiles      []*os.File
	GoferFilestores []*os.File
	DevIOFile       *os.File
	MountsFile      *os.File
	GoferMountConfs []specutils.GoferMountConf
}

// Adopt binds the zygote s to the root container described by spec, the
// spec as read from the container's bundle.
func (s *Sandbox) Adopt(conf *config.Config, spec *specs.Spec, f *AdoptFiles) error {
	log.Debugf("Adopting zygote sandbox %q, PID: %d", s.ID, s.Pid.Load())
	if err := s.configureStdios(conf, f.Stdios); err != nil {
		return err
	}
	args := sentryapi.AdoptArgs{
		Spec:                 spec,
		GoferMountConfs:      f.GoferMountConfs,
		NumStdio:             len(f.Stdios),
		NumGoferFDs:          len(f.GoferFiles),
		NumGoferFilestoreFDs: len(f.GoferFilestores),
	}
	files := append([]*os.File(nil), f.Stdios...)
	files = append(files, f.GoferFiles...)
	files = append(files, f.GoferFilestores...)
	if f.DevIOFile != nil {
		args.HaveDevGofer = true
		files = append(files, f.DevIOFile)
	}
	if f.MountsFile != nil {
		args.HaveMountsFile = true
		files = append(files, f.MountsFile)
	}
	args.FilePayload = urpc.FilePayload{Files: files}
	if err := s.call(sentryapi.ContMgrAdopt, &args, nil); err != nil {
		return fmt.Errorf("adopting zygote sandbox %q: %w", s.ID, err)
	}
	s.ZygoteShape = ""
	return nil
}

// MoveTo moves the sandbox's control socket into rootDir, the runsc root
// directory that holds the sandbox's state from now on.
func (s *Sandbox) MoveTo(rootDir string) error {
	old := s.getControlSocketPath()
	s.SetRootDir(rootDir)
	dst := filepath.Join(rootDir, controlSocketName(s.ID))
	if old == dst {
		return nil
	}
	// A bound socket can be renamed: connect(2) resolves the path to the
	// socket's inode.
	if err := os.Rename(old, dst); err != nil {
		return fmt.Errorf("moving control socket: %w", err)
	}
	s.ControlSocketPath = dst
	return nil
}

// SentryBinaryID identifies the Sentry binary that sandboxes boot with conf.
// A zygote can only be adopted by a runsc that boots the same binary.
func SentryBinaryID(conf *config.Config) (string, error) {
	path, err := sentryBinary(conf).Path()
	if err != nil {
		return "", err
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", fmt.Errorf("stat %q: %w", path, err)
	}
	return fmt.Sprintf("%s:%d:%d:%d:%d.%d", path, st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec), nil
}

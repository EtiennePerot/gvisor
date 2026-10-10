// Copyright 2019 The gVisor Authors.
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

package cmd

import (
	"context"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

// Syscalls implements subcommands.Command for the "syscalls" command, by
// forwarding it to the Sentry binary whose syscall tables it prints.
type Syscalls struct {
	format   string
	os       string
	arch     string
	filename string
}

// Name implements subcommands.Command.Name.
func (*Syscalls) Name() string {
	return "syscalls"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Syscalls) Synopsis() string {
	return "Print compatibility information for syscalls."
}

// Usage implements subcommands.Command.Usage.
func (*Syscalls) Usage() string {
	return "syscalls [options] - Print compatibility information for syscalls.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Syscalls) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.format, "format", "table", "Output format (table, csv, json).")
	f.StringVar(&s.os, "os", "all", "The OS (e.g. linux)")
	f.StringVar(&s.arch, "arch", "all", "The CPU architecture (e.g. amd64).")
	f.StringVar(&s.filename, "filename", "", "Output filename (otherwise stdout).")
}

// Execute implements subcommands.Command.Execute.
func (s *Syscalls) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	sentry := &gvisorbinaries.GvisorSentry
	p, err := sentry.Path()
	if err != nil {
		return util.Errorf("Sentry sidecar binary %q is not available: %v", sentry.Name, err)
	}
	argv := []string{p, s.Name(), "-format", s.format, "-os", s.os, "-arch", s.arch, "-filename", s.filename}
	err = sentry.Exec(gvisorbinaries.Options{Argv: argv, Envv: os.Environ()})
	// Unreachable unless `sentry.Exec` fails.
	return util.Errorf("Failed to execute %v: %v", argv, err)
}

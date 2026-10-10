// Copyright 2020 The gVisor Authors.
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
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

// Symbolize implements subcommands.Command for the "symbolize" command, by
// forwarding it to the Sentry binary whose coverage metadata it needs.
type Symbolize struct {
	dumpAll bool
}

// Name implements subcommands.Command.Name.
func (*Symbolize) Name() string {
	return "symbolize"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Symbolize) Synopsis() string {
	return "Convert synthetic instruction pointers from kcov into positions in the gVisor source code. Only used when Go coverage is enabled."
}

// Usage implements subcommands.Command.Usage.
func (*Symbolize) Usage() string {
	return `symbolize - converts synthetic instruction pointers into positions in the gVisor source code.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Symbolize) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.dumpAll, "all", false, "dump information on all coverage blocks along with their synthetic PCs")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Symbolize) FetchSpec(*config.Config, *flag.FlagSet) (string, *specs.Spec, error) {
	// This command does not operate on a single container, so nothing to fetch.
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *Symbolize) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	sentry := &gvisorbinaries.GvisorSentry
	p, err := sentry.Path()
	if err != nil {
		return util.Errorf("Sentry sidecar binary %q is not available: %v", sentry.Name, err)
	}
	argv := []string{p, c.Name()}
	if c.dumpAll {
		argv = append(argv, "-all")
	}
	err = sentry.Exec(gvisorbinaries.Options{Argv: argv, Envv: os.Environ()})
	// Unreachable unless `sentry.Exec` fails.
	return util.Errorf("Failed to execute %v: %v", argv, err)
}

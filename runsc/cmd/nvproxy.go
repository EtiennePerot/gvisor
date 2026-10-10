// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

// Nvproxy implements subcommands.Command for the "nvproxy" command, by
// forwarding it to the Sentry binary which contains nvproxy.
type Nvproxy struct{}

// Name implements subcommands.Command.Name.
func (*Nvproxy) Name() string {
	return "nvproxy"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Nvproxy) Synopsis() string {
	return "shows information about nvproxy support"
}

// Usage implements subcommands.Command.Usage.
func (*Nvproxy) Usage() string {
	return "Usage: nvproxy <flags> <subcommand> <subcommand args>\n\nRun `nvproxy help` to list subcommands.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Nvproxy) SetFlags(*flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Nvproxy) FetchSpec(*config.Config, *flag.FlagSet) (string, *specs.Spec, error) {
	// None of the subcommands operate on a single container, so nothing to fetch.
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *Nvproxy) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	sentry := &gvisorbinaries.GvisorSentry
	p, err := sentry.Path()
	if err != nil {
		return util.Errorf("Sentry sidecar binary %q is not available: %v", sentry.Name, err)
	}
	argv := append([]string{p, c.Name()}, f.Args()...)
	err = sentry.Exec(gvisorbinaries.Options{Argv: argv, Envv: os.Environ()})
	// Unreachable unless `sentry.Exec` fails.
	return util.Errorf("Failed to execute %v: %v", argv, err)
}

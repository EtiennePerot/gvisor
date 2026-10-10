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

package cmd

import (
	"context"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

// bootDeprecatedMessage explains why `runsc boot` no longer works.
var bootDeprecatedMessage = "The `runsc boot` subcommand is deprecated: the Sentry now runs from the separate " + gvisorbinaries.GvisorSentry.Name + " binary."

// Boot implements subcommands.Command for the deprecated "boot" command.
type Boot struct {
	util.InternalSubCommand
}

// Name implements subcommands.Command.Name.
func (*Boot) Name() string {
	return "boot"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Boot) Synopsis() string {
	return "deprecated; the Sentry now runs from a separate binary"
}

// Usage implements subcommands.Command.Usage.
func (*Boot) Usage() string {
	return bootDeprecatedMessage + "\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Boot) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*Boot) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	return util.Errorf("%s", bootDeprecatedMessage)
}

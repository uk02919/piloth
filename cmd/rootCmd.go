/*
  pilot host controller
  © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
  Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
  Contributors to this project, hereby assign copyright in this code to the project,
  to be licensed under the same terms as the rest of the code.
*/

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"southwinds.dev/piloth/core"
)

type RootCmd struct {
	Cmd *cobra.Command
}

// NewRootCmd creates the root command
func NewRootCmd() *RootCmd {
	c := &RootCmd{
		Cmd: &cobra.Command{
			Use:   "piloth",
			Short: "Host Pilot",
			Long: fmt.Sprintf(`
+---------------------------------------------------------+
|      _/_/_/    _/_/_/  _/          _/_/    _/_/_/_/_/   |
|     _/    _/    _/    _/        _/    _/      _/        |
|    _/_/_/      _/    _/        _/    _/      _/         |
|   _/          _/    _/        _/    _/      _/          |
|  _/        _/_/_/  _/_/_/_/    _/_/        _/           |
|                     Host Controller                     | 
+---------------------------------------------------------+

version: %s`, core.Version),
			Version: core.Version,
		},
	}
	c.Cmd.SetVersionTemplate("Pilot Host version: {{.Version}}\n")
	return c
}

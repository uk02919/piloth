/*
  pilot host controller
  © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
  Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
  Contributors to this project, hereby assign copyright in this code to the project,
  to be licensed under the same terms as the rest of the code.
*/

package cmd

func InitialiseRootCmd() *RootCmd {
	rootCmd := NewRootCmd()
	launchCmd := NewLaunchCmd()
	configCmd := NewConfigCmd()
	rootCmd.Cmd.AddCommand(
		launchCmd.cmd,
		configCmd.cmd,
	)
	return rootCmd
}

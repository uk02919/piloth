/*
  pilot host controller
  © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
  Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
  Contributors to this project, hereby assign copyright in this code to the project,
  to be licensed under the same terms as the rest of the code.
*/

package cmd

import (
	"southwinds.dev/artisan/core"
	ctl "southwinds.dev/pilotctl/types"
	pilotCore "southwinds.dev/piloth/core"
	"testing"
)

func TestStart(t *testing.T) {
	// collects device/host information
	hostInfo, err := ctl.NewHostInfo()
	if err != nil {
		core.RaiseErr("cannot collect host information")
	}
	// creates pilot instance
	p, err := pilotCore.NewPilot(pilotCore.PilotOptions{
		UseHwId:            false,
		Telemetry:          true,
		Tracing:            false,
		Info:               hostInfo,
		CPU:                false,
		MEM:                false,
		InsecureSkipVerify: true,
		CVEPath:            "cve",
	})
	core.CheckErr(err, "cannot start pilot")
	// start the pilot
	p.Start()
}

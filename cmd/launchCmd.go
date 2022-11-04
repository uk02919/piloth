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
	"southwinds.dev/artisan/core"
	ctl "southwinds.dev/pilotctl/types"
	pilotCore "southwinds.dev/piloth/core"
)

// LaunchCmd launches host pilot
type LaunchCmd struct {
	cmd                *cobra.Command
	useHwId            bool   // use hardware uuid to identify device (instead of primary mac address)
	tracing            bool   // enables tracing
	telemetry          bool   // enables telemetry file upload
	cpu                *bool  // enables cpu profiling
	mem                *bool  // enables memory profiling
	insecureSkipVerify bool   // if true, crypto/tls accepts any certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used.
	cvePath            string // the  path used to collect CVE reports to export
	cveUploadDelayMins *int   // the maximum delay in minutes for CVE report uploads
}

func NewLaunchCmd() *LaunchCmd {
	c := &LaunchCmd{
		cmd: &cobra.Command{
			Use:   "launch [flags]",
			Short: "launches host pilot",
			Long:  `launches host pilot`,
		},
	}
	c.cmd.Flags().BoolVarP(&c.useHwId, "hw-id", "w", false, "use hardware uuid to identify device(instead of primary mac address)")
	c.cmd.Flags().BoolVarP(&c.tracing, "trace", "t", false, "enables tracing")
	c.cmd.Flags().BoolVarP(&c.telemetry, "telemetry", "m", false, "enables the upload of telemetry information to pilot control")
	c.cpu = c.cmd.Flags().Bool("cpu", false, "enables cpu profiling only; cannot profile memory")
	c.mem = c.cmd.Flags().Bool("mem", false, "enables memory profiling only; cannot profile cpu")
	c.insecureSkipVerify = *c.cmd.Flags().Bool("insecureSkipVerify", false, "disables verification of certificates presented by the server and host name in that certificate; in this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used.")
	c.cmd.Flags().StringVar(&c.cvePath, "cve-path", "", "if set, uploads CVE reports in the specified path to pilot control")
	c.cveUploadDelayMins = c.cmd.Flags().Int("cve-up-delay", 5, "the maximum upload delay (in minutes) which pilot can apply before uploading a CVE report")
	c.cmd.Run = c.Run
	return c
}

func (c *LaunchCmd) Run(_ *cobra.Command, _ []string) {
	fmt.Println(*c.cveUploadDelayMins)
	// collects device/host information
	hostInfo, err := ctl.NewHostInfo()
	if err != nil {
		core.RaiseErr("cannot collect host information")
	}
	// creates pilot instance
	p, err := pilotCore.NewPilot(pilotCore.PilotOptions{
		UseHwId:            c.useHwId,
		Telemetry:          c.telemetry,
		Tracing:            c.tracing,
		Info:               hostInfo,
		CPU:                *c.cpu,
		MEM:                *c.mem,
		InsecureSkipVerify: c.insecureSkipVerify,
		CVEPath:            c.cvePath,
		CVEUploadDelay:     *c.cveUploadDelayMins,
	})
	core.CheckErr(err, "cannot start pilot")
	// start the pilot
	p.Start()
}

package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
)

type TelemCtl struct {
	logsChannels    []string
	metricsChannels []string
}

func NewTelemCtl() (*TelemCtl, error) {
	path := os.Getenv("PILOT_CTL_TELEM_PATH")
	if len(path) == 0 {
		log.Printf("missing PILOT_CTL_TELEM_PATH variable, reading telemetry data from default path at ./telemetry\n")
		path = "telemetry"
	} else {
		log.Printf("reading telemetry data from %s\n", path)
	}
	path, _ = filepath.Abs(path)
	logsPath := filepath.Join(path, "logs")
	metricsPath := filepath.Join(path, "metrics")

	logsChannel, err := ls(logsPath, true)
	if err != nil {
		return nil, err
	}
	metricsChannel, err := ls(metricsPath, true)
	if err != nil {
		return nil, err
	}
	return &TelemCtl{
		logsChannels:    logsChannel,
		metricsChannels: metricsChannel,
	}, nil
}

func (t *TelemCtl) Start(api *PilotCtl) error {
	for _, mChannel := range t.metricsChannels {
		p, _ := NewProcessor(mChannel, api, "metrics")
		p.Start()
	}
	for _, mChannel := range t.logsChannels {
		p, _ := NewProcessor(mChannel, api, "logs")
		p.Start()
	}
	return nil
}

// ls returns a list of file or folder names ordered by mod time
func ls(dirname string, isDir bool) ([]string, error) {
	// read entries from folder
	entries, err := os.ReadDir(dirname)
	if err != nil {
		return nil, fmt.Errorf("cannot read telemetry entries: %s", err)
	}
	// sort the file slice by ModTime()
	// ensuring the oldest file is processed first
	sort.Slice(entries, func(i, j int) bool {
		ii, _ := entries[i].Info()
		jj, _ := entries[j].Info()
		return ii.ModTime().UnixNano() <= jj.ModTime().UnixNano()
	})
	result := make([]string, 0)
	for _, entry := range entries {
		if isDir == entry.IsDir() {
			abs := filepath.Join(dirname, entry.Name())
			result = append(result, abs)
		}
	}
	return result, nil
}

/*
  pilot host controller
  © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
  Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
  Contributors to this project, hereby assign copyright in this code to the project,
  to be licensed under the same terms as the rest of the code.
*/

package core

import (
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Processor struct {
	path      string
	api       *PilotCtl
	telemType string
}

func NewProcessor(path string, api *PilotCtl, telemType string) (*Processor, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return &Processor{
		path:      absPath,
		api:       api,
		telemType: telemType,
	}, nil
}

func (p *Processor) Start() {
	go p.run()
}

func (p *Processor) run() {
	var count = 0
	// working loop
	for {
		files, err := getFiles(p.path)
		if err != nil {
			log.Fatalf("cannot read files in path '%s': %s", p.path, err)
		}
		// if there are no files
		if len(files) == 0 {
			// sleeps a bit
			time.Sleep(30 * time.Second)
			// then restart the loop
			continue
		}
		// picks the oldest file
		file := filepath.Join(p.path, files[0].Name())
		if err != nil {
			log.Fatalf("cannot figure absolute path for '%s': %s", files[0].Name(), err)
		}
		c, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("cannot read file '%s': %s", files[0].Name(), err)
		}
		result, err := p.api.SubmitTelemetry(filepath.Base(p.path), c, p.telemType)
		if err != nil {
			waitTime := backoffTime(count)
			log.Printf("ERROR: cannot submit %s: %s; waiting %v...\n", p.telemType, err, waitTime)
			count++
			time.Sleep(waitTime)
		} else if len(result.Error) > 0 {
			waitTime := backoffTime(count)
			log.Printf("ERROR: cannot submit %s: %s; waiting %v...\n", p.telemType, result.Error, waitTime)
			count++
			time.Sleep(waitTime)
		} else {
			count = 0
			if err = os.Remove(file); err != nil {
				log.Printf("ERROR: cannot delete %s file after submition: %s\n", p.telemType, err)
			}
		}
	}
}

func getFiles(path string) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		fmt.Errorf("cannot open path: %s", err)
	}
	dirs, err := f.ReadDir(-1)
	if err != nil {
		fmt.Errorf("cannot read path: %s", err)
	}
	// sort the directory entries by modification time
	sort.SliceStable(dirs, func(i, j int) bool {
		iInfo, _ := dirs[i].Info()
		jInfo, _ := dirs[j].Info()
		return iInfo.ModTime().Before(jInfo.ModTime())
		// return dirs[i].Name() < dirs[j].Name()
	})
	return dirs, err
}

// backoffTime exponentially increase backoff time until reaching 1 hour
func backoffTime(attempts int) time.Duration {
	var exponentialBackoffCeilingSecs int64 = 3600 // 1 hour
	delaySecs := int64(math.Floor((math.Pow(2, float64(attempts)) - 1) * 0.5))
	if delaySecs > exponentialBackoffCeilingSecs {
		delaySecs = exponentialBackoffCeilingSecs
	}
	return time.Duration(delaySecs) * time.Second
}

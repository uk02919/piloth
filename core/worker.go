/*
  pilot host controller
  © 2018-Present - SouthWinds Tech Ltd - www.southwinds.io
  Licensed under the Apache License, Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0
  Contributors to this project, hereby assign copyright in this code to the project,
  to be licensed under the same terms as the rest of the code.
*/

package core

import (
	"context"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"os"
	"path/filepath"
	"southwinds.dev/artisan/build"
	"southwinds.dev/artisan/merge"
	ctl "southwinds.dev/pilotctl/types"
	"strings"
	"time"
)

// workerStatus the status of the job execution worker
type workerStatus int

const (
	// the worker loop is ready to process jobs
	ready workerStatus = iota
	// the worker is started and processing a specific job
	busy
	// the worker has not yet started
	stopped
)

// Runnable the function that carries out the job
type Runnable func(data interface{}) (string, error)

// Worker manage execution of jobs on a single job at a time basis
type Worker struct {
	// what is the current status of the worker?
	status workerStatus
	// the context to manage the worker loop go routine
	ctx context.Context
	// the function to cancel the worker loop go routine
	cancel context.CancelFunc
	// the logic that carries the instructions to process each job
	run Runnable
	// syslog writer
	logs *syslog.Writer
}

// NewWorker create new worker using the specified runnable function
// Runnable: the function that processes each job
func NewWorker(run Runnable) *Worker {
	defer TRA(CE())
	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		status: stopped,
		ctx:    ctx,
		cancel: cancel,
		run:    run,
	}
}

// NewCmdRequestWorker create a new worker to process pilotctl command requests
func NewCmdRequestWorker() *Worker {
	defer TRA(CE())
	return NewWorker(run)
}

// Start starts the worker execution loop
func (w *Worker) Start() {
	defer TRA(CE())
	// if the worker is stopped then it can start
	if w.status == stopped {
		// changes the
		w.status = ready
		// launches the worker loop
		go func() {
			for {
				// peek the next job to be processed
				job, err := peekJob()
				// if it can't peek the next job, it must consider it as a failure as, if not, pilot could
				// continue to repeat the failure forever
				if err != nil {
					var errorMsg string
					// if it cannot read jobs
					if job == nil {
						ErrorLogger.Printf("cannot list jobs: %s", err)
					} else {
						// otherwise
						ErrorLogger.Printf("pilot could not read the next job to process from the local queue, possibly due to the file '%s' being corrupted: %s\n", job.file.Name(), err)
						// if a Job Id is known
						if job.cmd != nil && job.cmd.JobId > 0 {
							// send the error result for that job
							sendResult(job.cmd.JobId, "", errorMsg)
						} else {
							// if no Job could be found, remove the job from the local queue to avoid retrying over and over
							err = os.Remove(processDir(job.file.Name()))
							// and write to syslog
							if err == nil {
								SyslogWriter.Err(fmt.Sprintf("forcedly removed file %s from local queue, due to being unable to read it to avoid retrying\n", err))
							}
						}
					}
					// restart the loop to avoid retrying execution all over
					continue
				}
				// if the worker is ready to process a job and there are jobs waiting to start
				if w.status == ready && job != nil {
					// set the worker as busy
					w.status = busy
					InfoLogger.Printf("starting job %d, %s -> %s", job.cmd.JobId, job.cmd.Package, job.cmd.Function)
					// dump env vars if in debug mode
					w.debug(job.cmd.PrintEnv())
					// execute the job
					out, runErr := w.run(*job.cmd)
					if runErr != nil {
						InfoLogger.Printf("job %d, %s -> %s failed: %s", job.cmd.JobId, job.cmd.Package, job.cmd.Function, mask(runErr.Error(), job.cmd.User, job.cmd.Pwd))
					} else {
						InfoLogger.Printf("job %d, %s -> %s succeeded", job.cmd.JobId, job.cmd.Package, job.cmd.Function)
					}
					// check for an error
					var errorMsg string
					if runErr != nil {
						// build an error message masking registry credentials
						errorMsg = mask(runErr.Error(), job.cmd.User, job.cmd.Pwd)
					}
					// send the result to control
					sendResult(job.cmd.JobId, out, errorMsg)
					w.status = ready
				} else {
					// if no jobs wait for a little while until more jobs are available
					time.Sleep(5 * time.Second)
				}
			}
		}()
	} else {
		InfoLogger.Printf("worker has already started\n")
	}
}

// Stop stops the worker execution loop
func (w *Worker) Stop() {
	defer TRA(CE())
	w.cancel()
	w.status = stopped
}

func (w *Worker) Jobs() int {
	defer TRA(CE())
	dir := processDir("")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("cannot read directory: %s", err))
	}
	count := 0
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".job" {
			count = count + 1
		}
	}
	return count
}

// AddJob add a new job for processing to the worker
func (w *Worker) AddJob(job ctl.CmdInfo) {
	defer TRA(CE())
	err := addJob(Job{cmd: &job})
	if err != nil {
		ErrorLogger.Printf("cannot write job to process queue: %s\n", err)
	}
}

// Result returns the next
func (w *Worker) Result() (*ctl.JobResult, error) {
	defer TRA(CE())
	return peekJobResult()
}

func run(data interface{}) (string, error) {
	defer TRA(CE())
	// unbox the data
	cmd, ok := data.(ctl.CmdInfo)
	if !ok {
		return "", fmt.Errorf("Runnable data is not of the correct type\n")
	}

	// create the command to run
	var (
		artCmd = "exe"
	)
	// get the variables in the host environment
	hostEnv := merge.NewEnVarFromSlice(os.Environ())
	// get the variables in the command
	cmdEnv := merge.NewEnVarFromSlice(cmd.Env())
	// if the execution is containerised
	if cmd.Containerised {
		// use the exec command instead
		artCmd = fmt.Sprintf("%sc", artCmd)
	} else {
		// if not containerised add PATH to execution environment
		hostEnv.Merge(cmdEnv)
		cmdEnv = hostEnv
	}
	// if running in verbose mode
	if cmd.Verbose {
		// add ARTISAN_DEBUG to execution environment
		cmdEnv.Vars()["ARTISAN_DEBUG"] = "true"
	}
	// create the command statement to run
	cmdString := fmt.Sprintf("art %s -u %s:%s %s %s", artCmd, cmd.User, cmd.Pwd, cmd.Package, cmd.Function)
	// run and return
	return build.ExeAsync(cmdString, ".", cmdEnv, false)
}

func (w *Worker) debug(msg string, a ...interface{}) {
	defer TRA(CE())
	if len(os.Getenv("PILOT_DEBUG")) > 0 {
		DebugLogger.Printf(fmt.Sprintf("DEBUG: %s", msg), a...)
	}
}

func (w *Worker) RemoveResult(result *ctl.JobResult) error {
	defer TRA(CE())
	return removeJobResult(*result)
}

func mask(value, user, pwd string) string {
	defer TRA(CE())
	str := strings.Replace(value, user, "****", -1)
	str = strings.Replace(str, pwd, "xxxx", -1)
	return str
}

func sendResult(jobId int64, log, errorMsg string) {
	defer TRA(CE())
	result := &ctl.JobResult{
		JobId:   jobId,
		Success: len(errorMsg) == 0,
		Log:     log,
		Err:     errorMsg,
		Time:    time.Now(),
	}
	// add the last result to the submit queue
	err := submitJobResult(*result)
	// if the job result could not be saved
	if err != nil {
		// writes an error to Syslog, and do nothing
		// if the error cannot be serialised to file it could never reach the control plane
		// it means the control plane will not record the job as complete and the job will stay as started
		// with the syslog error sent to the control plane separately it should be possible to find the cause of the issue
		SyslogWriter.Err(fmt.Sprintf("cannot persist result for Job Id = %d: %s\n", jobId, err))
	}
	// remove job from the queue
	err = removeJob(jobId)
	// if the job could not be removed
	if err != nil {
		// writes an error to Syslog, and do nothing else
		SyslogWriter.Err(fmt.Sprintf("cannot remove Job Id = %d from local queue: %s, "+
			"this could lead to Pilot trying to run it over and over again. "+
			"Manual access to host is required to clean the job queue.\n", jobId, err))
	}
}

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/fsnotify/fsnotify.v1"
)

var (
	// shutdownSignals signals to watch for to terminate the operator gracefully
	// Using os.Interrupt is more portable across platforms instead of os.SIGINT
	shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
)

type Copier struct {
	// Our waitgroup is used to wait for the various go routines to finish
	// So that main() does not exit first, leaving the binary process running as a Zombie
	wg sync.WaitGroup
	// errorChan is used to propagate errors from the various go routines up to the main caller,
	// each function returns an error and sends it to the errorChan
	errorChan       chan error
	binaryFilePath  string
	execContext     context.Context
	execContextStop context.CancelFunc
}

func New(execContext context.Context, execContextStop context.CancelFunc, binaryFilePath string) *Copier {
	return &Copier{
		execContext:     execContext,
		execContextStop: execContextStop,
		errorChan:       make(chan error, 1),
		wg:              sync.WaitGroup{},
		binaryFilePath:  binaryFilePath,
	}
}

func main() {
	// Setup the logger using micro seconds for higher precision
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Verify the program has the expected number of arguments
	// We currently need only one which represents the binary file path the program will be running
	if len(os.Args) != 2 {
		log.Fatal("no binary path passed simply: ", os.Args)
	} else {
		log.Println("passed arguments", os.Args)
	}
	binaryFilePath := os.Args[1]
	binaryFileBase := filepath.Base(binaryFilePath)
	binaryDirPath := filepath.Dir(binaryFilePath)

	// Initialize the global context that manages the program lifecycle
	parentContext, parentContextStop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer parentContextStop()

	// Initialize the go routine context that manages the binary lifecycle
	// This is a child context that will also be cancelled when the main context is cancelled (the
	// program is stopped by Kubelet)
	execContext, execContextStop := context.WithCancel(parentContext)
	defer execContextStop()

	// Setup the directory watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Instantiate the copier
	copier := New(execContext, execContextStop, binaryFilePath)

	// Execute the goroutine watcher that watches for changes to the binary file's directory
	// When a change is detected (a REMOVE), the context is cancelled and the program exits
	// At this point, the program waits for a CREATE event to be received, which will run the binary
	// again.
	copier.wg.Add(1)
	go func(errorChan chan error) {
		defer copier.wg.Done()
		err := copier.directoryWatcher(parentContext, watcher)
		if err != nil {
			errorChan <- err
		}
	}(copier.errorChan)

	log.Printf("start watching for binary %q changes in %q\n", binaryFileBase, binaryDirPath)
	err = watcher.Add(binaryDirPath)
	if err != nil {
		log.Fatalf("failed to add watcher for binary %q in %q: %v", binaryFileBase, binaryDirPath, err)
	}

	// Add the watcher only if the binary exists otherwise we will get an error
	// So let's make sure it exists here
	_, err = os.Stat(binaryDirPath)
	if err != nil {
		log.Fatalf("failed to stat binary path %q: does not exist? %v", binaryDirPath, err)
	}
	log.Printf("binary directory path %q exists\n", binaryDirPath)

	// This is the initial start of the program where we must run the executor go routine to start
	// the binary
	copier.wg.Add(1)
	go func(errorChan chan error) {
		defer copier.wg.Done()
		err := copier.runCmd(execContext)
		if err != nil {
			execContextStop()
			errorChan <- err
		}
	}(copier.errorChan)

	// We block here, waiting for the main context to be cancelled by a signal
	for {
		select {
		case <-parentContext.Done():
			log.Println("shutdown signal received, waiting for the goroutines to finish")
			// Waiting for all the goroutines to finish
			copier.wg.Wait()
			log.Println("all go routines have finished, bye now!")
			os.Exit(0)

		case err := <-copier.errorChan:
			// Waiting for all the goroutines to finish
			copier.wg.Wait()
			if !strings.Contains(err.Error(), "context canceled") {
				log.Fatal(err)
			}
			os.Exit(1)
		}
	}
}

func (c *Copier) directoryWatcher(parentContext context.Context, watcher *fsnotify.Watcher) error {
	// When we exit, let's cancel the context to stop the program and other goroutines
	defer c.execContextStop()

	for {
		select {
		case event := <-watcher.Events:
			if event.Name == c.binaryFilePath {
				if event.Op&fsnotify.Create == fsnotify.Create {
					log.Println(event.String())

					// Run command
					err := c.runCmd(c.execContext)
					if err != nil {
						return err
					}

				} else if event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Println(event.String())
					c.execContextStop()
					c.execContext, c.execContextStop = context.WithCancel(parentContext)
					// There is nothing to wait for here since the process is already gone and
					// stopped with SIGKILL, so it returns immediately
				}
			}
		case err := <-watcher.Errors:
			return fmt.Errorf("failed to watch for changes: %v", err)

		case <-c.execContext.Done():
			return c.execContext.Err()

		case <-parentContext.Done():
			return parentContext.Err()
		}
	}
}

func (c *Copier) runCmd(ctx context.Context) error {
	// stdout represents the command's standard output
	var stdout io.ReadCloser

	// Discover args from file
	argFilePath := fmt.Sprintf("%s.args", c.binaryFilePath)
	argsByte, err := os.ReadFile(argFilePath)
	if err != nil {
		return fmt.Errorf("failed to read args file %q: %v", argFilePath, err)
	}

	// Build final args
	args := strings.Split(strings.TrimSuffix(string(argsByte), "\n"), " ")

	// There is a security risk since the context (ctx) is injected into the command execution. For instance
	// if that value is provided by an input controlled by an attacker.
	// Since ctx is a context it is not sanitized and can be used to inject code (via Value?), we
	// still have a potentially tainted input.
	cmd := exec.CommandContext(ctx, c.binaryFilePath, args...) //nolint:gosec

	log.Printf("starting command %q\n", cmd.Args)
	tries := 1000
	for tries > 0 {
		// Always re-hydrate the StdoutPipe otherwise it will remain the same as the previous command
		// that failed, thus empty.
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to setup stdout pipe for command %q: %v", cmd.Args, err)
		}

		// Merge both stdout and stderr
		cmd.Stderr = cmd.Stdout

		// Start the command!
		err = cmd.Start()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				log.Println("context has been cancelled, most likely due to a file change and/or multiple queued similar WRITE events")
				return nil
			} else if strings.Contains(err.Error(), "text file busy") {
				// Creating a file on Linux leads to a lot of WRITE events, we've seen around 140
				// events for a simple 'cp' command.
				// Since we are watching for CREATE event only (too avoid the storm of events and
				// context being renewed/cancelled), we can assume that the file is being created
				// BUT we can't assume that the file is being written to. For a small amount of time
				// ~100 milliseconds the file is being exclusively opened. Hence the retry.
				time.Sleep(time.Millisecond * 1)

				// We must close the stdout pipe, so that on retry it can be re-hydrated
				cmd.Stdout = nil

				continue
			} else {
				// Do not print the cmd and the args voluntarily, it will be too much output and
				// hard to see the error. The cmd and args are already logged above.
				return fmt.Errorf("failed to start command: %v", err)
			}
		}
		// Break out of the loop if no error
		break
	}

	pid := cmd.Process.Pid
	log.Printf("started child process %v\n", pid)

	// Wait for the process to finish, we don't need to block the context channel since cmd.Wait
	// does the same essentially.
	// Run this in since both the scanner and cmd.Wait() are blocking calls
	errChan := make(chan error)
	c.wg.Add(1)
	go func(errChan chan error) {
		// Stream stdout/stderr to stdout logs
		scanner := bufio.NewScanner(stdout)

		// This blocks until the process exits and stdout is exhausted
		for scanner.Scan() {
			m := scanner.Text()
			// use fmt here instead of log to avoid timestamp duplication. This also gives a more
			// "natural" output to the program
			fmt.Println(m)
		}

		err = cmd.Wait()
		if err != nil {
			// The process gets killed (with SIGKILL) when the context is cancelled
			// Is it ok from a ceph-csi point of view?
			if strings.Contains(err.Error(), "killed") {
				log.Printf("process %v was killed exiting go routine\n", pid)
			} else if strings.Contains(err.Error(), "interrupt") {
				log.Printf("process %v was interrupted exiting go routine\n", pid)
			} else if strings.Contains(err.Error(), "terminated") {
				log.Printf("process %v was terminated exiting go routine\n", pid)
			} else {
				errChan <- fmt.Errorf("cmd wait failed: %v", err)
			}
		}
		defer c.wg.Done()
	}(errChan)

	// Check if the cmd.Wait() failed
	if err := <-errChan; err != nil {
		return err
	}

	return nil
}

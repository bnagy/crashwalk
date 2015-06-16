// crashwalk is a support package for triaging crashfiles on unix systems. It
// concurrently walks a given root directory and instruments all matching
// files via an external debugger, passing the results to the caller over a
// channel.
package crashwalk

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/bnagy/crashwalk/crash"
	"github.com/boltdb/bolt"
	"github.com/gogo/protobuf/proto"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	//"path"
	"path/filepath"
	"strings"
	"sync"
)

// Summarize presents a nicely formatted, human readable summary of the crash.
// Quite a lot of analysis can be performed by combining this output with
// `awk`,`grep`, `sort`, `uniq -c` etc etc.
func Summarize(c crash.Crash) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "---CRASH SUMMARY---\n")
	fmt.Fprintf(&buf, "Filename: %s\n", c.OrigFilename)
	fmt.Fprintf(&buf, "SHA1: %s\n", hex.EncodeToString(c.SHA1))
	fmt.Fprintf(&buf, "Classification: %s\n", c.Classification)
	fmt.Fprintf(&buf, "Hash: %s\n", c.Hash)
	fmt.Fprintf(&buf, "Command: %s\n", strings.Join(c.Command, " "))
	fmt.Fprintf(&buf, "Faulting Frame:\n")
	ff := c.FaultingFrame
	fmt.Fprintf(&buf, "   %s @ 0x%.16x: in %s\n", ff.Symbol, ff.Address, ff.Module)
	fmt.Fprintf(&buf, "Disassembly:\n")
	for _, l := range c.Disassembly {
		if l.Address == c.FaultingInsn.Address {
			fmt.Fprintf(&buf, "=> 0x%.16x: %s\n", l.Address, l.Text)
			continue
		}
		fmt.Fprintf(&buf, "   0x%.16x: %s\n", l.Address, l.Text)
	}
	fmt.Fprintf(&buf, "Stack Head (%d entries):\n", len(c.Stack))
	for i, l := range c.Stack {
		fmt.Fprintf(&buf, "   %-25.25s @ 0x%.16x: in %s\n", l.Symbol, l.Address, l.Module)
		if i > 14 {
			break
		}
	}
	fmt.Fprintf(&buf, "Registers:")
	i := 0
	for _, reg := range c.Registers {
		if i%4 == 0 { // 4 registers per line
			fmt.Fprintf(&buf, "\n")
		}
		// OCD column alignent
		fmt.Fprintf(&buf, "%3.3s=0x%.16x ", reg.Name, reg.Value)
		i++
	}
	fmt.Fprintf(&buf, "\n")
	fmt.Fprintf(&buf, "Extra Data:\n")
	for _, l := range c.Extra {
		fmt.Fprintf(&buf, "   %s\n", l)
	}
	fmt.Fprintf(&buf, "---END SUMMARY---")
	return buf.String()
}

// Debugger is a simple interface that allows different debugger backends
// to be used by this package ( GDB, LLDB etc )
type Debugger interface {
	Run(command []string, memlimit, timeout int) (crash.Info, error)
}

// CrashwalkConfig is used to set the assorted configuration options for
// NewCrashwalk()
type CrashwalkConfig struct {
	FilterFunc  func(path string) error // Can be supplied by the user to filter non-crashes in a directory tree
	SeenDB      string                  // path to BoltDB (stores already processed crash info)
	Command     []string                // command to test crashfiles against
	Strict      bool                    // abort if any instrumentation calls error
	Debugger    Debugger                // A debugger that implements our interface
	Root        string                  // Root for the filepath.Walk
	Workers     int                     // number of workers to use
	IncludeSeen bool                    // include seen crashes from the DB to the output channel
	Auto        bool                    // Use the command from README.txt in AFL crash dirs
}

// Crashwalk is used to Run() walk instances, using the supplied config. Walks
// are not designed to be externally threadsafe, but can be configured to use
// multiple goroutines internally. Simultaneous calls to Run() from multiple
// goroutines will be serialised via an internal mutex.
type Crashwalk struct {
	root   string // root directory to walk for crashes
	config CrashwalkConfig
	db     *bolt.DB
	// for afl crash dirs containing a README.txt with metadata about the
	// command that was run to get this crash
	commandCache map[string][]string
	debugger     Debugger
	sync.Mutex
}

// Job is the basic unit of work that will be passed to the configured
// Debugger
type Job struct {
	Path    string
	Info    os.FileInfo
	Command []string
}

var CRASHBUCKET = []byte("crashes")

// NewCrashwalk creates a Crashwalk. Consult the information and warnings for
// that struct.
func NewCrashwalk(config CrashwalkConfig) (*Crashwalk, error) {

	cw := &Crashwalk{}
	cw.commandCache = make(map[string][]string)
	cw.debugger = config.Debugger //can't test this here

	fd, err := os.Open(config.Root)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open root %s: %s", config.Root, err)
	}
	fi, err := fd.Stat()
	if err != nil {
		return nil, fmt.Errorf("Couldn't stat root %s: %s", config.Root, err)
	}
	if !fi.Mode().IsDir() {
		return nil, fmt.Errorf("%s is not a directory.", config.Root)
	}
	cw.root = config.Root

	if !config.Auto {
		if len(config.Command) < 2 {
			return nil, fmt.Errorf(`Minimum command is ["path/to/binary", "@@"]`)
		}

		// smoke test the executable
		cmd := exec.Command(config.Command[0])
		err = cmd.Start()
		if err != nil {
			return nil, fmt.Errorf("Couldn't exec command '%s': %s", config.Command[0], err)
		}
		cmd.Process.Kill()

		// make sure there's at least one substitute marker
		sub := 0
		for _, elem := range config.Command {
			if elem == "@@" {
				sub++
			}
		}
		if sub == 0 {
			return nil, fmt.Errorf("No substitute markers ( @@ ) in supplied command?")
		}
	}

	// Smoke test the SeenDB. Run() will open and close this each time so that
	// we don't have to ask the user to call Close() on a Crashwalk.
	if config.SeenDB == "" {
		// will be created in .
		config.SeenDB = "crashwalk.db"
	}
	db, err := bolt.Open(config.SeenDB, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to open SeenDB (%s): %s", config.SeenDB, err)
	}
	err = db.Close()
	if err != nil {
		return nil, fmt.Errorf("Error closing SeenDB! %s", err)
	}

	// Initialize unset defaults
	if config.Workers == 0 {
		config.Workers = 1
	}
	if config.FilterFunc == nil {
		config.FilterFunc = func(p string) error { return nil }
	}

	// Good to go!
	cw.config = config
	return cw, nil

}

func process(cw *Crashwalk, jobs <-chan Job, crashes chan<- crash.Crash, wg *sync.WaitGroup) {

	defer wg.Done()
	hsh := sha1.New()
	cachedCE := &crash.Entry{}
	newCE := &crash.Entry{}

	for job := range jobs {

		var thisCmd []string
		// sub the filename into a copy of the template command
		if job.Command != nil {
			thisCmd = make([]string, len(job.Command))
			copy(thisCmd, job.Command)
		} else {
			thisCmd = make([]string, len(cw.config.Command))
			copy(thisCmd, cw.config.Command)
		}
		if len(thisCmd) < 2 {
			log.Fatalf("Internal Error: Job command too short: %v\n", job)
		}

		for i, s := range thisCmd {
			if s == "@@" {
				thisCmd[i] = job.Path
			}
		}
		f, err := os.Open(job.Path)
		if err != nil {
			log.Printf("Couldn't open file %s: %s", job.Path, err)
			if cw.config.Strict {
				log.Fatalf("[Instrumentation fault in strict mode]")
			}
			continue
		}

		// Read the crashfile into memory and calculate its SHA1 at the same
		// time
		tr := io.TeeReader(f, hsh)
		crashData, err := ioutil.ReadAll(tr)
		f.Close()
		if err != nil {
			log.Printf("Couldn't read file %s: %s", job.Path, err)
			if cw.config.Strict {
				log.Fatalf("[Instrumentation fault in strict mode]")
			}
			continue
		}
		hshCrash := hsh.Sum(nil)
		hsh.Reset()

		// Now calculate the tag sha1(path || cmd)
		hsh.Write([]byte(job.Path))
		hsh.Write([]byte(strings.Join(thisCmd, " ")))
		tag := hsh.Sum(nil)
		hsh.Reset()

		cachedCE.Reset()

		var cachedBytes []byte // marshaled crash.Entry
		// Optimistic View
		err = cw.db.View(func(tx *bolt.Tx) error {
			cachedBytes = tx.Bucket(CRASHBUCKET).Get(tag)
			return nil
		})
		if err != nil {
			log.Fatalf("FATAL: failed to read seenDB: %s", err)
		}

		// We found an old entry. Most likely we're about to skip.
		if cachedBytes != nil {
			err := proto.Unmarshal(cachedBytes, cachedCE)
			if err != nil {
				log.Fatalf("Error unmarshalling stored CrashEntry: %s", err)
			}
			if bytes.Equal(cachedCE.SHA1, hshCrash) {
				// Same command, path ( via tag ) and same contents. Seen it.
				if cw.config.IncludeSeen {
					crashes <- crash.Crash{Entry: *cachedCE, Data: crashData}
				}
				continue
			}
		}

		// If we're here, either:
		//  - we didn't find an entry
		//  - the crash contents changed
		//  - we lost a View() race ( should be impossible in this architecture )

		// run it under the debugger
		info, err := cw.debugger.Run(thisCmd, -1, -1)
		if err != nil {
			log.Printf("\n---\n")
			fmt.Fprintf(os.Stderr, "Command: %s\n", strings.Join(thisCmd, " "))
			fmt.Fprintf(os.Stderr, "File: %s\n", job.Path)
			fmt.Fprintf(os.Stderr, "Error: %s\n---\n", err)
			if cw.config.Strict {
				log.Fatalf("[Instrumentation fault in strict mode]")
			}
			continue
		}

		newCE.Reset()
		newCE.Info = info
		newCE.Timestamp = job.Info.ModTime().Unix()
		newCE.OrigFilename = job.Path
		newCE.SHA1 = hshCrash
		newCE.Command = thisCmd
		newBytes, err := proto.Marshal(newCE)
		if err != nil {
			log.Fatalf("Failed to marshal crash.Entry: %s", err)
		}

		// serialised Update ( threadsafe, but slower )
		err = cw.db.Update(func(tx *bolt.Tx) error {
			// check once more in case we're racing and someone else created
			// it first
			cachedBytes = tx.Bucket(CRASHBUCKET).Get(tag)
			if cachedBytes != nil {
				log.Printf("BUG: We raced trying to read a tag? Recovered.")
				// same checks as above
				ce := &crash.Entry{}
				err := proto.Unmarshal(cachedBytes, ce)
				if err != nil {
					return fmt.Errorf("Failed to unmarshal CrashEntry: %s", err)
				}
				if bytes.Equal(ce.SHA1, hshCrash) {
					// Same command, path ( matching tag ) and same contents.
					// Seen it, don't update.
					return nil
				}
				// Different contents. Cool, we do the update anyway.
			}

			if err := tx.Bucket(CRASHBUCKET).Put(tag, newBytes); err != nil {
				return fmt.Errorf("Failed to store token: %s", err)
			}

			return nil
		})

		if err != nil {
			log.Fatalf("FATAL: failed to write seenDB: %s", err)
		}

		// send it!
		crashes <- crash.Crash{Entry: *newCE, Data: crashData}
	}
	// All done. wg will be closed by defer.
}

func parseReadmeCommand(f *os.File) (cmd []string) {
	// Command line used to find this crash:
	//
	// ./afl-fuzz -i /Users/ben/src/afl-1.36b/testcases/others/pdf/ -o /Volumes/ramdisk/popplFIXED -d -x /Users/ben/scratch/pdfextras -T pdftoppm FIXED -- /Users/ben/src/poppler-0.31.0/utils/pdftoppm -aa no -r 36 -png @@
	//
	// If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
	// memory limit. The limit used for this fuzzing session was 50.0 MB.

	cmd = []string{}

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	if scanner.Text() != "Command line used to find this crash:" {
		return
	}

	scanner.Scan() // blank line
	scanner.Scan()
	subst := strings.SplitN(scanner.Text(), " -- ", 2)
	if len(subst) != 2 {
		return
	}
	cmd = strings.Split(subst[1], " ")
	return
}

// Run will take one run through the crashes, (optionally) skipping any we
// have seen, and push all the results down to the end-user on the crash
// channel. It closes its own resources once the run is finished. Multiple
// calls to Run() will be serialised via an internal mutex, however this is
// not recommended. The Workers setting in CrashwalkConfig allows the Run to
// use multiple goroutines, (and multiple cores, if GOMAXPROCS is set
// correctly)
func (cw *Crashwalk) Run() <-chan crash.Crash {

	cw.Lock()

	crashes := make(chan crash.Crash)

	db, err := bolt.Open(cw.config.SeenDB, 0600, nil)
	if err != nil {
		log.Fatalf("Failed to open SeenDB (%s): %s", cw.config.SeenDB, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists(CRASHBUCKET)
		return nil
	})
	if err != nil {
		log.Fatalf("Error creating bucket! %s", err)
	}
	cw.db = db

	wg := &sync.WaitGroup{}
	jobs := make(chan Job)

	// start debugger runners
	for i := 0; i < cw.config.Workers; i++ {
		wg.Add(1)
		go process(cw, jobs, crashes, wg)
	}

	// kick off filepath walk
	go func() {

		filepath.Walk(
			cw.root,
			func(path string, info os.FileInfo, err error) error {

				if err != nil {
					return nil
				}

				if e := cw.config.FilterFunc(path); e != nil {
					// This allows the caller to return the special filepath.SkipDir
					// error if they feel like it.
					if e == filepath.SkipDir {
						return e
					}
					return nil
				}

				if cw.config.Auto {
					dn, _ := filepath.Split(path)

					if cached := cw.commandCache[dn]; cached == nil {
						// First hit for this dir
						readme, err := os.Open(filepath.Join(dn, "README.txt"))
						if err != nil {
							// persistent "don't bother"
							cw.commandCache[dn] = []string{}
						} else {
							// try to get command
							cw.commandCache[dn] = parseReadmeCommand(readme)
						}
					}

					if cached := cw.commandCache[dn]; len(cached) > 0 {
						// There's an entry and it's not an empty slice
						jobs <- Job{Path: path, Info: info, Command: cached}
						return nil
					}

					if cw.config.Command == nil || len(cw.config.Command) < 2 {
						if !cw.config.Strict {
							return nil
						}
						log.Fatalf("STRICT MODE + AUTO: Unable to parse README.txt command and no default given.")
					}
				}

				jobs <- Job{Path: path, Info: info}
				return nil
			})

		close(jobs)

	}()

	// spawn a goroutine to wait for the runners then clean up
	go func() {
		wg.Wait()
		db.Close()
		close(crashes)
		// unlock here and not in a defer, because we return the output
		// channel immediately but need to hold the lock until the work is
		// finished.
		cw.Unlock()
	}()

	return crashes

}

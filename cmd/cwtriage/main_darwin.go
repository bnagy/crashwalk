package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/bnagy/crashwalk"
	"github.com/bnagy/crashwalk/gdb"
	"github.com/bnagy/francis"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

var (
	crashRoot     = flag.String("root", "", "Root directory to look for crashes")
	matchPattern  = flag.String("match", "", "Match pattern for files ( go regex syntax )")
	ignorePattern = flag.String("ignore", "", "Directory skip pattern ( go regex syntax )")
	flagWorkers   = flag.Int("workers", 1, "Number of concurrent workers")
	includeSeen   = flag.Bool("seen", false, "Include seen results from the DB in the output")
	flagDebugger  = flag.String("engine", "gdb", "Debugging engine to use: [gdb lldb]")
	flagAfl       = flag.Bool("afl", false, "Prefer the AFL recorded crashing command, if present")
	flagStrict    = flag.Bool("strict", false, "Abort the whole run if any crashes fail to repro")
	flagMem       = flag.Int("mem", -1, "Memory limit for target processes (MB)")
	flagTimeout   = flag.Int("t", 60, "Timeout for target processes (secs)")
	flagEvery     = flag.Int("every", -1, "Run every n seconds")
	flagOutput    = flag.String("output", "text", "Output format to use: [json pb text]")
	flagTidy      = flag.Bool("tidy", false, "Move crashes that error under Run() to a tidy dir")
	flagFile      = flag.String("f", "", "Template filename to use while running crash")
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"\n  %s runs crashfiles with instrumentation and outputs results in various formats\n",
			path.Base(os.Args[0]),
		)
		fmt.Fprintf(
			os.Stderr,
			"  Usage: %s -root /path/to/afl-dir [-match pattern] -- /path/to/target -in @@ -out whatever\n",
			path.Base(os.Args[0]),
		)
		fmt.Fprintf(os.Stderr, "  ( @@ will be substituted for each crashfile )\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")

	}

	flag.Parse()
	if *crashRoot == "" {
		fmt.Fprintf(os.Stderr, "  FATAL: No root directory given\n")
		flag.Usage()
		os.Exit(1)
	}

	if *matchPattern == "" {
		if *flagAfl {
			*matchPattern = "crashes.*id:"
		} else {
			*matchPattern = ".*"
		}
	}
	crashRegex, err := regexp.Compile(fmt.Sprintf("%s", *matchPattern))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FATAL: %s\n", err)
		flag.Usage()
		os.Exit(1)
	}

	var skipRegex *regexp.Regexp
	if *ignorePattern != "" {
		skipRegex, err = regexp.Compile(fmt.Sprintf("%s", *ignorePattern))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FATAL: %s\n", err)
			flag.Usage()
			os.Exit(1)
		}
	}
	// If the user hasn't supplied a skip regex AND they want AFL auto mode,
	// we supply a useful one.
	if skipRegex == nil && *flagAfl {
		// I, personally, name sync dirs from other fuzzers something.sync
		// This skips those, which might trip you up, although it seems
		// unlikely. The other directories it skips are the queue and hang
		// dirs, which means the walker doesn't need to visit each file in
		// those directories (quite a big speedup).
		// UPDATE: we also skip our own .cwtidy directory, if present.
		skipRegex = regexp.MustCompile(".sync/|queue/|hang/|.cwtidy/")
	} else {
		// when people use manual mode via -match is surprises them when the
		// .cwtidy directory is not ignored, so it makes sense to do that by
		// default (#6). They can always unignore it by manually specifying
		// something else with -ignore if they want to re-try tidied
		// crashfiles.
		skipRegex = regexp.MustCompile(".cwtidy/")
	}

	skipErr := errors.New("no match")
	filter := func(path string) error {
		if skipRegex != nil && skipRegex.MatchString(path) {
			// Whole directory will be exited. Note that the directory itself
			// (without the /) will first be evaluated as a file. This is why
			// .cwtidy was erroneously passing, since it matched crash.*id but not
			// .cwtidy/ (no trailing slash)
			return filepath.SkipDir
		}
		if crashRegex.MatchString(path) {
			return nil
		}
		return skipErr
	}

	command := flag.Args()
	if len(command) < 2 && !*flagAfl {
		fmt.Fprintf(os.Stderr, "  FATAL: Minimum target command is: /path/to/target @@\n")
		flag.Usage()
		os.Exit(1)
	}

	runtime.GOMAXPROCS(*flagWorkers)

	var debugger crashwalk.Debugger
	switch *flagDebugger {
	default:
		fmt.Fprintf(os.Stderr, "  FATAL: Unknown debugging engine %s, only [gdb lldb]\n", *flagDebugger)
		flag.Usage()
		os.Exit(1)
	case "gdb":
		debugger = &gdb.Engine{}
	case "lldb":
		debugger = &francis.Engine{}
	}

	switch *flagOutput {
	default:
		fmt.Fprintf(os.Stderr, "  FATAL: Unknown output format %s, only [json pb text]\n", *flagOutput)
		flag.Usage()
		os.Exit(1)
	case "pb":
	case "json":
	case "text":
	}

	// If the user provided a template filename, create or check the base path
	// before we go any further.
	if *flagFile != "" {

		// Is the directory OK ( create if it doesn't exist )
		base, _ := path.Split(*flagFile)
		err := os.MkdirAll(base, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FATAL: failed sanity check for -f: %s\n", err)
			flag.Usage()
			os.Exit(1)
		}

		// Can we create files there?
		fd, err := os.Create(path.Join(base, "cwtriage.test"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FATAL: failed sanity check for -f: %s\n", err)
			flag.Usage()
			os.Exit(1)
		}

		// Clean up.
		fd.Close()
		err = os.Remove(path.Join(base, "cwtriage.test"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FATAL: failed sanity check for -f: %s\n", err)
			flag.Usage()
			os.Exit(1)
		}
	}

	config := crashwalk.CrashwalkConfig{
		Command:     command,
		Strict:      *flagStrict,
		Debugger:    debugger,
		Root:        *crashRoot,
		FilterFunc:  filter,
		Workers:     *flagWorkers,
		IncludeSeen: *includeSeen,
		Afl:         *flagAfl,
		MemoryLimit: *flagMem,
		Timeout:     *flagTimeout,
		Tidy:        *flagTidy,
		File:        *flagFile,
	}

	cw, err := crashwalk.NewCrashwalk(config)
	if err != nil {
		log.Fatalf("Unable to create Crashwalk: %s", err)
	}

	var ticker <-chan (time.Time)
	if *flagEvery > 0 {
		ticker = time.Tick(time.Duration(*flagEvery) * time.Second)
	}

	for {

		ch := cw.Run()
		for crash := range ch {
			switch *flagOutput {
			case "text":
				fmt.Println(crashwalk.Summarize(crash))
			case "pb":
				fmt.Println(crash.String())
			case "json":
				j, err := json.Marshal(crash)
				if err != nil {
					log.Fatalf("[BUG]: Failed to marshal crash as JSON: %s", err)
				}
				fmt.Println(string(j))
			default:
				log.Fatalf("[BUG] Unknown output format %q, how did we pass startup checks?", *flagOutput)
			}
		}

		if ticker == nil {
			break
		}
		<-ticker
	}

}

package main

import (
	"flag"
	"fmt"
	"github.com/bnagy/crashwalk"
	"github.com/bnagy/crashwalk/gdb"
	"github.com/bnagy/francis"
	"log"
	"os"
	"path"
	"regexp"
	"runtime"
	"time"
)

var (
	crashRoot    *string = flag.String("root", "", "Root directory to look for crashes")
	matchPattern *string = flag.String("match", "", "Match pattern for files ( go regex syntax )")
	flagWorkers  *int    = flag.Int("workers", 1, "Number of concurrent workers")
	includeSeen  *bool   = flag.Bool("seen", false, "Include seen results from the DB in the output")
	flagDebugger *string = flag.String("engine", "gdb", "Debugging engine to use: [gdb lldb]")
	flagAuto     *bool   = flag.Bool("auto", false, "Prefer the AFL recorded crashing command, if present")
	flagEvery    *int    = flag.Int("every", -1, "Run every n seconds")
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"  Usage: %s -root /path/to/afl-dir [-match pattern] -- /path/to/target -in @@ -out whatever\n",
			path.Base(os.Args[0]),
		)
		fmt.Fprintf(os.Stderr, "  ( @@ will be substituted for each crashfile )\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if *crashRoot == "" {
		fmt.Fprintf(os.Stderr, "  FATAL: No root directory given\n")
		flag.Usage()
		os.Exit(1)
	}

	if *matchPattern == "" {
		if *flagAuto {
			*matchPattern = "crashes.*id"
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

	filter := func(path string) error {
		if crashRegex.MatchString(path) {
			return nil
		}
		return fmt.Errorf("no match")
	}

	command := flag.Args()
	if len(command) < 2 && !*flagAuto {
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

	config := crashwalk.CrashwalkConfig{
		Command:     command,
		Strict:      true,
		Debugger:    debugger,
		Root:        *crashRoot,
		FilterFunc:  filter,
		Workers:     *flagWorkers,
		IncludeSeen: *includeSeen,
		Auto:        *flagAuto,
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
			fmt.Println(crashwalk.Summarize(crash))
		}

		if ticker == nil {
			break
		}
		<-ticker
	}

}

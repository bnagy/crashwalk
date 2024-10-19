package main

import (
	"flag"
	"fmt"
	"crashwalk/pkg/crashwalk"
	"crashwalk/pkg/crash"
	"github.com/boltdb/bolt"
	"github.com/gogo/protobuf/proto"
	"log"
	"os"
	"path"
)

type summary struct {
	detail string
	count  int
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"\n  %s summarizes crashes in the given crashwalk databases by major.minor hash\n",
			path.Base(os.Args[0]),
		)
		fmt.Fprintf(
			os.Stderr,
			"  Usage: %s /path/to/crashwalk.db [db db ...]\n\n",
			path.Base(os.Args[0]),
		)
	}

	flag.Parse()
	for _, arg := range flag.Args() {

		db, err := bolt.Open(arg, 0600, nil)
		if err != nil {
			log.Fatalf("failed to open DB (%s): %s", arg, err)
		}
		defer db.Close()

		db.View(func(tx *bolt.Tx) error {

			tx.ForEach(func(name []byte, b *bolt.Bucket) error {

				summaries := make(map[string]summary)
				b.ForEach(func(k, v []byte) error {
					ce := &crash.Entry{}
					err := proto.Unmarshal(v, ce)
					if err != nil {
						return err
					}
					s, ok := summaries[ce.Hash]
					if !ok {
						s = summary{detail: crashwalk.Summarize(crash.Crash{Entry: *ce})}
					}
					s.count++
					summaries[ce.Hash] = s
					return nil
				})

				for k, v := range summaries {
					fmt.Printf("(1 of %v) - Hash: %v\n", v.count, k)
					fmt.Println(v.detail)
				}
				return nil

			})
			return nil
		})
	}
}

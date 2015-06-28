package main

import (
	"flag"
	"fmt"
	"github.com/bnagy/crashwalk/crash"
	"github.com/boltdb/bolt"
	"github.com/gogo/protobuf/proto"
	"log"
	"os"
	"path"
)

var (
	dbFlag = flag.String("db", "crashwalk.db", "crashwalk DB to search")
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"\n  %s finds all filenames in a crashwalk.db with the given major.minor hashes\n",
			path.Base(os.Args[0]),
		)
		fmt.Fprintf(
			os.Stderr,
			"  Usage: %s -db /path/to/crashwalk.db hash [hash hash ...]\n\n",
			path.Base(os.Args[0]),
		)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
	}

	flag.Parse()

	db, err := bolt.Open(*dbFlag, 0600, nil)
	if err != nil {
		log.Fatalf("failed to open DB (%s): %s", *dbFlag, err)
	}
	defer db.Close()

	for _, arg := range flag.Args() {

		db.View(func(tx *bolt.Tx) error {

			tx.ForEach(func(name []byte, b *bolt.Bucket) error {

				b.ForEach(func(k, v []byte) error {
					ce := &crash.Entry{}
					err := proto.Unmarshal(v, ce)
					if err != nil {
						log.Fatalf(err.Error())
					}
					if ce.Hash == arg {
						fmt.Println(ce.OrigFilename)
					}
					return nil
				})

				return nil

			})
			return nil
		})
	}
}

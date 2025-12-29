package main

import (
	"flag"
	"fmt"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		return
	}

	processCertificate()
}

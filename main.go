package main

import (
	"flag"
	"fmt"
	"runtime"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	processCertificate()
}

package main

import (
	"flag"
	"fmt"
	"runtime"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	bikeid := flag.String("bikeid", "", "Bike ID to verify (optional)")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	if *cert == "" {
		fmt.Println("Error: -cert flag is required")
		fmt.Println("Usage: vanmoof-certificates -cert <base64_cert> [-pubkey <base64_pubkey>] [-bikeid <bike_id>]")
		return
	}

	processCertificate(*cert, *pubkey, *bikeid)
}

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	bikeid := flag.String("bikeid", "", "Bike ID to verify (optional)")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	if *cert == "" {
		// Ask for credentials and fetch certificate
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter VanMoof email: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		fmt.Print("Enter VanMoof password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		if err := getCert(email, password, *debug); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		return
	}

	processCertificate(*cert, *pubkey, *bikeid)
}

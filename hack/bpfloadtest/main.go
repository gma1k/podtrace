package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println("rlimit:", err)
	}
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		fmt.Println("SPEC FAIL:", err)
		os.Exit(1)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Printf("VERIFIER FAIL: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()
	fmt.Printf("VERIFIER OK: %d programs loaded\n", len(coll.Programs))
}

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG, $BPF_CFLAGS and $BPF_HEADERS are set by the Makefile.
//
//go:generate /root/go/bin/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel,bpfeb bpf execve_counter.bpf.c -- -I $BPF_HEADERS
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// init the map element
	var key [64]byte
	copy(key[:], []byte("execve_counter"))
	var val int64 = 0
	if err := objs.bpfMaps.ExecveCounter.Put(key, val); err != nil {
		log.Fatalf("init map key error: %s", err)
	}

	// attach to xxx
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.BpfProg, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := objs.bpfMaps.ExecveCounter.Lookup(key, &val); err != nil {
				log.Fatalf("reading map error: %s", err)
			}
			log.Printf("execve_counter: %d\n", val)

		case <-stopper:
			// Wait for a signal and close the perf reader,
			// which will interrupt rd.Read() and make the program exit.
			log.Println("Received signal, exiting program..")
			return
		}
	}
}

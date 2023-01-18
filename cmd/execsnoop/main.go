package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf execsnoop.bpf.c -- -I../../headers

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

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

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attach the BPF program to sys_enter_execve tracepoint: %s", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSyscallsSysExitExecve, nil)
	if err != nil {
		log.Fatalf("attach the BPF program to sys_enter_execve tracepoint: %s", err)
	}
	defer tpExit.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Printf("Listening for events..")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}
			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			var event event
			if err := binary.Read(
				bytes.NewBuffer(record.RawSample),
				binary.LittleEndian,
				&event,
			); err != nil {
				log.Printf("parsing %d bytes perf event: %s", len(record.RawSample), err)
				fmt.Println(hex.Dump(record.RawSample[:]))
				continue
			}

			log.Printf("%+v\n", event)
		}
	}()
	<-ctx.Done()
	log.Println("Received signal, exiting program...")
}

// event represents a perf event sent to user space from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
// The variable length args field is omitted here and decoded manually.
type event struct {
	// PID is the process ID.
	PID int32
	// PPID is the process ID of the parent of this process.
	PPID int32
	// UID is the process user ID, e.g., 1000.
	UID uint32
	// Retval is the return value of the execve().
	Retval int32
	// ArgsCount is a number of arguments.
	ArgsCount int32
	// ArgSize is a size of arguments in bytes.
	ArgsSize uint32
	// Comm is the parent process/command name, e.g., bash.
	Comm [16]byte
}

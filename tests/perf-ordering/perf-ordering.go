package main

import (
	bpflib "github.com/iovisor/gobpf/elf"

	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"time"
)

/*
#include "gettimeofday-bpf.h"
*/
import "C"

type eventT struct {
	Timestamp uint64 // Monotonic timestamp
	CPU       uint64 // CPU index
	Pid       uint64 // Process ID, who triggered the event
	Comm      string // The process command (as in /proc/$pid/comm)
}

func pmTimestamp(data *[]byte) uint64 {
	ts := (*uint64)(unsafe.Pointer(&(*data)[0]))
	return *ts
}

func eventToGo(data *[]byte) (ret eventT) {
	eventC := (*C.struct_gettimeofday_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.CPU = uint64(eventC.cpu)
	ret.Pid = uint64(eventC.pid & 0xffffffff)
	ret.Comm = C.GoString(&eventC.comm[0])

	return
}

var lastTimestamp uint64
var lastCPU uint64

func nowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}
func gettimeofdayCb(e eventT) {
	now := nowNanoseconds()
	fmt.Printf("\t\t%v cpu#%d %v %s (now=%v diff=%v) [lastTimestamp=%v]\n",
		e.Timestamp, e.CPU, e.Pid, e.Comm, now, now-e.Timestamp, lastTimestamp)

	if lastTimestamp > e.Timestamp {
		fmt.Printf("\t\tERROR: late event! %v[cpu#%d] > %v[cpu#%d]\n", lastTimestamp, lastCPU, e.Timestamp, e.CPU)
		time.Sleep(time.Hour)
		os.Exit(1)
	}

	lastTimestamp = e.Timestamp
	lastCPU = e.CPU
}

func main() {
	fmt.Printf("Hello.\n")

	buf, err := ioutil.ReadFile("ebpf/gettimeofday-bpf.o")
	if err != nil {
		fmt.Printf("cannot open file: %v\n", err)
		os.Exit(1)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		fmt.Printf("BPF not supported\n")
		os.Exit(1)
	}

	err = m.Load()
	if err != nil {
		fmt.Printf("cannot load: %v\n", err)
		os.Exit(1)
	}

	err = m.Load()
	if err != nil {
		fmt.Printf("cannot load: %v\n", err)
		os.Exit(1)
	}

	err = m.EnableKprobes(16)
	if err != nil {
		fmt.Printf("cannot enable kprobe: %v\n", err)
		os.Exit(1)
	}

	eventChan := make(chan []byte)

	pm, err := bpflib.InitPerfMap(m, "gettimeofday_event", eventChan)
	if err != nil {
		fmt.Printf("cannot init perf map: %v\n", err)
		os.Exit(1)
	}
	pm.SetTimestampFunc(pmTimestamp)

	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			case data := <-eventChan:
				gettimeofdayCb(eventToGo(&data))
			}
		}
	}()

	pm.PollStart()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
}

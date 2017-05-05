// +build linux

// Copyright 2016 Cilium Project
// Copyright 2016 Sylvain Afchain
// Copyright 2016 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elf

import (
	"fmt"
	"os"
	"sort"
	"syscall"
	"unsafe"
	//"math/rand"
	//"time"
)

/*
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <linux/perf_event.h>
#include <poll.h>

// from https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	void *buf;
	int buf_len;
};

static int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}
*/
import "C"

type PerfMap struct {
	name         string
	program      *Module
	receiverChan chan []byte
	pollStop     chan bool
	timestamp    func(*[]byte) uint64
}

// Matching 'struct perf_event_sample in kernel sources
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

func InitPerfMap(b *Module, mapName string, receiverChan chan []byte) (*PerfMap, error) {
	_, ok := b.maps[mapName]
	if !ok {
		return nil, fmt.Errorf("no map with name %s", mapName)
	}
	// Maps are initialized in b.Load(), nothing to do here
	return &PerfMap{
		name:         mapName,
		program:      b,
		receiverChan: receiverChan,
		pollStop:     make(chan bool),
	}, nil
}

// SetTimestampFunc registers a timestamp callback that will be used to
// reorder the perf events chronologically.
//
// If not set, the order of events sent through receiverChan is not guaranteed.
//
// Typically, the ebpf program will use bpf_ktime_get_ns() to get a timestamp
// and store it in the perf event. The perf event struct is opaque to this
// package, hence the need for a callback.
func (pm *PerfMap) SetTimestampFunc(timestamp func(*[]byte) uint64) {
	pm.timestamp = timestamp
}

func (pm *PerfMap) PollStart() {
	arr := make([][]byte, 0)
	incoming := OrderedBytesArray{timestamp: pm.timestamp, bytesArray: &arr}

	m, ok := pm.program.maps[pm.name]
	if !ok {
		// should not happen or only when pm.program is
		// suddenly changed
		panic(fmt.Sprintf("cannot find map %q", pm.name))
	}

	go func() {
		cpuCount := len(m.pmuFDs)
		pageSize := os.Getpagesize()
		pageCount := 8
		state := C.struct_read_state{}

		for {
			select {
			case <-pm.pollStop:
				break
			default:
				perfEventPoll(m.pmuFDs)
			}

			for {
				var harvestCount C.int
				beforeHarvest := nowNanoseconds() - 2000952751
				fmt.Printf("%v -- beforeHarvest\n", beforeHarvest)
				for cpu := 0; cpu < cpuCount; cpu++ {
					for {
						var sample *PerfEventSample
						var lost *PerfEventLost

						ok := C.perf_event_read(C.int(pageCount), C.int(pageSize),
							unsafe.Pointer(&state), unsafe.Pointer(m.headers[cpu]),
							unsafe.Pointer(&sample), unsafe.Pointer(&lost))

						switch ok {
						case 0:
							break // nothing to read
						case C.PERF_RECORD_SAMPLE:
							size := sample.Size - 4
							b := C.GoBytes(unsafe.Pointer(&sample.data), C.int(size))
							b2 := make([]byte, C.int(size))
							copy(b2, b)
							*incoming.bytesArray = append(*incoming.bytesArray, b2)
							harvestCount++
							if pm.timestamp == nil {
								continue
							}
							if incoming.timestamp(&b2) > beforeHarvest {
								// see comment below
								fmt.Printf("%v > %v // break from cpu#%d (count=%d)\n", incoming.timestamp(&b2), beforeHarvest, cpu, harvestCount)
								break
							} else {
								continue
							}
						case C.PERF_RECORD_LOST:
						default:
							// TODO: handle lost/unknown events?
						}
						break
					}
				}

				if incoming.timestamp != nil {
					fmt.Printf("%v ++ sorting %d items\n", beforeHarvest, incoming.Len())
					sort.Sort(incoming)
					if incoming.Len() >= 2 {
						v1 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[0][0]))
						v2 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[1][0]))
						fmt.Printf("%v < %v [less=%v] (just after the SORT), Len=%d\n", v1, v2, v1 < v2, incoming.Len())
					}
				}
				for incoming.Len() > 0 {
					if incoming.timestamp != nil && incoming.timestamp(&(*incoming.bytesArray)[0]) > beforeHarvest {
						// This record has been sent after the beginning of the harvest. Stop
						// processing here to keep the order. "incoming" is sorted, so the next
						// elements also must not be processed now.
						fmt.Printf("break len=%d\n", incoming.Len())
						break
					}
					copyOverTheChannel := make([]byte, len((*incoming.bytesArray)[0]))
					copy(copyOverTheChannel, (*incoming.bytesArray)[0])
					pm.receiverChan <- copyOverTheChannel

					if incoming.Len() >= 2 {
						v1 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[0][0]))
						v2 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[1][0]))
						fmt.Printf("%v < %v [less=%v] (after sending over channel) Len=%d\n", v1, v2, v1 < v2, incoming.Len())
					} else {
						v1 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[0][0]))
						fmt.Printf("%v < ?? [less=X] (after sending over channel) Len=%d\n", v1, incoming.Len())
					}

					// remove first element
					*incoming.bytesArray = (*incoming.bytesArray)[1:]

					if incoming.Len() >= 2 {
						v1 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[0][0]))
						v2 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[1][0]))
						fmt.Printf("%v < %v [less=%v] (after removing first elem) Len=%d\n", v1, v2, v1 < v2, incoming.Len())
					} else if incoming.Len() >= 1 {
						v1 := *(*C.uint64_t)(unsafe.Pointer(&(*incoming.bytesArray)[0][0]))
						fmt.Printf("%v < ??[less=x] (after removing first elem) Len=%d\n", v1, incoming.Len())
					}
				}
				if harvestCount == 0 && len(*incoming.bytesArray) == 0 {
					break
				}
				//if rand.Intn(10) == 1 {
				//	fmt.Printf("Sleeping\n")
				//	time.Sleep(time.Millisecond * 20)
				//}
			}
		}
	}()
}

func (pm *PerfMap) PollStop() {
	pm.pollStop <- true
}

func perfEventPoll(fds []C.int) error {
	var pfds []C.struct_pollfd

	for i, _ := range fds {
		var pfd C.struct_pollfd

		pfd.fd = fds[i]
		pfd.events = C.POLLIN

		pfds = append(pfds, pfd)
	}
	_, err := C.poll(&pfds[0], C.nfds_t(len(fds)), 500)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

// Assume the timestamp is at the beginning of the user struct
type OrderedBytesArray struct {
	bytesArray *[][]byte
	timestamp  func(*[]byte) uint64
}

func (a OrderedBytesArray) Len() int {
	return len(*(a.bytesArray))
}

func (a OrderedBytesArray) Swap(i, j int) {
	(*a.bytesArray)[i], (*a.bytesArray)[j] = (*a.bytesArray)[j], (*a.bytesArray)[i]
}

func (a OrderedBytesArray) Less(i, j int) bool {
	return *(*C.uint64_t)(unsafe.Pointer(&(*a.bytesArray)[i][0])) < *(*C.uint64_t)(unsafe.Pointer(&(*a.bytesArray)[j][0]))
}

// Matching 'struct perf_event_header in <linux/perf_event.h>
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// Matching 'struct perf_event_lost in kernel sources
type PerfEventLost struct {
	PerfEventHeader
	Id   uint64
	Lost uint64
}

// nowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
func nowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}

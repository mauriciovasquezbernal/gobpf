package main

import (
	"syscall"
)

func main() {
	var buf syscall.Utsname
	for {
		syscall.Uname(&buf)
	}
}

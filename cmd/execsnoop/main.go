package main

import _ "github.com/cilium/ebpf"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf execsnoop.bpf.c -- -I../../headers

func main(){}

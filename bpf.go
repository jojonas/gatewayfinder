package main

import (
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

func translateBPF(instructions []pcap.BPFInstruction) []bpf.RawInstruction {
	translated := make([]bpf.RawInstruction, 0, len(instructions))

	for _, instruction := range instructions {
		translated = append(translated, bpf.RawInstruction{
			Op: instruction.Code,
			Jt: instruction.Jt,
			Jf: instruction.Jf,
			K:  instruction.K,
		})
	}

	return translated
}

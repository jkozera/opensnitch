package netstat

import (
	lru "github.com/hashicorp/golang-lru"
)

type Ip6Event struct {
    TsUs uint64
    Pid uint32
	Saddr1 uint64
	Saddr2 uint64
    Sport uint16
	Daddr1 uint64
	Daddr2 uint64
	Ipver uint64
    Dport uint16
    Udp uint8
}

type Ip4Event struct {
    TsUs uint64
	Pid uint32
	Saddr uint32
    Sport uint16
	Daddr uint32
	Ipver uint64
    Dport uint16
    Udp uint8
}

var (
	TCPCache, _ = lru.New(1024)
	UDPCache, _ = lru.New(1024)
)
package netstat

import (
	"net"

	"github.com/evilsocket/opensnitch/daemon/log"
)

func FindEntry(proto string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *Entry {
	entries, err := Parse(proto)
	if err != nil {
		log.Warning("Error while searching for %s netstat entry: %s", proto, err)
		return nil
	}

	for _, entry := range entries {
		if proto == "udp" && srcPort == entry.SrcPort {
			return &entry
		}
		if srcIP.Equal(entry.SrcIP) && srcPort == entry.SrcPort && dstIP.Equal(entry.DstIP) && dstPort == entry.DstPort {
			return &entry
		}
	}

	return nil
}

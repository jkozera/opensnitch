package netstat

import (
	"net"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/log"
)

func FindEntry(proto string, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) *Entry {
	entries, err, lines := Parse(proto)
	if err != nil {
		log.Debug(strings.Join(lines, "\n"));
		log.Warning("Error while searching for %s netstat entry: %s", proto, err)
		return nil
	}

	for _, entry := range entries {
		if srcIP.Equal(entry.SrcIP) && srcPort == entry.SrcPort && dstIP.Equal(entry.DstIP) && dstPort == entry.DstPort {
			return &entry
		}
	}
	for _, entry := range entries {
		if proto == "udp" && srcPort == entry.SrcPort {
			return &entry
		}
	}
	log.Debug(strings.Join(lines, "\n"));

	return nil
}

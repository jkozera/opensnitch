package conman

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/google/gopacket/layers"
)

type Connection struct {
	Protocol string
	SrcIP    net.IP
	SrcPort  int
	DstIP    net.IP
	DstPort  int
	DstHost  string
	Entry    *netstat.Entry
	Process  *procmon.Process

	pkt *netfilter.Packet
}

func Parse(nfp netfilter.Packet) *Connection {
	ipLayer := nfp.Packet.Layer(layers.LayerTypeIPv4)
	ipLayer6 := nfp.Packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil && ipLayer6 == nil {
		return nil
	}

	if (ipLayer == nil) {
		ip, ok := ipLayer6.(*layers.IPv6)
		if ok == false || ip == nil {
			return nil
		}

		con, err := NewConnection6(&nfp, ip)
		if err != nil {
			log.Debug("%s", err)
			return nil
		} else if con == nil {
			return nil
		}
		return con
	} else {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok == false || ip == nil {
			return nil
		}

		con, err := NewConnection(&nfp, ip)
		if err != nil {
			log.Debug("%s", err)
			return con
		} else if con == nil {
			return nil
		}
		return con
	}
}

func tryBPF(nfp *netfilter.Packet, c *Connection) (cr *Connection, err error) {
	port := uint16(c.SrcPort)
	if event, ok := netstat.UDPCache.Get(port); ok && c.Protocol == "udp" {
		e4 := event.(netstat.Ip4Event)
		c.Process = procmon.FindProcess(int(e4.Pid))
		entry := netstat.NewEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, nfp.Uid, int(e4.Pid))
		c.Entry = &entry
		return c, nil
	} else if event, ok := netstat.TCPCache.Get(port); ok && c.Protocol == "tcp" {
		e4 := event.(netstat.Ip4Event)
		c.Process = procmon.FindProcess(int(e4.Pid))
		entry := netstat.NewEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, nfp.Uid, int(e4.Pid))
		c.Entry = &entry
		return c, nil
	} else if event, ok := netstat.UDPCache.Get(port); ok && c.Protocol == "udp6" {
		e6 := event.(netstat.Ip6Event)
		c.Process = procmon.FindProcess(int(e6.Pid))
		entry := netstat.NewEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, nfp.Uid, int(e6.Pid))
		c.Entry = &entry
		return c, nil
	} else if event, ok := netstat.TCPCache.Get(port); ok && c.Protocol == "tcp6" {
		e6 := event.(netstat.Ip6Event)
		c.Process = procmon.FindProcess(int(e6.Pid))
		entry := netstat.NewEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, nfp.Uid, int(e6.Pid))
		c.Entry = &entry
		return c, nil
	}
	return nil, nil
}

func newConnectionImpl(nfp *netfilter.Packet, c *Connection) (cr *Connection, err error) {
	// no errors but not enough info neither
	if c.parseDirection() == false {
		return nil, nil
	}
	
	conn, err := tryBPF(nfp, c)
	if conn != nil {
		return conn, nil
	}

	// 1. lookup uid and inode using /proc/net/(udp|tcp)
	// 2. lookup pid by inode
	// 3. if this is coming from us, just accept
	// 4. lookup process info by pid
	if c.Entry = netstat.FindEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort); c.Entry == nil {
		// Try once more after 0.5s in case of a race:
		time.Sleep(1000 * 500);
		conn, err = tryBPF(nfp, c)
		if conn != nil {
			return conn, nil
		}
		
		entry := netstat.NewEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, nfp.Uid, -1)
		c.Entry = &entry
		c.Process = procmon.NewProcess(-1, "")
		return c, fmt.Errorf("Could not find netstat entry for: %s", c)
	} else if pid := procmon.GetPIDFromINode(c.Entry.INode); pid == -1 {
		// Try once more after 0.5s in case of a race:
		time.Sleep(1000 * 500);
		conn, err = tryBPF(nfp, c)
		if conn != nil {
			return conn, nil
		}

		c.Process = procmon.NewProcess(-1, "")
		return c, fmt.Errorf("Could not find process id for: %s", c)
	} else if pid == os.Getpid() {
		return nil, nil
	} else if c.Process = procmon.FindProcess(pid); c.Process == nil {
		return c, fmt.Errorf("Could not find process by its pid %d for: %s", pid, c)
	}

	// Try once more after 0.5s in case of a race:
	time.Sleep(1000 * 500);
	conn, err = tryBPF(nfp, c)
	if conn != nil {
		return conn, nil
	}
	return c, nil

}

func NewConnection(nfp *netfilter.Packet, ip *layers.IPv4) (c *Connection, err error) {
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ip.DstIP.String()),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c)
}

func NewConnection6(nfp *netfilter.Packet, ip *layers.IPv6) (c *Connection, err error) {
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ip.DstIP.String()),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c)
}

func (c *Connection) parseDirection() bool {
	ret := false
	for _, layer := range c.pkt.Packet.Layers() {
		if layer.LayerType() == layers.LayerTypeTCP {
			if tcp, ok := layer.(*layers.TCP); ok == true && tcp != nil {
				c.Protocol = "tcp"
				c.DstPort = int(tcp.DstPort)
				c.SrcPort = int(tcp.SrcPort)
				ret = true
			}
		} else if layer.LayerType() == layers.LayerTypeUDP {
			if udp, ok := layer.(*layers.UDP); ok == true && udp != nil {
				c.Protocol = "udp"
				c.DstPort = int(udp.DstPort)
				c.SrcPort = int(udp.SrcPort)
				ret = true
			}
		}
	}

	for _, layer := range c.pkt.Packet.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv6 {
			if tcp, ok := layer.(*layers.IPv6); ok == true && tcp != nil {
				c.Protocol += "6"
			}
		}
	}
	return ret
}

func (c *Connection) To() string {
	if c.DstHost == "" {
		return c.DstIP.String()
	}
	return c.DstHost
}

func (c *Connection) String() string {
	if c.Entry == nil || c.Entry.INode == -1 {
		return fmt.Sprintf("%s:%d ->(%s)-> %s:%d", c.SrcIP, c.SrcPort, c.Protocol, c.To(), c.DstPort)
	}

	if c.Process == nil || c.Process.ID == -1 {
		return fmt.Sprintf("%s (uid:%d) ->(%s)-> %s:%d", c.SrcIP, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	}

	return fmt.Sprintf("%s (%d) -> %s:%d (proto:%s uid:%d)", c.Process.Path, c.Process.ID, c.To(), c.DstPort, c.Protocol, c.Entry.UserId)
}

func (c *Connection) Serialize() *protocol.Connection {
	uid := uint32(0)
	pid := uint32(0)
	path := ""
	args := make([]string, 0)
	if (c.Process != nil) {
		path = c.Process.Path
		args = c.Process.Args
		pid = uint32(c.Process.ID)
	}
	if (c.Entry != nil) {
		uid = uint32(c.Entry.UserId)
	}
	return &protocol.Connection{
		Protocol:    c.Protocol,
		SrcIp:       c.SrcIP.String(),
		SrcPort:     uint32(c.SrcPort),
		DstIp:       c.DstIP.String(),
		DstHost:     c.DstHost,
		DstPort:     uint32(c.DstPort),
		UserId:      uid,
		ProcessId:   pid,
		ProcessPath: path,
		ProcessArgs: args,
	}
}

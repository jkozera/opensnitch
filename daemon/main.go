package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui"
)

import "C"


// based on https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py (Apache licensed)
const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(currsock_udp, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
	u64 ts_us;
	u32 pid;
	u32 saddr;
	u16 sport;
	u32 daddr;
	u64 ip;
	u16 dport;
	u8 udp;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
	u64 ts_us;
	u32 pid;
	unsigned __int128 saddr;
	u16 sport;
	unsigned __int128 daddr;
	u64 ip;
	u16 dport;
	u8 udp;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);

	return 0;
};

int trace_connect_entry_udp(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock_udp.update(&pid, &sk);

	return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;   // missed entry
	}
	currsock.delete(&pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u16 dport = skp->__sk_common.skc_dport;
	u16 sport = skp->__sk_common.skc_num;
	
	struct ipv4_data_t data4 = {};
	struct ipv6_data_t data6 = {};

	if (ipver == 4) {
		data4.ts_us = bpf_ktime_get_ns() / 1000;
		data4.pid = pid;
		data4.saddr = skp->__sk_common.skc_rcv_saddr;
		if (data4.saddr == 0 && data4.daddr == 0)  // tunnels
			return 0;
		data4.sport = sport;
		data4.daddr = skp->__sk_common.skc_daddr;
		data4.ip = ipver;
		data4.dport = ntohs(dport);
		data4.udp = 0;
		ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
	} else /* 6 */ {
		data6.ts_us = bpf_ktime_get_ns() / 1000;
		data6.pid = pid;
		bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
			skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
			skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		data6.sport = sport;
		data6.ip = ipver;
		data6.dport = ntohs(dport);
		data4.udp = 0;
		ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
	}
	return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx, 6);
}

int trace_connect_udp_return(struct pt_regs *ctx)
{
	struct sock **skpp;
	u32 pid = bpf_get_current_pid_tgid();
	skpp = currsock_udp.lookup(&pid);
	if (skpp == 0) {
		return 0;   // missed entry
	}
	currsock_udp.delete(&pid);
	struct sock *skp = *skpp;
	u16 dport = skp->__sk_common.skc_dport;
	u16 sport = skp->__sk_common.skc_num;
	struct ipv4_data_t data4 = {};
	struct ipv6_data_t data6 = {};

	if (skp->sk_family == AF_INET6) {
		data6.ts_us = bpf_ktime_get_ns() / 1000;
		data6.pid = pid;
		bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
			skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		data6.sport = sport;
		bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
			skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		data6.ip = 6;
		data6.dport = ntohs(dport);
		data6.udp = 1;
		ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
	} else {
		data4.ts_us = bpf_ktime_get_ns() / 1000;
		data4.pid = pid;
		data4.saddr = skp->__sk_common.skc_rcv_saddr;
		if (data4.saddr == 0 && data4.daddr == 0) // tunnels
			return 0;
		data4.sport = sport;
		data4.daddr = skp->__sk_common.skc_daddr;
		data4.ip = 4;
		data4.dport = ntohs(dport);
		data4.udp = 1;
		ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
	}
	return 0;
}
`

var (
	logFile	  = ""
	rulesPath	= "rules"
	noLiveReload = false
	queueNum	 = 0
	workers	  = 16
	debug		= false

	uiSocket = "unix:///tmp/osui.sock"
	uiClient = (*ui.Client)(nil)

	cpuProfile = ""
	memProfile = ""

	err	 = (error)(nil)
	rules   = (*rule.Loader)(nil)
	stats   = (*statistics.Statistics)(nil)
	queue   = (*netfilter.Queue)(nil)
	pktChan = (<-chan netfilter.Packet)(nil)
	wrkChan = (chan netfilter.Packet)(nil)
	sigChan = (chan os.Signal)(nil)
)

func init() {
	flag.StringVar(&uiSocket, "ui-socket", uiSocket, "Path the UI gRPC service listener (https://github.com/grpc/grpc/blob/master/doc/naming.md).")
	flag.StringVar(&rulesPath, "rules-path", rulesPath, "Path to load JSON rules from.")
	flag.IntVar(&queueNum, "queue-num", queueNum, "Netfilter queue number.")
	flag.IntVar(&workers, "workers", workers, "Number of concurrent workers.")
	flag.BoolVar(&noLiveReload, "no-live-reload", debug, "Disable rules live reloading.")

	flag.StringVar(&logFile, "log-file", logFile, "Write logs to this file instead of the standard output.")
	flag.BoolVar(&debug, "debug", debug, "Enable debug logs.")

	flag.StringVar(&cpuProfile, "cpu-profile", cpuProfile, "Write CPU profile to this file.")
	flag.StringVar(&memProfile, "mem-profile", memProfile, "Write memory profile to this file.")
}

func setupLogging() {
	golog.SetOutput(ioutil.Discard)
	if debug {
		log.MinLevel = log.DEBUG
	} else {
		log.MinLevel = log.INFO
	}

	if logFile != "" {
		if log.Output, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
			panic(err)
		}
	}
}

func setupSignals() {
	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Raw("\n")
		log.Important("Got signal: %v", sig)
		doCleanup()
		os.Exit(0)
	}()
}

func worker(id int) {
	log.Debug("Worker #%d started.", id)
	for true {
		select {
		case pkt := <-wrkChan:
			onPacket(pkt)
		}
	}
}

func runKprobes() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()
	entry, err := m.LoadKprobe("trace_connect_entry")
	if err != nil {
		log.Error("LoadKprobe failed!", err)
	}
	entryUdp, err := m.LoadKprobe("trace_connect_entry_udp")
	if err != nil {
		log.Error("LoadKprobe failed!", err)
	}
	connect4Ret, err := m.LoadKprobe("trace_connect_v4_return")
	if err != nil {
		log.Error("LoadKprobe failed!", err)
	}
	connect6Ret, err := m.LoadKprobe("trace_connect_v6_return")
	if err != nil {
		log.Error("LoadKprobe failed!", err)
	}
	udpReturn, err := m.LoadKprobe("trace_connect_udp_return")
	if err != nil {
		log.Error("LoadKprobe failed!", err)
	}
	
	err = m.AttachKprobe("tcp_v4_connect", entry)
	err = m.AttachKprobe("tcp_v6_connect", entry)
	err = m.AttachKprobe("udp_sendmsg", entryUdp)
	err = m.AttachKretprobe("tcp_v4_connect", connect4Ret)
	err = m.AttachKretprobe("tcp_v6_connect", connect6Ret)
	err = m.AttachKretprobe("udp_sendmsg", udpReturn)

	table4 := bpf.NewTable(m.TableId("ipv4_events"), m)
	channel4 := make(chan []byte)
	perfMap4, err := bpf.InitPerfMap(table4, channel4)
	if err != nil {
		perfMap4 = nil
	}

	table6 := bpf.NewTable(m.TableId("ipv6_events"), m)
	channel6 := make(chan []byte)
	perfMap6, err := bpf.InitPerfMap(table6, channel6)
	if err != nil {
		perfMap6 = nil
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go (func() {
		for {
			var event netstat.Ip4Event
			data := <-channel4
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if event.Udp == 1 {
				netstat.UDPCache.Add(event.Sport, event)
			} else {
				netstat.TCPCache.Add(event.Sport, event)
			}
		}
	})()
	go (func() {
		for {
			var event netstat.Ip6Event
			data := <-channel6
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if event.Udp == 1 {
				netstat.UDPCache.Add(event.Sport, event)
			} else {
				netstat.TCPCache.Add(event.Sport, event)
			}
		}
	})()

	if perfMap4 != nil {
		perfMap4.Start()
	}
	if perfMap6 != nil {
		perfMap6.Start()
	}
	<-sig
	if perfMap4 != nil {
		perfMap4.Stop()
	}
	if perfMap6 != nil {
		perfMap6.Stop()
	}
}

func setupWorkers() {
	log.Debug("Starting %d workers ...", workers)
	// setup the workers
	wrkChan = make(chan netfilter.Packet)
	for i := 0; i < workers; i++ {
		go worker(i)
	}

	go runKprobes()
}

func doCleanup() {
	log.Info("Cleaning up ...")
	firewall.QueueDNSResponses(false, queueNum)
	firewall.QueueConnections(false, queueNum)
	firewall.DropMarked(false)

	go procmon.Stop()

	if cpuProfile != "" {
		pprof.StopCPUProfile()
	}

	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			fmt.Printf("Could not create memory profile: %s\n", err)
			return
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			fmt.Printf("Could not write memory profile: %s\n", err)
		}
	}
}

func onPacket(packet netfilter.Packet) {
	// DNS response, just parse, track and accept.
	if dns.TrackAnswers(packet.Packet) == true {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		stats.OnDNSResponse()
		return
	}

	// Parse the connection state
	con := conman.Parse(packet)
	if con == nil {
		log.Error("con is nil - DROPPING!")
		packet.SetVerdict(netfilter.NF_DROP)
		stats.OnConnectionEvent(con, nil, true)
		return
	}

	// search a match in preloaded rules
	connected := false
	missed := false
	r := rules.FindFirstMatch(con)
	if r == nil {
		missed = true
		// no rule matched, send a request to the
		// UI client if connected and running
		r, connected = uiClient.Ask(con)
		if connected {
			ok := false
			pers := ""
			action := string(r.Action)
			if r.Action == rule.Allow {
				action = log.Green(action)
			} else {
				action = log.Red(action)
			}

			// check if and how the rule needs to be saved
			if r.Duration == rule.Restart {
				pers = "Added"
				// add to the rules but do not save to disk
				if err := rules.Add(r, false); err != nil {
					log.Error("Error while adding rule: %s", err)
				} else {
					ok = true
				}
			} else if r.Duration == rule.Always {
				pers = "Saved"
				// add to the loaded rules and persist on disk
				if err := rules.Add(r, true); err != nil {
					log.Error("Error while saving rule: %s", err)
				} else {
					ok = true
				}
			}

			if ok {
				log.Important("%s new rule: %s if %s", pers, action, r.Operator.String())
			}
		}
	}

	stats.OnConnectionEvent(con, r, missed)

	path := ""
	if con.Process != nil {
		path = con.Process.Path
	}

	if r.Action == rule.Allow {
		packet.SetVerdict(netfilter.NF_ACCEPT)

		ruleName := log.Green(r.Name)
		if r.Operator.Operand == rule.OpTrue {
			ruleName = log.Dim(r.Name)
		}
		log.Debug("%s %s -> %s:%d (%s)", log.Bold(log.Green("✔")), log.Bold(path), log.Bold(con.To()), con.DstPort, ruleName)
	} else {
		packet.SetVerdictAndMark(netfilter.NF_DROP, firewall.DropMark)
		log.Warning("%s %s -> %s:%d (%s)", log.Bold(log.Red("✘")), log.Bold(path), log.Bold(con.To()), con.DstPort, log.Red(r.Name))
	}
}

func main() {
	flag.Parse()

	setupLogging()

	if cpuProfile != "" {
		if f, err := os.Create(cpuProfile); err != nil {
			log.Fatal("%s", err)
		} else if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("%s", err)
		}
	}

	log.Important("Starting %s v%s", core.Name, core.Version)

	if err := procmon.Start(); err != nil {
		log.Fatal("%s", err)
	}

	rulesPath, err := core.ExpandPath(rulesPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	setupSignals()

	log.Info("Loading rules from %s ...", rulesPath)
	if rules, err = rule.NewLoader(!noLiveReload); err != nil {
		log.Fatal("%s", err)
	} else if err = rules.Load(rulesPath); err != nil {
		log.Fatal("%s", err)
	}
	stats = statistics.New(rules)

	// prepare the queue
	setupWorkers()
	queue, err := netfilter.NewQueue(uint16(queueNum))
	if err != nil {
		log.Fatal("Error while creating queue #%d: %s", queueNum, err)
	}
	pktChan = queue.Packets()

	// queue is ready, run firewall rules
	if err = firewall.QueueDNSResponses(true, queueNum); err != nil {
		log.Fatal("Error while running DNS firewall rule: %s", err)
	} else if err = firewall.QueueConnections(true, queueNum); err != nil {
		log.Fatal("Error while running conntrack firewall rule: %s", err)
	} else if err = firewall.DropMarked(true); err != nil {
		log.Fatal("Error while running drop firewall rule: %s", err)
	}

	uiClient = ui.NewClient(uiSocket, stats)

	log.Info("Running on netfilter queue #%d ...", queueNum)
	for true {
		select {
		case pkt := <-pktChan:
			wrkChan <- pkt
		}
	}
}

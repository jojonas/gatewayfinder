package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const protocolIPv4 = 0x0800
const protocolICMP = 1

func main() {
	log.SetLevel(log.InfoLevel)

	var interfaceName string
	var destinationIP string

	flag.StringVarP(&interfaceName, "interface", "i", "", "network interface")
	flag.StringVarP(&destinationIP, "target", "t", "1.1.1.1", "destination IP address")

	flag.Parse()

	if interfaceName == "" {
		log.Fatal("No interface specified, specify one with the command-line option --interface/-i.")
	}

	iface, subnet, err := findInterface(interfaceName)
	if err != nil {
		log.Fatalf("Error finding interface %q: %v", interfaceName, err)
	}

	log.Infof("ARP scanning network %s from interface %s...", subnet, iface.Name)

	prefix := netip.MustParsePrefix(subnet.String())
	replies, err := discoverPeers(iface, prefix)
	if err != nil {
		log.Fatalf("Error discovering peers: %v", err)
	}

	dst, err := netip.ParseAddr(destinationIP)
	if err != nil {
		log.Fatalf("Error parsing destination IP address %q: %v", destinationIP, err)
	}

	err = pingViaPeers(iface, dst, replies)
	if err != nil {
		log.Fatalf("Error sending ICMP pings to %s: %v", dst, err)
	}
}

func findInterface(name string) (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get list of interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name != name {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get IP address for interface %q: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			if subnet, ok := addr.(*net.IPNet); ok {
				return &iface, subnet, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("cannot find interface matching %q", name)
}

func discoverPeers(iface *net.Interface, prefix netip.Prefix) ([]arp.Packet, error) {
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("set up ARP client: %v", err)
	}
	defer client.Close()

	timeout := 3 * time.Second
	err = client.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("set ARP client's timeouts to %s: %v", timeout, err)
	}

	for ip := prefix.Masked().Addr(); prefix.Contains(ip); ip = ip.Next() {
		log.Debugf("Sending ARP ping to %s...", ip)

		err := client.Request(ip)
		if err != nil {
			log.Warnf("Error sending ARP ping to %s: %v", ip, err)
		}
	}

	var peers []arp.Packet
	var macsSeen []net.HardwareAddr

outer:
	for {
		packet, _, err := client.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			return nil, fmt.Errorf("read from ARP client: %v", err)
		}

		log.Debugf("Got ARP reply from %s (%s).", packet.SenderHardwareAddr, packet.SenderIP)

		for _, hardwareAddress := range macsSeen {
			if bytes.Equal(hardwareAddress, packet.SenderHardwareAddr) {
				continue outer
			}
		}

		peers = append(peers, *packet)
		macsSeen = append(macsSeen, packet.SenderHardwareAddr)
	}

	log.Infof("Got %d ARP replies.", len(peers))
	return peers, nil
}

func pingViaPeers(iface *net.Interface, dst netip.Addr, arpReplies []arp.Packet) error {
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 1, SkipTrue: 1},
		bpf.RetConstant{Val: 4096},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return fmt.Errorf("assemble BPF filter: %w", err)
	}

	packetconn, err := packet.Listen(iface, packet.Raw, protocolIPv4, &packet.Config{
		Filter: filter,
	})
	if err != nil {
		return fmt.Errorf("set up PacketConn: %w", err)
	}

	timeout := 5 * time.Second
	err = packetconn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return fmt.Errorf("set PacketConn's timeouts to %s: %v", timeout, err)
	}

	id := os.Getpid() & 0xffff

	for seq, arpReply := range arpReplies {
		if !arpReply.SenderIP.Is4() {
			log.Warnf("This implementation currently only supports IPv4.")
			continue
		}

		pattern := pingPattern(48)
		log.Debugf("Pattern: %x", pattern)

		icmpBody := &icmp.Echo{
			ID:   id,
			Seq:  seq + 1,
			Data: pattern,
		}

		icmpMessage := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: icmpBody,
		}

		icmpBytes, err := icmpMessage.Marshal(nil)
		if err != nil {
			return fmt.Errorf("marshal ICMP message: %w", err)
		}

		ipHeader := ipv4.Header{
			Version:  4,
			Len:      20,
			TotalLen: 20 + len(icmpBytes),
			TTL:      64,
			Protocol: protocolICMP,
			Src:      arpReply.TargetIP.AsSlice(),
			Dst:      dst.AsSlice(),
		}
		ipHeader.Checksum, err = checksum(ipHeader)
		if err != nil {
			return fmt.Errorf("calculate IP checksum: %w", err)
		}

		ipBytes, err := ipHeader.Marshal()
		if err != nil {
			return fmt.Errorf("marshal IP header: %w", err)
		}

		ethernetFrame := &ethernet.Frame{
			Destination: arpReply.SenderHardwareAddr,
			Source:      arpReply.TargetHardwareAddr,
			EtherType:   ethernet.EtherTypeIPv4,
			Payload:     append(ipBytes, icmpBytes...),
		}

		ethernetBytes, err := ethernetFrame.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal Ethernet frame: %w", err)
		}

		log.Infof("Sending ICMP ping #%d to %s via %s (%s)...", icmpBody.Seq, dst, ethernetFrame.Destination, arpReply.SenderIP)
		log.Debugf("Ethernet frame: %v", ethernetFrame)
		log.Debugf("IP header: %s", ipHeader.String())
		log.Debugf("ICMP message: %v", icmpMessage)

		_, err = packetconn.WriteTo(ethernetBytes, &packet.Addr{HardwareAddr: ethernetFrame.Destination})
		if err != nil {
			return fmt.Errorf("write to PacketConn: %w", err)
		}
	}

	buf := make([]byte, 1024)
	for {
		n, _, err := packetconn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			return fmt.Errorf("PacketConn.ReadFrom: %w", err)
		}

		ethernetFrame := new(ethernet.Frame)
		err = ethernetFrame.UnmarshalBinary(buf[:n])
		if err != nil {
			return fmt.Errorf("unmarshal ethernet frame: %w", err)
		}

		if ethernetFrame.EtherType != ethernet.EtherTypeIPv4 {
			log.Debugf("ignoring ethernet frame (EtherType: %s)", ethernetFrame.EtherType.String())
			continue
		}

		ipFrame := new(ipv4.Header)
		err = ipFrame.Parse(ethernetFrame.Payload)
		if err != nil {
			return fmt.Errorf("unmarshal IP header: %w", err)
		}

		if ipFrame.Protocol != protocolICMP {
			log.Debugf("ignoring IP packet (protocol: %d)", ipFrame.Protocol)
			continue
		}

		icmpBytes := ethernetFrame.Payload[ipFrame.Len:]
		icmpMessage, err := icmp.ParseMessage(ipFrame.Protocol, icmpBytes)
		if err != nil {
			return fmt.Errorf("parse ICMP message: %w", err)
		}

		if icmpMessage.Type == ipv4.ICMPTypeEchoReply {
			icmpBody := icmpMessage.Body.(*icmp.Echo)
			if icmpBody.ID != id {
				continue
			}

			log.Infof("Got ICMP echo reply #%d from %s (%s)!", icmpBody.Seq, ethernetFrame.Source, ipFrame.Src)
		}
	}

	return nil
}

func pingPattern(n int) []byte {
	padding := make([]byte, 0, n)

	var x byte
	for x = 0x10; len(padding) < n; x++ {
		padding = append(padding, x)
	}

	return padding
}

func checksum(header ipv4.Header) (int, error) {
	header.Checksum = 0
	buf, err := header.Marshal()
	if err != nil {
		return 0, err
	}

	return int(tcpipChecksum(buf, 0)), nil
}

func tcpipChecksum(data []byte, csum uint32) uint16 {
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

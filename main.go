package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/packet"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

const protocolIPv4 = 0x0800

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
	// filter language: https://www.winpcap.org/docs/docs_40_2/html/group__language.html
	filterString := "icmp and icmp[icmptype] = icmp-echoreply"

	pcapFilter, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 1024, filterString)
	if err != nil {
		return fmt.Errorf("compile BPF filter %q: %w", filterString, err)
	}
	filter := translateBPF(pcapFilter)

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

		ethernetLayer := layers.Ethernet{
			SrcMAC:       arpReply.TargetHardwareAddr,
			DstMAC:       arpReply.SenderHardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		}

		ipLayer := layers.IPv4{
			Version:  4,
			SrcIP:    arpReply.TargetIP.AsSlice(),
			DstIP:    dst.AsSlice(),
			Protocol: layers.IPProtocolICMPv4,
			TTL:      64,
		}

		icmpLayer := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       uint16(id),
			Seq:      uint16(seq + 1),
		}

		pattern := pingPattern(48)
		log.Debugf("Pattern: %x", pattern)

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		gopacket.SerializeLayers(buffer, options,
			&ethernetLayer,
			&ipLayer,
			&icmpLayer,
			gopacket.Payload(pattern),
		)

		log.Infof("Sending ICMP ping #%d to %s via %s (%s)...", icmpLayer.Seq, dst, ethernetLayer.DstMAC, arpReply.SenderIP)

		_, err = packetconn.WriteTo(buffer.Bytes(), &packet.Addr{HardwareAddr: ethernetLayer.DstMAC})
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

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.DecodeOptions{})

		ethernetLayer, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			log.Debugf("Ignoring non-Ethernet packet: %s...", packet)
			continue
		}

		ipLayer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			log.Debugf("Ignoring non-IPv4 packet: %s...", packet)
			continue
		}

		icmpLayer, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			log.Debugf("Ignoring non-ICMP packet: %s...", packet)
			continue
		}

		if icmpLayer.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			log.Infof("Got ICMP echo reply #%d from %s (%s)!", icmpLayer.Seq, ethernetLayer.SrcMAC, ipLayer.SrcIP)
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

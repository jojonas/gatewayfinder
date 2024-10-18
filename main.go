package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/packet"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

const protocolIPv4 = 0x0800

func main() {
	log.SetLevel(log.InfoLevel)

	var flagInterface string
	var flagNetwork string
	var flagTarget string
	var flagVerbose bool
	var flagShuffle bool
	var flagPort uint16

	flag.StringVarP(&flagInterface, "interface", "i", "", "network interface")
	flag.StringVarP(&flagTarget, "target", "t", "1.1.1.1", "destination IP address")
	flag.StringVarP(&flagNetwork, "network", "n", "", "network to scan (default: derived from the interface address)")
	flag.BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output")
	flag.BoolVar(&flagShuffle, "shuffle", false, "shuffle peers before pinging")
	flag.Uint16VarP(&flagPort, "port", "p", 0, "use this TCP port (or 0 for ICMP, which is the default)")

	flag.Parse()

	if flagVerbose {
		log.SetLevel(log.DebugLevel)
	}

	if flagInterface == "" {
		log.Fatal("No interface specified, specify one with the command-line option --interface/-i.")
	}

	iface, ifaceNetwork, err := findInterface(flagInterface)
	if err != nil {
		log.Fatalf("Error finding interface %q: %v", flagInterface, err)
	}

	var prefix netip.Prefix

	if flagNetwork != "" {
		prefix, err = netip.ParsePrefix(flagNetwork)
		if err != nil {
			log.Fatalf("Error parsing network %q: %v", flagNetwork, err)
		}
	} else {
		prefix = ifaceNetwork
	}

	dstIP, err := netip.ParseAddr(flagTarget)
	if err != nil {
		log.Fatalf("Error parsing destination IP %q: %v", flagTarget, err)
	}

	log.Infof("ARP scanning network %s from interface %s (%s)...", prefix.Masked().String(), iface.Name, ifaceNetwork.Addr())

	peers, err := DiscoverPeers(iface, &prefix)
	if err != nil {
		log.Fatalf("Error discovering peers: %v", err)
	}

	if flagShuffle {
		// shuffle peers
		for i := range peers {
			j := rand.Intn(i + 1)
			peers[i], peers[j] = peers[j], peers[i]
		}
	}

	if flagPort != 0 {
		err = tcpPing(iface, dstIP, peers, ifaceNetwork.Addr(), flagPort)
	} else {
		err = icmpPing(iface, dstIP, peers, ifaceNetwork.Addr())
	}
	if err != nil {
		log.Fatalf("Error sending pings to %s: %v", dstIP, err)
	}
}

func findInterface(name string) (*net.Interface, netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("cannot get list of interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name != name {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, netip.Prefix{}, fmt.Errorf("cannot get IP address for interface %q: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			if subnet, ok := addr.(*net.IPNet); ok {
				prefix := convertToPrefix(*subnet)
				return &iface, prefix, nil
			}
		}
	}

	return nil, netip.Prefix{}, fmt.Errorf("cannot find interface matching %q", name)
}

func icmpPing(iface *net.Interface, dstIP netip.Addr, peers []*Peer, srcIP netip.Addr) error {
	// filter language: https://www.winpcap.org/docs/docs_40_2/html/group__language.html
	filterString := fmt.Sprintf("dst host %s and icmp and icmp[icmptype] = icmp-echoreply", srcIP)

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

	log.Infof("Sending ICMP pings to %s...", dstIP)

	id := uint16(rand.Intn(1 << 16))

	pattern := icmpPingPattern(48)
	log.Debugf("Pattern: %x", pattern)

	echoRequests := make(map[uint16]*Peer)
	for index, peer := range peers {
		ethernetLayer := layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       peer.MAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		ipLayer := layers.IPv4{
			Version:  4,
			SrcIP:    srcIP.AsSlice(),
			DstIP:    dstIP.AsSlice(),
			Protocol: layers.IPProtocolICMPv4,
			TTL:      64,
		}

		seq := uint16(index + 1)

		icmpLayer := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       id,
			Seq:      seq,
		}

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

		log.Infof("Sending ICMP ping #%d/%d via %s...", icmpLayer.Id, icmpLayer.Seq, peer)

		buf := buffer.Bytes()

		_, err = packetconn.WriteTo(buf, &packet.Addr{HardwareAddr: ethernetLayer.DstMAC})
		if err != nil {
			return fmt.Errorf("write to PacketConn: %w", err)
		}

		echoRequests[icmpLayer.Seq] = peer
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

		replyPacket := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.DecodeOptions{})

		replyEthernetLayer, ok := replyPacket.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			log.Debugf("Ignoring non-Ethernet packet: %s...", replyPacket)
			continue
		}

		_, ok = replyPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			log.Debugf("Ignoring non-IPv4 packet: %s...", replyPacket)
			continue
		}

		replyIcmpLayer, ok := replyPacket.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			log.Debugf("Ignoring non-ICMP packet: %s...", replyPacket)
			continue
		}

		if replyIcmpLayer.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			log.Debugf("Ignoring ICMP non echo reply packet: %s...", replyPacket)
			continue
		}

		if replyIcmpLayer.Id != id {
			log.Debugf("Ignoring ICMP echo reply with mismatching ID: %s...", replyPacket)
			continue
		}

		requestPeer, ok := echoRequests[replyIcmpLayer.Seq]
		if !ok {
			log.Debugf("Ignoring ICMP echo reply with invalid seq: %s...", replyPacket)
			continue
		}

		var replyPeer *Peer = nil
		for _, candidatePeer := range peers {
			if bytes.Equal(replyEthernetLayer.SrcMAC, candidatePeer.MAC) {
				replyPeer = candidatePeer
			}
		}

		replyPeerStr := ""
		if replyPeer != nil {
			replyPeerStr = replyPeer.String()
		} else {
			replyPeerStr = replyEthernetLayer.SrcMAC.String()
		}

		if !bytes.Equal(replyEthernetLayer.SrcMAC, requestPeer.MAC) {
			log.Infof("Got ICMP echo reply #%d/%d from %s (ping was originally sent out to %s)!", replyIcmpLayer.Id, replyIcmpLayer.Seq, replyPeerStr, requestPeer)
		} else {
			log.Infof("Got ICMP echo reply #%d/%d from %s!", replyIcmpLayer.Id, replyIcmpLayer.Seq, replyPeerStr)
		}
	}

	return nil
}

func icmpPingPattern(n int) []byte {
	padding := make([]byte, 0, n)

	var x byte
	for x = 0x10; len(padding) < n; x++ {
		padding = append(padding, x)
	}

	return padding
}

func tcpPing(iface *net.Interface, dstIP netip.Addr, peers []*Peer, srcIP netip.Addr, port uint16) error {
	// filter language: https://www.winpcap.org/docs/docs_40_2/html/group__language.html
	filterString := fmt.Sprintf("dst host %s and tcp src port %d", srcIP, port)

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

	log.Infof("Sending TCP SYNs (port %d) to %s...", port, dstIP)

	tcpSyns := make(map[layers.TCPPort]*Peer)
	for index, peer := range peers {
		ethernetLayer := layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       peer.MAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		ipLayer := layers.IPv4{
			Version:  4,
			SrcIP:    srcIP.AsSlice(),
			DstIP:    dstIP.AsSlice(),
			Protocol: layers.IPProtocolTCP,
			TTL:      64,
		}

		srcPort := uint16(50000 + index)

		tcpLayer := layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(port),
			SYN:     true,
		}
		tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		gopacket.SerializeLayers(buffer, options,
			&ethernetLayer,
			&ipLayer,
			&tcpLayer,
		)

		log.Infof("Sending TCP SYN from port %d via %s...", tcpLayer.SrcPort, peer)

		buf := buffer.Bytes()

		_, err = packetconn.WriteTo(buf, &packet.Addr{HardwareAddr: ethernetLayer.DstMAC})
		if err != nil {
			return fmt.Errorf("write to PacketConn: %w", err)
		}

		tcpSyns[tcpLayer.SrcPort] = peer
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

		replyPacket := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.DecodeOptions{})

		replyEthernetLayer, ok := replyPacket.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			log.Debugf("Ignoring non-Ethernet packet: %s...", replyPacket)
			continue
		}

		_, ok = replyPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			log.Debugf("Ignoring non-IPv4 packet: %s...", replyPacket)
			continue
		}

		replyTcpLayer, ok := replyPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			log.Debugf("Ignoring non-TCP packet: %s...", replyPacket)
			continue
		}

		requestPeer, ok := tcpSyns[replyTcpLayer.DstPort]
		if !ok {
			log.Debugf("Ignoring TCP packet with invalid src port: %s...", replyPacket)
			continue
		}

		var replyPeer *Peer = nil
		for _, candidatePeer := range peers {
			if bytes.Equal(replyEthernetLayer.SrcMAC, candidatePeer.MAC) {
				replyPeer = candidatePeer
			}
		}

		replyPeerStr := ""
		if replyPeer != nil {
			replyPeerStr = replyPeer.String()
		} else {
			replyPeerStr = replyEthernetLayer.SrcMAC.String()
		}

		if !bytes.Equal(replyEthernetLayer.SrcMAC, requestPeer.MAC) {
			log.Infof("Got TCP %s from %s (ping was originally sent out to %s)!", tcpFlags(replyTcpLayer), replyPeerStr, requestPeer)
		} else {
			log.Infof("Got TCP %s from %s!", tcpFlags(replyTcpLayer), replyPeerStr)
		}
	}

	return nil
}

func tcpFlags(tcpLayer *layers.TCP) string {
	var parts []string
	if tcpLayer.SYN {
		parts = append(parts, "SYN")
	}
	if tcpLayer.ACK {
		parts = append(parts, "ACK")
	}
	if tcpLayer.RST {
		parts = append(parts, "RST")
	}
	if tcpLayer.FIN {
		parts = append(parts, "FIN")
	}

	return strings.Join(parts, "|")
}

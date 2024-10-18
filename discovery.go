package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
)

type Peer struct {
	MAC net.HardwareAddr
	IPs []netip.Addr
}

func (p Peer) String() string {
	var ipStr []string
	for _, ip := range p.IPs {
		ipStr = append(ipStr, ip.String())
	}

	return fmt.Sprintf("%s (%s)", p.MAC, strings.Join(ipStr, ", "))
}

func appendPeer(peers []*Peer, hwaddr net.HardwareAddr, ip netip.Addr) []*Peer {
	var peer *Peer = nil

	// search for existing
	for _, candidatePeer := range peers {
		if bytes.Equal(candidatePeer.MAC, hwaddr) {
			peer = candidatePeer
		}
	}

	if peer == nil {
		// if not found, insert new peer
		peer = &Peer{MAC: hwaddr}
		peers = append(peers, peer)
	}

	// uniquely insert into list of IPs
	found := false
	for _, candidateIP := range peer.IPs {
		if candidateIP == ip {
			found = true
		}
	}
	if !found {
		peer.IPs = append(peer.IPs, ip)
	}

	return peers
}

func DiscoverPeers(iface *net.Interface, prefix *netip.Prefix) ([]*Peer, error) {
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

	if prefix.Bits() <= 16 {
		log.Warnf("This appears to be a large network: %s", prefix)
	}

	for ip := prefix.Masked().Addr(); prefix.Contains(ip); ip = ip.Next() {
		log.Debugf("Sending ARP ping to %s...", ip)

		err := client.Request(ip)
		if err != nil {
			log.Warnf("Error sending ARP ping to %s: %v", ip, err)
		}
	}

	var peers []*Peer

	for {
		packet, _, err := client.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			return nil, fmt.Errorf("read from ARP client: %v", err)
		}

		log.Debugf("Got ARP reply from %s (%s).", packet.SenderHardwareAddr, packet.SenderIP)

		peers = appendPeer(peers, packet.SenderHardwareAddr, packet.SenderIP)
	}

	log.Infof("Discovered %d peers.", len(peers))
	for _, peer := range peers {
		log.Debugf("Peer: %s", peer)
	}

	return peers, nil
}

func convertToAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

func convertToPrefix(network net.IPNet) netip.Prefix {
	addr := convertToAddr(network.IP)
	ones, _ := network.Mask.Size()
	return netip.PrefixFrom(addr, ones)
}

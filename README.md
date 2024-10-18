# Gateway Finder

This is a small Go application that can be used to discover gateways to other
networks. The following example shows an invocation:

```shell-session
$ sudo ./gatewayfinder -i wlp3s0 -t 1.1.1.1
INFO[0000] ARP scanning network 192.168.179.0/24 from interface wlp3s0 (192.168.179.8)... 
INFO[0003] Discovered 1 peers.                          
INFO[0003] Sending ICMP pings to 1.1.1.1...             
INFO[0003] Sending ICMP ping #33313/1 via 3c:a6:2f:c6:fc:a2 (192.168.179.1)... 
INFO[0003] Got ICMP echo reply #33313/1 from 3c:a6:2f:c6:fc:a2 (192.168.179.1)!
``` 

The discovery is basically a two-step process:
1. *Peer discovery*: The applicaton uses ARP to discovery systems directly
   reachable via Ethernet in the current network.
2. *Ping*: The application sends out a series of "pings" (either ICMP or TCP
   SYN). The IP header for each ping is identical and specifies a given target
   IP address. The underlying Ethernet-frame is however sent to each of the
   peers discovered in step 1.

Note:
 * The network used when ARP scanning can be configured with `-n`/`--network`.
 * The ping method (ICMP or TCP port) can be configured with `-p`/`--port`. Use `0` for ICMP.
 * The target IP address to ping can be configured with `-t`/`--target`, the
   default is 1.1.1.1, which can be used to discover Internet access.

The documentation for the command-line options can be printed out by setting the
`--help` command-line option.

## Building

The application is written in Go and therefore requires a Go compiler.
Additionally, as the application sends and receives packets using `gopacket`, it
depends on libpcap. Both dependencies can usually be installed through the
package manager:

```
sudo apt install golang libpcap-dev
``` 

Building is simple:
```
go build .
```

## Required Privileges

The discovery process uses raw sockets. Therefore it must be either started as
the `root` user (for example using `sudo`) or you can set the corresponding
capabilities on the binary (note that this has to be repeated after
recompiling), which allows you to run it as any user:

```
sudo setcap cap_net_raw+ep ./gatewayfinder
./gatewayfinder [...]
```
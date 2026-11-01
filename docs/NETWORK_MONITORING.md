# How network visibility works (and its limits)

"Every packet on the network" is not achievable by any program on a normal PC, including Wireshark. InetGateway is honest about this in the UI and here.

## What can be captured

| Backend | Layer | Sees | Does not see |
|---|---|---|---|
| Windows raw socket (`SIO_RCVALL`) | IP | IPv4 packets to/from the chosen local address | IPv6, loopback, Ethernet headers and ARP, packets dropped earlier by the OS or a firewall driver |
| Npcap (optional, installed separately) | Ethernet | Ethernet frames, IPv4, IPv6, ARP, the loopback adapter | The network limits below |
| Linux `AF_PACKET` | Ethernet | Ethernet frames, IPv4, IPv6, ARP, loopback | The network limits below |

## What no backend can see

- **Other devices' traffic.** On a switched network or behind a router your PC only receives its own unicast traffic plus broadcast and multicast.
  Seeing other devices needs a mirror (SPAN) port or a capture on the router or gateway.
- **Encrypted contents.** HTTPS, QUIC and similar are shown as headers and sizes only. The app never decrypts anything. By default only the first 128 bytes per packet are even stored.
- **Everything under load.** The OS or the viewer queue can drop packets. The status bar counts viewer-side drops only.
- Virtual switches, VPN adapters and security software can change what a backend receives.

## Process attribution

- **Windows:** a once-per-second snapshot of the TCP/UDP tables (`GetExtendedTcpTable`/`GetExtendedUdpTable`). TCP needs an exact 4-tuple match. UDP matches the local port only and is labelled lower confidence in the details.
- **Linux:** `/proc/net/{tcp,udp}[6]` for the sockets and `/proc/<pid>/fd` for their owners. As a normal user only your own processes are visible; as root, all.
- Connections that start and end between snapshots are not attributed. A blank Process column means *unknown*, never a guess.
- Process names come from the executable path. A recycled PID inside the 10-second name cache can briefly mislabel a process.
- **Service names:** Windows `tasklist /svc` (e.g. `svchost.exe [Dnscache]`); Linux the systemd unit from the process's cgroup (e.g. `sshd [ssh]`).

## What "Sent" and "Received" mean

Packets leaving or arriving at this PC, decided by comparing a packet's addresses with this PC's addresses (taken from the connection tables and the host name lookup).
They are **not** HTTP requests and responses: encrypted traffic cannot be split that way. DNS queries and responses *are* counted, from DNS headers.
If no local address is known (for example when you open a pcap file) the direction is shown as unknown rather than guessed.

## DNS names

Names are learned only from A/AAAA answers in plain DNS responses seen on this PC and shown next to the IP. The app performs no lookups.
IPs reached without a visible DNS answer (cached names, DNS over HTTPS, hard-coded addresses) appear as bare IPs. Applications usually resolve through the OS resolver,
so their queries often appear under the DNS client service rather than the application.

## Extending visibility

Router flow exports (NetFlow/IPFIX), mirror ports and gateway captures are **not implemented**. A pcap taken at such a point can be opened with *File > Open pcap*.

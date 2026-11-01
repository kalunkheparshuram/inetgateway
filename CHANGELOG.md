# Changelog

All notable changes are listed here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-01

First public pre-release. Treat it as beta: the Windows capture paths have not been exercised on real Windows hardware by the author.

### Added
- Wireshark-style packet list, decoded details and hex view; display filters; pcap save/open; CSV export.
- Decoders for Ethernet/VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP/ICMPv6, IGMP, DNS/mDNS (queries and A/AAAA answers).
- Capture backends: Windows raw socket (no driver), optional Npcap, Linux `AF_PACKET`.
- Process attribution from OS connection tables (Windows) or `/proc` (Linux), with Windows service names (`tasklist /svc`) and systemd unit names.
- Dashboard: per-software and per-service activity, From/To with DNS names, throughput graph, pie and bar charts.
- Threat Intel tab: optional, off-by-default VirusTotal lookups (own API key, rate limits, local cache, DPAPI-encrypted key on Windows).
- Rounded light and true-black dark themes; keyboard-accessible controls.
- Packages: single-file Windows `.exe` and Debian/Ubuntu `.deb`, built by GitHub Actions.

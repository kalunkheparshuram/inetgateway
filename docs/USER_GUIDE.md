# User guide

## Install and start

- **Windows 10/11:** download `InetGateway-<version>-windows-x64.exe` from the Releases page, check its SHA-256 against `SHA256SUMS.txt`
  (see [Verifying downloads](#verifying-downloads)), run it. Windows SmartScreen will warn because the file is not code-signed.
  For live capture, right-click and choose *Run as administrator*, or use *Capture > Restart as administrator*.
- **Debian/Ubuntu:** `sudo apt install ./inetgateway_<version>-1_all.deb`, then start it from the menu, or for live capture run
  `sudo -E inetgateway` (see [Linux permissions](TROUBLESHOOTING.md#linux-needs-root-for-capture)).
- **From source (any OS with Python 3.9+ and tkinter):** `python3 inetgateway.py` (add `--demo` to try it with synthetic traffic).

First run: choose an interface, press **Start** (F5). **Stop** is F6. `--demo` shows clearly labelled fake traffic for trying the interface.

## Interfaces

| System | What is listed | What you get |
|---|---|---|
| Windows | `Npcap: ...` entries if Npcap is installed, plus `Raw socket: <your IP>` | Npcap: Ethernet frames, IPv4, IPv6, ARP, loopback adapter. Raw socket: IPv4 only, no loopback |
| Linux | `Linux capture: <interface>` for every interface, loopback last | Ethernet frames, IPv4, IPv6, ARP, loopback |

## Packets tab

The packet list shows No., Time (seconds since the first packet), Source, Destination, Protocol, Length, Process and Info. Click a row for the
decoded layers and a hex dump. Only the first N bytes of each packet are stored (default 128, *Capture > Settings*), so you see headers, not payloads.
Right-click a row to copy fields or filter on its addresses.

**Filter** (Enter or Apply; invalid filters turn red and keep the old filter). Space means AND, a leading `!` means NOT:

`tcp` `udp` `dns` `mdns` `arp` `icmp` `icmpv6` `igmp` `ipv4` `ipv6` · `ip==1.2.3.4` `src==` `dst==` · `port==443` `sport==` `dport==` ·
`proc==chrome` · `len>1000` `len<=60` · any other word matches addresses, process names and the Info text.

Files: *File > Save as pcap* (opens in Wireshark), *Open pcap* (classic pcap only, not pcapng), *Export CSV (current filter)*.
Starting a new capture clears the current packets after asking.

## Dashboard tab

Counts run from capture start and are not limited by the packet buffer. See [NETWORK_MONITORING.md](NETWORK_MONITORING.md) for what "Sent" and "Received" mean.

- **Summary line:** sent and received totals, software seen, remote endpoints, DNS names learned.
- **Throughput graph:** the last 120 seconds, sent (solid) and received (dashed).
- **Pie chart:** share of traffic by software, protocol, remote endpoint or direction (dropdown).
- **Bar chart:** top remote endpoints by total bytes.
- **Software and services table:** per program or service: packets and bytes each way, connections opened (outbound SYN), DNS queries, number of remotes, last seen (date and time). Click a row to filter the activity list.
- **Activity table:** one row per software and remote endpoint: From and To (IP plus DNS name when learned), protocol and port, packets and bytes each direction, first and last seen, and the Threat intel result if you enabled lookups.

## Threat Intel tab

System status, and the optional VirusTotal checks. Full details: [THREAT_INTEL.md](THREAT_INTEL.md).

## Themes and settings

*View > Dark mode* switches between the light theme and the true-black theme; the choice is remembered. Settings are stored in
`%APPDATA%\InetGateway\config.json` (Windows) or `~/.config/InetGateway/config.json` (Linux). Deleting that folder resets everything.

## Keyboard

F5 start, F6 stop, Ctrl+F focus the filter, Ctrl+1/2/3 or Ctrl+Tab switch tabs, Tab/Shift+Tab move focus, Space/Enter press the focused button, Left/Right move between tabs.

## Verifying downloads

Each release has `SHA256SUMS.txt`. Windows PowerShell: `Get-FileHash .\InetGateway-*.exe -Algorithm SHA256`. Linux: `sha256sum -c SHA256SUMS.txt`.
The values must match the file. The binaries are built by the public GitHub Actions workflow in this repository from the tagged source.

## Uninstall

- Windows: delete the `.exe`; delete `%APPDATA%\InetGateway` to remove settings, the cached lookups and any saved key.
- Debian/Ubuntu: `sudo apt remove inetgateway`; delete `~/.config/InetGateway` to remove settings.

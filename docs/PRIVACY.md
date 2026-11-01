# Privacy

## Summary

- **Offline by default.** With the optional VirusTotal lookups off (the default) InetGateway starts no network connection at all: no telemetry, no update checks, no accounts, no remote fonts or scripts, no crash reporting.
- Captured packets stay **in memory** and are discarded when you clear or close. Nothing is written unless you save it.
- It never decrypts traffic, never collects credentials, cookies or message contents, and stores only the first 128 bytes of each packet by default (headers).

## What is stored on disk

| File | Where | Contents | When |
|---|---|---|---|
| `config.json` | `%APPDATA%\InetGateway\` or `~/.config/InetGateway/` | Theme, capture size limits, last interface, VirusTotal on/off and limits | Always (settings) |
| `vt_key.json` | same folder | Your VirusTotal API key: DPAPI-encrypted for your Windows user; on Linux only base64 with owner-only permissions (not encryption) | Only if you save a key |
| `intel_cache.json` | same folder | Indicators you looked up (IP/domain/file hash), VirusTotal counts, times, daily request counter | Only if lookups were enabled |
| `.pcap` / `.csv` files | where you choose | Packets / the packet list | Only when you click save/export |

Remove everything by deleting the settings folder, or use *Threat Intel > Clear results* and *Remove key*.

## What the optional VirusTotal feature sends

Only if you save a key and enable lookups: public IP addresses seen in your traffic, public domain names from DNS answers, and SHA-256 hashes of program files, to `www.virustotal.com` over HTTPS with your key.
**Never sent:** file contents, file paths, packet contents, your private/local/multicast addresses, process names. VirusTotal's own terms and privacy policy apply to what you send them,
and they associate lookups with your account. Details and controls: [THREAT_INTEL.md](THREAT_INTEL.md).

## Things to be aware of

- Packet bytes you view or save can contain sensitive data: unencrypted traffic is readable in the hex view and in saved `.pcap` files. Treat those files like any sensitive file.
- Running a capture tool on a network you do not own or administer may be restricted by policy or law. Use it on your own machine and networks.
- "Offline" is verified by the test suite for the decoding, filtering and storage code and by reading the source (the only web address in it is VirusTotal's). It is not a guarantee about your OS or other software.

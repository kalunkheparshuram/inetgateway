# Security policy

## Reporting a vulnerability

Please report security problems **privately** using GitHub's "Report a vulnerability" button on the repository's *Security* tab
(*Security > Advisories > Report a vulnerability*). Do not open a public issue for an undisclosed vulnerability.
If that button is not available, open a public issue asking for a private contact channel, without technical details.

This is a volunteer project: reports are handled on a best-effort basis with no guaranteed response time. Please include the version, your system, and steps to reproduce.
Do not include your VirusTotal API key or private packet captures.

## Supported versions

Only the latest release receives fixes.

## Scope and threat model

InetGateway is a local desktop program. It has no server, no service, no IPC endpoint and no installer component, and it runs with the privileges of whoever starts it
(capture needs administrator/root, or `CAP_NET_RAW` on Linux). Things we consider in scope:

- **Hostile network input**: packets are untrusted. The decoders must never crash, hang or run code on crafted packets (fuzz-tested). Captured strings are sanitised before display and export (including CSV formula injection).
- **Files it reads**: pcap files and its own JSON files are validated; corrupt files are set aside, never executed.
- **The optional VirusTotal feature**: the API key must never leave the machine except in the `x-apikey` header to `www.virustotal.com`; requests are built only from validated values; redirects are refused; responses are size-capped and parsed defensively.
- **Privacy claims** in the docs and UI (what is stored, what is sent).

Known limitations, not vulnerabilities by themselves: on Linux the saved API key is base64 with owner-only permissions (not encrypted); on Windows DPAPI protects the key from other users but not from malware running as the same user;
a process running as you can read your settings and cache; running the program as root/administrator means a bug in it runs with those privileges, so prefer capability-based or short-lived elevation.

## Verifying downloads

Releases include `SHA256SUMS.txt`. The files are built by the public GitHub Actions workflow from the tagged commit. The Windows `.exe` is not code-signed.

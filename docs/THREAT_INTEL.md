# Threat intelligence (VirusTotal)

An optional, **off-by-default** aid in the Threat Intel tab. It checks things your computer talks to against VirusTotal using **your own API key** and shows hits next to the software involved.
It is a detection aid, not an EDR: it only reports. It never blocks, kills, quarantines or changes anything.

## Turning it on

1. Create a VirusTotal account and copy your API key (VirusTotal's site, your profile).
2. Threat Intel tab > paste the key > **Save key**. The key must be letters and digits only (other input is rejected).
3. Tick **Enable VirusTotal lookups**. Nothing is sent before this.
4. Optionally tick the automatic sources: new public remote IPs, domains learned from DNS answers, program files (SHA-256) of software that uses the network. Each is off by default.
5. Or type an IP, domain or MD5/SHA-1/SHA-256 into *Check* for a one-off lookup.

## What is sent, and what is not

| Sent to `www.virustotal.com` (HTTPS, your key in the `x-apikey` header) | Never sent |
|---|---|
| Public IP addresses seen in your traffic | File contents or paths |
| Public domain names from DNS answers | Packet contents |
| SHA-256 of program files | Private/loopback/link-local/multicast addresses |
| | Process names, your hostname, other settings |

Program hashes are computed locally; the file is read, hashed and never uploaded. Files over 512 MB and network-share paths are skipped.

## Limits and politeness

- You set **requests per minute** (default 4) and a **daily cap** (default 500). Those defaults match what VirusTotal documents for free public keys at the time of writing; the free API is for non-commercial use. Check VirusTotal's current terms and your plan, and raise limits only if your plan allows.
- One request at a time, spaced out. On HTTP 429 the program waits 60 seconds and retries up to twice, then gives up on that item. If the key is rejected (401/403) it stops sending until you change the key.
- Answers are cached locally: 24 hours for IPs and domains, 7 days for files. Repeat sightings cost no requests. The daily counter survives restarts.
- At most 200 automatic lookups wait in the queue; manual checks jump the queue.

## Reading results

| Severity | Meaning |
|---|---|
| **High** | 3 or more engines say *malicious* |
| **Low** | 1 or 2 engines say malicious (could be false positives) |
| **Review** | No *malicious* verdicts but some *suspicious* |
| **None** | No detections from the engines that analysed it |
| n/a | Not found (HTTP 404: VirusTotal has never seen it, which is *no verdict*, not "clean"), rate limited, key rejected, or lookup failed |

Detections are evidence, not proof: security vendors disagree and false positives happen. No detections does not mean safe. An unfamiliar address or file is not malicious by itself.
Selecting a row shows the engine counts, reputation score, owner/name, and which software it was seen with. **Open in VirusTotal** opens your browser (the app sends nothing at that moment).
The Dashboard's *Threat intel* column shows `VT flagged/engines` (malicious plus suspicious over total engines) for the remote IP of each activity row.

## Your key and your data

The key is stored in its own file (`vt_key.json`), never in `config.json`, never shown, logged or exported. On Windows it is encrypted with DPAPI for your Windows user (other users and other machines cannot decrypt it; malware running as you can).
On Linux it is only base64 with `0600` permissions, which is **not encryption**; the Threat Intel tab says so. Remove it any time with **Remove key**. The lookup cache is `intel_cache.json` in the same folder (*Clear results* empties it).

## Security notes

- Requests go only to `https://www.virustotal.com/api/v3/`. The URL is built from validated values (IP parsed, domain pattern-checked, hash pattern-checked, percent-encoded); anything else is refused. Redirects are never followed, so the key cannot be sent anywhere else. TLS certificates are verified. Responses are capped at 1 MB and parsed defensively; text from responses is sanitised before display.
- Your system proxy settings apply (standard Python behaviour).
- `--demo` mode uses canned answers and never touches the network or your real key.

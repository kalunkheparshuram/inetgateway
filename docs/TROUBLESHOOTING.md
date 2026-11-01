# Troubleshooting

## Windows

- **SmartScreen: "Windows protected your PC".** The `.exe` is not code-signed. Check the SHA-256 against `SHA256SUMS.txt`, then *More info > Run anyway*.
- **Antivirus flags the `.exe`.** Executables made with PyInstaller are sometimes flagged by heuristics. You can instead run the source (`py -3 inetgateway.py`) or build the exe yourself (`packaging\windows\build_exe.bat`) and compare behaviour. Report persistent false positives to your antivirus vendor.
- **"Administrator rights are required" when starting capture.** Raw-socket capture needs it: use *Capture > Restart as administrator*, or install Npcap and choose an Npcap interface.
- **Only incoming or only outgoing packets (raw socket).** A raw-socket limit on some Windows builds and with some security software. Use Npcap.
- **No interfaces listed.** The raw-socket list comes from your host name lookup. Install Npcap, which lists every adapter.
- **Process column blank / everything "(unattributed)".** Short-lived connections can start and end between once-per-second snapshots; UDP and some system traffic cannot be matched. Make sure you run as administrator.
- **Dark mode: title bar stays light.** The dark title bar is requested best-effort and depends on your Windows build.

## Linux

### Linux needs root for capture
Live capture uses an `AF_PACKET` socket and needs root or `CAP_NET_RAW`.

- Simplest: `sudo -E inetgateway` (the `-E` keeps `DISPLAY`/`XAUTHORITY` so the window can open). On Wayland desktops root may not be allowed to open a window; if it fails, allow it for this session with `xhost +si:localuser:root` (understand what that permits) or run in an X11 session.
- Not recommended: `setcap cap_net_raw+ep` on the system Python gives raw-socket capability to *every* Python script. Only consider it on a dedicated, private interpreter.
- Without root the app still starts, `--demo` works, and *File > Open pcap* works; starting a capture shows the permission message.
- As a normal user the Process column can only name your own processes; as root it names all.

### Other
- **"Tkinter is not available".** Install it: Debian/Ubuntu `sudo apt install python3-tk` (the `.deb` depends on it).
- **A VPN/virtual interface shows "Unsupported interface type".** Only Ethernet-like, loopback and raw-IP (tun/ppp) interfaces are supported.
- **No process names in a container or restricted environment.** `/proc` access to other processes may be blocked.

## Both

- **Nothing happens on Start / "No capture interface found".** Check you picked an interface; on Windows without Npcap or admin rights the list can be short.
- **High CPU or "Viewer drops" rising.** Sustained thousands of packets per second exceed what the Python viewer can keep up with. Use a capture filter at the network level, stop the capture, or use a pcap + Wireshark for heavy loads.
- **No DNS names in the Dashboard.** Names are learned only from plain DNS answers seen on this PC. DNS over HTTPS, cached names and hard-coded IPs do not show names.
- **VirusTotal: "API key rejected", "Rate limited", "Daily limit reached".** Check the key, wait (the app backs off by itself), or lower your request rate. *No valid API key* means the key was removed or never saved. Lookups never start unless you enabled them.
- **Settings file was unreadable.** It is renamed to `config.json.bad` and defaults are loaded; delete the `.bad` file when you are done with it.
- **Reset everything.** Close the app and delete `%APPDATA%\InetGateway` (Windows) or `~/.config/InetGateway` (Linux).

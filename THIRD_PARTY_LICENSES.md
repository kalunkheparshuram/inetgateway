# Third-party notices

InetGateway itself is GPL-3.0-or-later (see LICENSE).

It uses only the Python standard library (including Tcl/Tk via tkinter), which is covered by the
Python Software Foundation License and the Tcl/Tk license. No third-party packages are bundled or required at runtime.

Optional, not included: **Npcap** (separate download by its authors, with its own license terms that you must read
before installing or using it). InetGateway only loads Npcap's wpcap.dll at runtime if you have already installed it.

Development-time only, not included: PyInstaller (GPL-2.0-or-later with a bootloader exception), used only by build_exe.bat.

Optional online service, not included: **VirusTotal** (Threat Intel tab). It is a third-party service with its own terms of service and
API usage limits, which apply to you when you use your own API key. InetGateway ships no VirusTotal code, data, or key.

## What the packaged files contain

- **`InetGateway.exe`** (PyInstaller one-file build) bundles the CPython runtime and standard library (Python Software Foundation License), Tcl/Tk (Tcl/Tk licence), and the PyInstaller bootloader (GPL-2.0-or-later with a special exception that permits bundling). Source for InetGateway is this repository at the release tag.
- **`inetgateway_*.deb`** contains only InetGateway itself; it depends on the system `python3` and `python3-tk` packages.
- Pinned build tool (not shipped, build time only): PyInstaller 6.22.3.

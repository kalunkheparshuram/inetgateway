# Development

## Layout

```
inetgateway.py            the application (standard library only)
tests/                    unit tests, GUI smoke tests (need a display), Linux capture tests (need root)
packaging/                icons, .deb and Windows .exe build scripts, release helpers
docs/                     documentation
.github/workflows/        CI and release automation
```

## Run from source

```
python3 inetgateway.py --demo          # synthetic traffic, no capture, no network
sudo -E python3 inetgateway.py         # live capture on Linux (Windows: run as administrator)
```
Requires Python 3.9+ and tkinter (`sudo apt install python3-tk` on Debian/Ubuntu). There is nothing to `pip install` to run it.

## Tests

```
python3 -m pip install -r requirements-dev.txt
python3 -m pyflakes inetgateway.py tests packaging
python3 -m unittest discover -s tests -v                       # logic tests; GUI tests skip without a display
xvfb-run -a python3 -m unittest discover -s tests -v           # Linux: includes the GUI smoke tests
sudo python3 -m unittest tests.test_inetgateway.LinuxCaptureIntegrationTests -v   # real loopback capture
```
The suite never uses the real network: tests that involve lookups use fake responders and a guard that fails if the real fetch function is called.
Tests that need privileges or a display are skipped (not failed) when those are missing, and say so.

## Rules the code follows (please keep them)

- Standard library only at runtime. Build tools (PyInstaller) and dev tools are pinned in `requirements-*.txt`.
- No network traffic unless the user turns on the optional lookups. The only web address allowed in the source is VirusTotal's (a test enforces it).
- Treat every captured string as untrusted (`safe_text`); decoders must never raise (add fuzz cases for new decoders); bound every queue, table and cache.
- Never claim more than the backend can see. Wording in the UI and docs must match the code.
- No silent system changes: no firewall, routing or process control.
- New behaviour needs tests, and a line in `CHANGELOG.md`.

## Icons

`python3 packaging/make_icons.py` regenerates the PNG/ICO/SVG and the 64-px base64 used for the window icon (paste it into `ICON_PNG_B64`).

## Building packages locally

- Debian/Ubuntu package (needs `dpkg-deb`): `packaging/debian/build_deb.sh` → `dist/inetgateway_<version>-1_all.deb`. Optional: `MAINTAINER="Name <email>" HOMEPAGE=https://github.com/OWNER/REPO`.
- Windows exe (on Windows, Python 3.9+): `packaging\windows\build_exe.bat` → `dist\InetGateway.exe` (unsigned).

Releases are built by GitHub Actions: see [RELEASING.md](RELEASING.md).

# Contributing

Thanks for helping. This project aims to stay small, offline-by-default and honest about what it can see.

## Ground rules

1. **Standard library only at runtime.** No new runtime dependencies.
2. **No network traffic unless the user explicitly turns on the optional VirusTotal feature.** The only web address allowed in the source is VirusTotal's (a test enforces this).
3. **Never claim more than the code does**, in the UI or the docs. If a path is untested on a platform, say so.
4. **Hostile input is the default**: decoders must not raise on any bytes; sanitise captured strings; bound every queue, table and cache.
5. **No silent system changes**: no firewall, routing or process control, no hidden persistence.

## Setup, tests, style

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Before opening a pull request:

```
python -m pip install -r requirements-dev.txt
python -m pyflakes inetgateway.py tests packaging
python -m unittest discover -s tests -v          # use xvfb-run -a on Linux to include the GUI tests
```

Add tests for new behaviour (and truncation/fuzz cases for any new decoder), update `CHANGELOG.md`, and keep pull requests focused.
Tests must never touch the real network or your real settings (they use `INETGATEWAY_CONFIG_DIR` and a guard around the network function).

## Licence

By contributing you agree that your contribution is licensed under GPL-3.0-or-later, like the rest of the project.
Do not submit code you do not have the right to license that way.

## Reporting bugs and security problems

Bugs: open an issue (do not paste API keys or private captures). Security: see [SECURITY.md](SECURITY.md).

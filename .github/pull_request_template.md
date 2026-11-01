## What and why

## Checklist
- [ ] `python -m pyflakes inetgateway.py tests packaging` is clean
- [ ] `python -m unittest discover -s tests` passes (state which tests were skipped and why)
- [ ] New behaviour has tests; decoders have fuzz/truncation cases
- [ ] No new runtime dependencies; no new network traffic (the VirusTotal feature stays opt-in)
- [ ] UI text and docs claim no more than the code can do
- [ ] `CHANGELOG.md` updated

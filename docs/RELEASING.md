# Publishing on GitHub and releasing the `.exe` and `.deb`

Releases are built by GitHub Actions from a tag, so the downloadable files come from the public source, not from a developer's laptop.
(Replace `OWNER/REPO` with your account and repository name everywhere below.)

## One-time setup

1. **Create the repository** on github.com (empty: no README, no licence, no .gitignore; they already exist here). Public if you want others to download the releases.
2. **Fill in the placeholders.** Run `grep -rn "OWNER\|YOUR_" .` and edit what it finds (names, links). The copyright holder is written as "InetGateway contributors"; change it in `LICENSE` headers/`packaging/debian/copyright` if you want your own name.
3. **Push the code**
   ```
   git init -b main
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/OWNER/REPO.git
   git push -u origin main
   ```
4. **Repository settings**
   - *Settings > Actions > General > Workflow permissions*: "Read repository contents" is enough (the release job asks for write on its own).
   - *Settings > Code security*: enable **Private vulnerability reporting** (SECURITY.md points reporters there) and Dependabot alerts.
   - *Optional* *Settings > Variables > Actions*: add a variable `DEB_MAINTAINER` = `Your Name <you@example.com>` for the `.deb` Maintainer field (a clearly fake placeholder is used otherwise). Use an address you are happy to publish.
   - *Optional* branch protection on `main`: require the CI checks to pass.
5. Open the **Actions** tab and confirm CI is green on `main`.

## Making a release

1. Decide the version (SemVer; `0.x` releases are published as GitHub *pre-releases* automatically).
2. Edit `__version__` in `inetgateway.py` and add a matching `## [X.Y.Z] - YYYY-MM-DD` section at the top of `CHANGELOG.md` (it becomes the release notes).
3. Commit and push. Wait for CI to pass.
4. Tag and push the tag:
   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
5. The **Release** workflow then: checks the tag matches the version and CHANGELOG, runs the tests, builds `InetGateway.exe` on a Windows runner (and launches it once in demo mode as a smoke test), builds the `.deb` on Ubuntu (lintian check, installs it, runs it, removes it), writes `SHA256SUMS.txt`, and creates the release with these files:
   - `InetGateway-X.Y.Z-windows-x64.exe`
   - `inetgateway_X.Y.Z-1_all.deb`
   - `SHA256SUMS.txt`
6. Download the files from the release page and test them on a clean Windows machine and a Debian/Ubuntu machine before announcing. The workflow cannot prove the Windows capture path works on real hardware.

**Dry run:** *Actions > Release > Run workflow* builds and tests everything and publishes nothing (the artifacts can be downloaded from the run).

**If a release is wrong:** delete the release and the tag (`git push --delete origin vX.Y.Z`; `git tag -d vX.Y.Z`), fix, and tag again (or bump the patch version).

## Building locally instead

- `.deb` (Debian/Ubuntu with `dpkg-deb`): `MAINTAINER="Name <email>" HOMEPAGE=https://github.com/OWNER/REPO packaging/debian/build_deb.sh`
- `.exe` (Windows, Python 3.9+): `packaging\windows\build_exe.bat`
- Upload by hand: `gh release create vX.Y.Z dist/* --prerelease --notes-file notes.md`

## Honest limits of these packages

- The `.exe` is **not code-signed**: Windows SmartScreen warns on first run, and some antivirus products flag PyInstaller executables. Mitigations you control: publish `SHA256SUMS.txt` (done), build in public CI (done), keep the source runnable (`python inetgateway.py`). Code signing needs a certificate or a signing programme for open-source projects; check current offers and eligibility before relying on one.
- The `.deb` is architecture-independent (`all`), depends on `python3 (>= 3.9)` and `python3-tk`, and is **not** signed or in an apt repository: users install it with `sudo apt install ./file.deb`. Hosting an apt repository, an installer (MSI/Inno Setup), winget or Flatpak packaging are not covered here.
- GitHub Actions in the workflows are referenced by major version tags. For stricter supply-chain hygiene, pin them to full commit SHAs (Dependabot, configured here, will propose updates).
- GPL-3.0-or-later: when you distribute the binaries you must make the corresponding source available. Linking the GitHub repository at the release tag from the release notes satisfies that for most uses; keep the tags.

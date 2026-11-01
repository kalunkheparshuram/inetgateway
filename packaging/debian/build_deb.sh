#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build dist/inetgateway_<version>-1_all.deb from the repository (pure Python, architecture-independent).
# Environment (all optional):
#   MAINTAINER  "Name <email>" for the Maintainer field (a clearly fake placeholder is used if unset)
#   HOMEPAGE    project URL for the Homepage field
set -eu
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
VERSION="$(python3 - <<'PY'
import re
print(re.search(r'^__version__ = "([^"]+)"', open("inetgateway.py", encoding="utf-8").read(), re.M).group(1))
PY
)"
DEBVER="${VERSION}-1"
PKG="inetgateway"
MAINTAINER="${MAINTAINER:-InetGateway contributors <noreply@example.invalid>}"
HOMEPAGE="${HOMEPAGE:-}"
STAGE="$ROOT/dist/deb-stage"
OUT="$ROOT/dist/${PKG}_${DEBVER}_all.deb"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/lib/$PKG" "$STAGE/usr/bin" \
         "$STAGE/usr/share/applications" "$STAGE/usr/share/man/man1" \
         "$STAGE/usr/share/icons/hicolor/256x256/apps" "$STAGE/usr/share/icons/hicolor/scalable/apps" \
         "$STAGE/usr/share/doc/$PKG"

install -m 0644 inetgateway.py "$STAGE/usr/lib/$PKG/inetgateway.py"
cat > "$STAGE/usr/bin/$PKG" <<'WRAP'
#!/bin/sh
exec /usr/bin/python3 /usr/lib/inetgateway/inetgateway.py "$@"
WRAP
chmod 0755 "$STAGE/usr/bin/$PKG"
install -m 0644 packaging/debian/inetgateway.desktop "$STAGE/usr/share/applications/inetgateway.desktop"
install -m 0644 packaging/icons/inetgateway.png "$STAGE/usr/share/icons/hicolor/256x256/apps/inetgateway.png"
install -m 0644 packaging/icons/inetgateway.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/inetgateway.svg"
gzip -9nc packaging/debian/inetgateway.1 > "$STAGE/usr/share/man/man1/inetgateway.1.gz"
chmod 0644 "$STAGE/usr/share/man/man1/inetgateway.1.gz"
install -m 0644 README.md "$STAGE/usr/share/doc/$PKG/README.md"
for f in docs/USER_GUIDE.md docs/PRIVACY.md docs/THREAT_INTEL.md docs/NETWORK_MONITORING.md docs/TROUBLESHOOTING.md; do
  [ -f "$f" ] && install -m 0644 "$f" "$STAGE/usr/share/doc/$PKG/$(basename "$f")"
done
sed "s/@VERSION@/${DEBVER}/g; s/@MAINTAINER@/$(printf '%s' "$MAINTAINER" | sed 's/[&/\]/\\&/g')/g" \
    packaging/debian/changelog.in | gzip -9nc > "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"
install -m 0644 packaging/debian/copyright "$STAGE/usr/share/doc/$PKG/copyright"
gzip -9nf "$STAGE/usr/share/doc/$PKG/README.md"
for f in "$STAGE"/usr/share/doc/$PKG/*.md; do [ -f "$f" ] && gzip -9nf "$f"; done

SIZE_KB="$(du -sk "$STAGE/usr" | cut -f1)"
{
  echo "Package: $PKG"
  echo "Version: $DEBVER"
  echo "Architecture: all"
  echo "Maintainer: $MAINTAINER"
  echo "Installed-Size: $SIZE_KB"
  echo "Depends: python3 (>= 3.9), python3-tk"
  echo "Section: net"
  echo "Priority: optional"
  [ -n "$HOMEPAGE" ] && echo "Homepage: $HOMEPAGE"
  cat <<'DESC'
Description: offline packet viewer with a per-application dashboard
 InetGateway is a small Wireshark-style viewer: live capture on this machine,
 decoded packet details, a dashboard that groups traffic by program and
 service, DNS names learned from DNS answers, and optional VirusTotal
 lookups using your own API key (off by default).
 .
 It only observes traffic that reaches this computer, never decrypts
 anything, makes no network connections unless you enable the optional
 lookups, and never blocks or changes anything.
 .
 Live capture needs root or the CAP_NET_RAW capability.
DESC
} > "$STAGE/DEBIAN/control"

find "$STAGE" -type d -exec chmod 0755 {} +
(cd "$STAGE" && find usr -type f -exec md5sum {} + | sed 's#  #  #') > "$STAGE/DEBIAN/md5sums"
chmod 0644 "$STAGE/DEBIAN/md5sums"
mkdir -p "$ROOT/dist"
rm -f "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo "Built $OUT"

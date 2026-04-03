#!/usr/bin/env bash
set -euo pipefail

APP_ID="io.srmkv.tlsclientnative"
APP_NAME="tlsclientnative"
VERSION="${1:-1.0.0}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/dist/deb-build"
PKG_DIR="${BUILD_DIR}/${APP_NAME}_${VERSION}_${ARCH}"
BIN_OUT="${ROOT_DIR}/dist/${APP_NAME}"

mkdir -p "${ROOT_DIR}/dist"
rm -rf "${BUILD_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"          "${PKG_DIR}/opt/${APP_NAME}"          "${PKG_DIR}/usr/bin"          "${PKG_DIR}/usr/share/applications"          "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps"          "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps"          "${PKG_DIR}/usr/share/metainfo"          "${PKG_DIR}/usr/share/doc/${APP_NAME}"

echo "[1/3] Сборка бинарника"
cd "${ROOT_DIR}"
go mod tidy
go build -o "${BIN_OUT}" ./cmd/tlsclient

echo "[2/3] Подготовка пакета"
install -Dm755 "${BIN_OUT}" "${PKG_DIR}/opt/${APP_NAME}/${APP_NAME}"
ln -s "/opt/${APP_NAME}/${APP_NAME}" "${PKG_DIR}/usr/bin/${APP_NAME}"
install -Dm644 "${ROOT_DIR}/packaging/linux/${APP_ID}.desktop" "${PKG_DIR}/usr/share/applications/${APP_ID}.desktop"
install -Dm644 "${ROOT_DIR}/packaging/linux/${APP_ID}.metainfo.xml" "${PKG_DIR}/usr/share/metainfo/${APP_ID}.metainfo.xml"
install -Dm644 "${ROOT_DIR}/packaging/linux/assets/${APP_ID}.svg" "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
install -Dm644 "${ROOT_DIR}/packaging/linux/assets/${APP_ID}.png" "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps/${APP_ID}.png"
install -Dm644 "${ROOT_DIR}/LICENSE" "${PKG_DIR}/usr/share/doc/${APP_NAME}/copyright"
install -Dm644 "${ROOT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/${APP_NAME}/README.md"

cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${APP_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Local Builder <local@example.invalid>
Depends: libc6
Description: TLS Client Native
 Нативный Linux-клиент для mTLS-подключения с GUI.
EOF

cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/usr/bin/env bash
set -e
update-desktop-database >/dev/null 2>&1 || true
gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat > "${PKG_DIR}/DEBIAN/postrm" <<'EOF'
#!/usr/bin/env bash
set -e
update-desktop-database >/dev/null 2>&1 || true
gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

echo "[3/3] Сборка .deb"
dpkg-deb --build "${PKG_DIR}" "${ROOT_DIR}/dist/${APP_NAME}_${VERSION}_${ARCH}.deb"
echo "Готово: ${ROOT_DIR}/dist/${APP_NAME}_${VERSION}_${ARCH}.deb"

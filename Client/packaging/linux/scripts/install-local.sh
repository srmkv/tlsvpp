#!/usr/bin/env bash
set -euo pipefail

APP_ID="io.srmkv.tlsclientnative"
APP_NAME="tlsclientnative"
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
PREFIX="${HOME}/.local"
APP_DIR="${PREFIX}/opt/${APP_NAME}"
BIN="${APP_DIR}/${APP_NAME}"

mkdir -p "${APP_DIR}"          "${PREFIX}/bin"          "${PREFIX}/share/applications"          "${PREFIX}/share/icons/hicolor/scalable/apps"          "${PREFIX}/share/icons/hicolor/256x256/apps"          "${PREFIX}/share/metainfo"

echo "[1/3] Сборка"
cd "${ROOT_DIR}"
go mod tidy
go build -o "${BIN}" ./cmd/tlsclient

echo "[2/3] Установка файлов"
ln -sf "${BIN}" "${PREFIX}/bin/${APP_NAME}"
install -Dm644 "${ROOT_DIR}/packaging/linux/${APP_ID}.desktop" "${PREFIX}/share/applications/${APP_ID}.desktop"
install -Dm644 "${ROOT_DIR}/packaging/linux/${APP_ID}.metainfo.xml" "${PREFIX}/share/metainfo/${APP_ID}.metainfo.xml"
install -Dm644 "${ROOT_DIR}/packaging/linux/assets/${APP_ID}.svg" "${PREFIX}/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
install -Dm644 "${ROOT_DIR}/packaging/linux/assets/${APP_ID}.png" "${PREFIX}/share/icons/hicolor/256x256/apps/${APP_ID}.png"

echo "[3/3] Готово"
echo "Запуск: ${PREFIX}/bin/${APP_NAME}"
echo "При необходимости перелогиньтесь, чтобы пункт меню появился в системе."

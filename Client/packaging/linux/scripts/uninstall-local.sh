#!/usr/bin/env bash
set -euo pipefail

APP_ID="io.srmkv.tlsclientnative"
APP_NAME="tlsclientnative"
PREFIX="${HOME}/.local"

rm -f "${PREFIX}/bin/${APP_NAME}"
rm -rf "${PREFIX}/opt/${APP_NAME}"
rm -f "${PREFIX}/share/applications/${APP_ID}.desktop"
rm -f "${PREFIX}/share/metainfo/${APP_ID}.metainfo.xml"
rm -f "${PREFIX}/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
rm -f "${PREFIX}/share/icons/hicolor/256x256/apps/${APP_ID}.png"

echo "Удалено."
